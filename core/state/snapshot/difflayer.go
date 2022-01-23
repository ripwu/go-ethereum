// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package snapshot

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	bloomfilter "github.com/holiman/bloomfilter/v2"
)

var (
	// TODO 参考 Dynamic state snapshots #20152 中 holiman 的估算

	// aggregatorMemoryLimit is the maximum size of the bottom-most diff layer
	// that aggregates the writes from above until it's flushed into the disk
	// layer.
	//
	// Note, bumping this up might drastically increase the size of the bloom
	// filters that's stored in every diff layer. Don't do that without fully
	// understanding all the implications.
	aggregatorMemoryLimit = uint64(4 * 1024 * 1024)

	// aggregatorItemLimit is an approximate number of items that will end up
	// in the aggregator layer before it's flushed out to disk. A plain account
	// weighs around 14B (+hash), a storage slot 32B (+hash), a deleted slot
	// 0B (+hash). Slots are mostly set/unset in lockstep, so that average at
	// 16B (+hash). All in all, the average entry seems to be 15+32=47B. Use a
	// smaller number to be on the safe side.
	aggregatorItemLimit = aggregatorMemoryLimit / 42

	// bloomTargetError is the target false positive rate when the aggregator
	// layer is at its fullest. The actual value will probably move around up
	// and down from this number, it's mostly a ballpark figure.
	//
	// Note, dropping this down might drastically increase the size of the bloom
	// filters that's stored in every diff layer. Don't do that without fully
	// understanding all the implications.
	bloomTargetError = 0.02

	// bloomSize is the ideal bloom filter size given the maximum number of items
	// it's expected to hold and the target false positive error rate.
	bloomSize = math.Ceil(float64(aggregatorItemLimit) * math.Log(bloomTargetError) / math.Log(1/math.Pow(2, math.Log(2))))

	// bloomFuncs is the ideal number of bits a single entry should set in the
	// bloom filter to keep its size to a minimum (given it's size and maximum
	// entry count).
	bloomFuncs = math.Round((bloomSize / float64(aggregatorItemLimit)) * math.Log(2))

	// the bloom offsets are runtime constants which determines which part of the
	// the account/storage hash the hasher functions looks at, to determine the
	// bloom key for an account/slot. This is randomized at init(), so that the
	// global population of nodes do not all display the exact same behaviour with
	// regards to bloom content
	bloomDestructHasherOffset = 0
	bloomAccountHasherOffset  = 0
	bloomStorageHasherOffset  = 0
)

func init() {
	// Init the bloom offsets in the range [0:24] (requires 8 bytes)
	bloomDestructHasherOffset = rand.Intn(25)
	bloomAccountHasherOffset = rand.Intn(25)
	bloomStorageHasherOffset = rand.Intn(25)

	// The destruct and account blooms must be different, as the storage slots
	// will check for destruction too for every bloom miss. It should not collide
	// with modified accounts.
	for bloomAccountHasherOffset == bloomDestructHasherOffset {
		bloomAccountHasherOffset = rand.Intn(25)
	}
}

// diffLayer represents a collection of modifications made to a state snapshot
// after running a block on top. It contains one sorted list for the account trie
// and one-one list for each storage tries.
//
// The goal of a diff layer is to act as a journal, tracking recent modifications
// made to the state, that have not yet graduated into a semi-immutable state.
// diffLayer 记录对应 block 执行时产生的修改
type diffLayer struct {
	// 指向底层 diskLayer
	origin *diskLayer // Base disk layer to directly use on bloom misses

	// 指向父层，可能是 diskLayer 或 diffLayer
	parent snapshot   // Parent snapshot modified by this one, never nil

	memory uint64     // Approximate guess as to how much memory we use

	root  common.Hash // Root hash to which this snapshot diff belongs to

	// 正常来说，在 diffToDisk() 中被设置为 true，表示 diffLayer 数据已经写入 diskLayer
	stale uint32      // Signals that the layer became stale (state progressed)

	// destructSet is a very special helper marker. If an account is marked as
	// deleted, then it's recorded in this set. However it's allowed that an account
	// is included here but still available in other sets(e.g. storageData). The
	// reason is the diff layer includes all the changes in a *block*. It can
	// happen that in the tx_1, account A is self-destructed while in the tx_2
	// it's recreated. But we still need this marker to indicate the "old" A is
	// deleted, all data in other set belongs to the "new" A.
	destructSet map[common.Hash]struct{}               // Keyed markers for deleted (and potentially) recreated accounts
	accountList []common.Hash                          // List of account for iteration. If it exists, it's sorted, otherwise it's nil
	accountData map[common.Hash][]byte                 // Keyed accounts for direct retrieval (nil means deleted)
	storageList map[common.Hash][]common.Hash          // List of storage slots for iterated retrievals, one per account. Any existing lists are sorted if non-nil
	storageData map[common.Hash]map[common.Hash][]byte // Keyed storage slots for direct retrieval. one per account (nil means deleted)

	// 理解：维护从 diskLayer 经过中间的 diffLayer 到当前 diffLayer，累计的 bloom filter
	// 用于快速过滤 account 是否出现在中间层 diffLayer 中，加快查询请求 (参考 diffLayer.AccountRLP(hash common.Hash))
	// 如果存在，查询时递归不过向上层 diffLayer 查询 账户 (参考 diffLayer.accountRLP(hash common.Hash, depth int))
	// 如果不存在，直接请求底层 diskLayer，从 db 中查询
	diffed *bloomfilter.Filter // Bloom filter tracking all the diffed items up to the disk layer

	// 粒度：看起来是为了控制整个结构体的并发访问，不限定某些成员
	lock sync.RWMutex
}

// destructBloomHasher is a wrapper around a common.Hash to satisfy the interface
// API requirements of the bloom library used. It's used to convert a destruct
// event into a 64 bit mini hash.
type destructBloomHasher common.Hash

func (h destructBloomHasher) Write(p []byte) (n int, err error) { panic("not implemented") }
func (h destructBloomHasher) Sum(b []byte) []byte               { panic("not implemented") }
func (h destructBloomHasher) Reset()                            { panic("not implemented") }
func (h destructBloomHasher) BlockSize() int                    { panic("not implemented") }
func (h destructBloomHasher) Size() int                         { return 8 }
func (h destructBloomHasher) Sum64() uint64 {
	return binary.BigEndian.Uint64(h[bloomDestructHasherOffset : bloomDestructHasherOffset+8])
}

// accountBloomHasher is a wrapper around a common.Hash to satisfy the interface
// API requirements of the bloom library used. It's used to convert an account
// hash into a 64 bit mini hash.
type accountBloomHasher common.Hash

func (h accountBloomHasher) Write(p []byte) (n int, err error) { panic("not implemented") }
func (h accountBloomHasher) Sum(b []byte) []byte               { panic("not implemented") }
func (h accountBloomHasher) Reset()                            { panic("not implemented") }
func (h accountBloomHasher) BlockSize() int                    { panic("not implemented") }
func (h accountBloomHasher) Size() int                         { return 8 }
func (h accountBloomHasher) Sum64() uint64 {
	return binary.BigEndian.Uint64(h[bloomAccountHasherOffset : bloomAccountHasherOffset+8])
}

// storageBloomHasher is a wrapper around a [2]common.Hash to satisfy the interface
// API requirements of the bloom library used. It's used to convert an account
// hash into a 64 bit mini hash.
type storageBloomHasher [2]common.Hash

func (h storageBloomHasher) Write(p []byte) (n int, err error) { panic("not implemented") }
func (h storageBloomHasher) Sum(b []byte) []byte               { panic("not implemented") }
func (h storageBloomHasher) Reset()                            { panic("not implemented") }
func (h storageBloomHasher) BlockSize() int                    { panic("not implemented") }
func (h storageBloomHasher) Size() int                         { return 8 }
func (h storageBloomHasher) Sum64() uint64 {
	return binary.BigEndian.Uint64(h[0][bloomStorageHasherOffset:bloomStorageHasherOffset+8]) ^
		binary.BigEndian.Uint64(h[1][bloomStorageHasherOffset:bloomStorageHasherOffset+8])
}

// newDiffLayer creates a new diff on top of an existing snapshot, whether that's a low
// level persistent database or a hierarchical diff already.
// parent 可能是 diskLayer 也可能是 diffLayer
func newDiffLayer(parent snapshot, root common.Hash, destructs map[common.Hash]struct{}, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) *diffLayer {
	// Create the new layer with some pre-allocated data segments
	dl := &diffLayer{
		parent:      parent,
		root:        root,
		destructSet: destructs,
		accountData: accounts,
		storageData: storage,
		storageList: make(map[common.Hash][]common.Hash),
	}

	switch parent := parent.(type) {
	case *diskLayer:
		dl.rebloom(parent)
	case *diffLayer:
		dl.rebloom(parent.origin)
	default:
		panic("unknown parent type")
	}

	// 对传入参数的完整性检查
	// Sanity check that accounts or storage slots are never nil
	for accountHash, blob := range accounts {
		if blob == nil {
			panic(fmt.Sprintf("account %#x nil", accountHash))
		}
		// Determine memory size and track the dirty writes
		dl.memory += uint64(common.HashLength + len(blob))
		snapshotDirtyAccountWriteMeter.Mark(int64(len(blob)))
	}

	for accountHash, slots := range storage {
		if slots == nil {
			panic(fmt.Sprintf("storage %#x nil", accountHash))
		}
		// Determine memory size and track the dirty writes
		for _, data := range slots {
			dl.memory += uint64(common.HashLength + len(data))
			snapshotDirtyStorageWriteMeter.Mark(int64(len(data)))
		}
	}

	dl.memory += uint64(len(destructs) * common.HashLength)
	return dl
}

// rebloom discards the layer's current bloom and rebuilds it from scratch based
// on the parent's and the local diffs.
// 重新构建本层的 diffed 累计过滤器：将 父层过滤器 与 本层修改内容，合并写到 本层过滤器
func (dl *diffLayer) rebloom(origin *diskLayer) {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	defer func(start time.Time) {
		snapshotBloomIndexTimer.Update(time.Since(start))
	}(time.Now())

	// Inject the new origin that triggered the rebloom
	dl.origin = origin

	// Retrieve the parent bloom or create a fresh empty one
	// 重新初始化本层 diffed 或拷贝上层 diffed
	if parent, ok := dl.parent.(*diffLayer); ok {
		parent.lock.RLock()

		// 1.尝试拷贝父层的 diffed
		dl.diffed, _ = parent.diffed.Copy()

		parent.lock.RUnlock()
	} else {
		dl.diffed, _ = bloomfilter.New(uint64(bloomSize), uint64(bloomFuncs))
	}

	// 2.然后向本层 diffed 写入本层的数据

	// Iterate over all the accounts and storage slots and index them
	for hash := range dl.destructSet {
		dl.diffed.Add(destructBloomHasher(hash))
	}

	for hash := range dl.accountData {
		dl.diffed.Add(accountBloomHasher(hash))
	}

	for accountHash, slots := range dl.storageData {
		for storageHash := range slots {
			dl.diffed.Add(storageBloomHasher{accountHash, storageHash})
		}
	}

	// Calculate the current false positive rate and update the error rate meter.
	// This is a bit cheating because subsequent layers will overwrite it, but it
	// should be fine, we're only interested in ballpark figures.
	k := float64(dl.diffed.K())
	n := float64(dl.diffed.N())
	m := float64(dl.diffed.M())
	snapshotBloomErrorGauge.Update(math.Pow(1.0-math.Exp((-k)*(n+0.5)/(m-1)), k))
}

// Root returns the root hash for which this snapshot was made.
func (dl *diffLayer) Root() common.Hash {
	return dl.root
}

// Parent returns the subsequent layer of a diff layer.
func (dl *diffLayer) Parent() snapshot {
	return dl.parent
}

// Stale return whether this layer has become stale (was flattened across) or if
// it's still live.
func (dl *diffLayer) Stale() bool {
	return atomic.LoadUint32(&dl.stale) != 0
}

// Account directly retrieves the account associated with a particular hash in
// the snapshot slim data format.
func (dl *diffLayer) Account(hash common.Hash) (*Account, error) {
	data, err := dl.AccountRLP(hash)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 { // can be both nil and []byte{}
		return nil, nil
	}

	account := new(Account)
	if err := rlp.DecodeBytes(data, account); err != nil {
		panic(err)
	}
	return account, nil
}

// AccountRLP directly retrieves the account RLP associated with a particular
// hash in the snapshot slim data format.
//
// Note the returned account is not a copy, please don't modify it.
func (dl *diffLayer) AccountRLP(hash common.Hash) ([]byte, error) {
	// Check the bloom filter first whether there's even a point in reaching into
	// all the maps in all the layers below
	dl.lock.RLock()

	hit := dl.diffed.Contains(accountBloomHasher(hash))
	if !hit {
		hit = dl.diffed.Contains(destructBloomHasher(hash))
	}

	var origin *diskLayer
	if !hit {
		origin = dl.origin // extract origin while holding the lock
	}

	dl.lock.RUnlock()

	// If the bloom filter misses, don't even bother with traversing the memory
	// diff layers, reach straight into the bottom persistent disk layer
	if origin != nil {
		snapshotBloomAccountMissMeter.Mark(1)
		return origin.AccountRLP(hash)
	}

	// The bloom filter hit, start poking in the internal maps
	return dl.accountRLP(hash, 0)
}

// accountRLP is an internal version of AccountRLP that skips the bloom filter
// checks and uses the internal maps to try and retrieve the data. It's meant
// to be used if a higher layer's bloom filter hit already.
func (dl *diffLayer) accountRLP(hash common.Hash, depth int) ([]byte, error) {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	// If the layer was flattened into, consider it invalid (any live reference to
	// the original should be marked as unusable).
	if dl.Stale() {
		return nil, ErrSnapshotStale
	}

	// If the account is known locally, return it
	if data, ok := dl.accountData[hash]; ok {
		snapshotDirtyAccountHitMeter.Mark(1)
		snapshotDirtyAccountHitDepthHist.Update(int64(depth))
		snapshotDirtyAccountReadMeter.Mark(int64(len(data)))
		snapshotBloomAccountTrueHitMeter.Mark(1)
		return data, nil
	}

	// If the account is known locally, but deleted, return it
	if _, ok := dl.destructSet[hash]; ok {
		snapshotDirtyAccountHitMeter.Mark(1)
		snapshotDirtyAccountHitDepthHist.Update(int64(depth))
		snapshotDirtyAccountInexMeter.Mark(1)
		snapshotBloomAccountTrueHitMeter.Mark(1)
		return nil, nil
	}

	// Account unknown to this diff, resolve from parent
	if diff, ok := dl.parent.(*diffLayer); ok {
		return diff.accountRLP(hash, depth+1)
	}

	// Failed to resolve through diff layers, mark a bloom error and use the disk
	snapshotBloomAccountFalseHitMeter.Mark(1)
	return dl.parent.AccountRLP(hash)
}

// Storage directly retrieves the storage data associated with a particular hash,
// within a particular account. If the slot is unknown to this diff, it's parent
// is consulted.
//
// Note the returned slot is not a copy, please don't modify it.
func (dl *diffLayer) Storage(accountHash, storageHash common.Hash) ([]byte, error) {
	// Check the bloom filter first whether there's even a point in reaching into
	// all the maps in all the layers below
	dl.lock.RLock()
	hit := dl.diffed.Contains(storageBloomHasher{accountHash, storageHash})
	if !hit {
		hit = dl.diffed.Contains(destructBloomHasher(accountHash))
	}
	var origin *diskLayer
	if !hit {
		origin = dl.origin // extract origin while holding the lock
	}
	dl.lock.RUnlock()

	// If the bloom filter misses, don't even bother with traversing the memory
	// diff layers, reach straight into the bottom persistent disk layer
	if origin != nil {
		snapshotBloomStorageMissMeter.Mark(1)
		return origin.Storage(accountHash, storageHash)
	}
	// The bloom filter hit, start poking in the internal maps
	return dl.storage(accountHash, storageHash, 0)
}

// storage is an internal version of Storage that skips the bloom filter checks
// and uses the internal maps to try and retrieve the data. It's meant  to be
// used if a higher layer's bloom filter hit already.
// 注释中的 higher layer，是更高的 block Number 的意思，即当前 diffLayer 的子层
func (dl *diffLayer) storage(accountHash, storageHash common.Hash, depth int) ([]byte, error) {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	// If the layer was flattened into, consider it invalid (any live reference to
	// the original should be marked as unusable).
	if dl.Stale() {
		return nil, ErrSnapshotStale
	}

	// If the account is known locally, try to resolve the slot locally
	if storage, ok := dl.storageData[accountHash]; ok {
		if data, ok := storage[storageHash]; ok {
			snapshotDirtyStorageHitMeter.Mark(1)
			snapshotDirtyStorageHitDepthHist.Update(int64(depth))
			if n := len(data); n > 0 {
				snapshotDirtyStorageReadMeter.Mark(int64(n))
			} else {
				snapshotDirtyStorageInexMeter.Mark(1)
			}
			snapshotBloomStorageTrueHitMeter.Mark(1)
			return data, nil
		}
	}

	// If the account is known locally, but deleted, return an empty slot
	if _, ok := dl.destructSet[accountHash]; ok {
		snapshotDirtyStorageHitMeter.Mark(1)
		snapshotDirtyStorageHitDepthHist.Update(int64(depth))
		snapshotDirtyStorageInexMeter.Mark(1)
		snapshotBloomStorageTrueHitMeter.Mark(1)
		return nil, nil
	}

	// Storage slot unknown to this diff, resolve from parent
	if diff, ok := dl.parent.(*diffLayer); ok {
		return diff.storage(accountHash, storageHash, depth+1)
	}

	// Failed to resolve through diff layers, mark a bloom error and use the disk
	snapshotBloomStorageFalseHitMeter.Mark(1)
	return dl.parent.Storage(accountHash, storageHash)
}

// Update creates a new layer on top of the existing snapshot diff tree with
// the specified data items.
func (dl *diffLayer) Update(blockRoot common.Hash, destructs map[common.Hash]struct{}, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) *diffLayer {
	return newDiffLayer(dl, blockRoot, destructs, accounts, storage)
}

// flatten pushes all data from this point downwards, flattening everything into
// a single diff at the bottom. Since usually the lowermost diff is the largest,
// the flattening builds up from there in reverse.
// 调用来源：Tree.Cap() / Tree.cap()
//
// 递归合并多层 diffLayer，最终得到一层 diffLayer
// 1.将 diffLayer1 合并到 diffLayer0，得到 diffLayerNew0
// 2.将 diffLayer2 合并到 diffLayerNew0，得到 diffLayerNew1
// 3.将 diffLayer3 合并到 diffLayerNew1，得到 diffLayerNew2
// ...
// 最后，返回 将 dl 表示的 diffLayer 合并到 diffLayerNewX，得到 diffLayerNewY 并返回
//
// 可以有两种合并顺序：
// (((dl0 <- dl1) <- dl2) <- ... <-dlN)
// (dl0 <- (dl1 <- (dl2 <- ... (dlN-2 <- (dlN-1 <- dlN)))))
// TODO 理解：代码采用的是第一种顺序。按照注释，是为了减少合并的数据量
func (dl *diffLayer) flatten() snapshot {
	// If the parent is not diff, we're the first in line, return unmodified
	// 如果 parent 不是 diffLayer，直接返回当前层
	// (说明：parent 是 diskLayer，即当前层已经是最早的 diffLayer)
	parent, ok := dl.parent.(*diffLayer)
	if !ok {
		return dl
	}

	// Parent is a diff, flatten it first (note, apart from weird corned cases,
	// flatten will realistically only ever merge 1 layer, so there's no need to
	// be smarter about grouping flattens together).

	// flatten() 返回的是新构造的 diffLayer，这里将其转为 parent，再将当前节点合并，递归调用
	parent = parent.flatten().(*diffLayer)

	parent.lock.Lock()
	defer parent.lock.Unlock()

	// Before actually writing all our data to the parent, first ensure that the
	// parent hasn't been 'corrupted' by someone else already flattening into it
	if atomic.SwapUint32(&parent.stale, 1) != 0 {
		panic("parent diff layer is stale") // we've flattened into the same parent from two children, boo
	}

	// Overwrite all the updated accounts blindly, merge the sorted list
	for hash := range dl.destructSet {
		parent.destructSet[hash] = struct{}{}
		delete(parent.accountData, hash)
		delete(parent.storageData, hash)
	}

	for hash, data := range dl.accountData {
		parent.accountData[hash] = data
	}

	// Overwrite all the updated storage slots (individually)
	for accountHash, storage := range dl.storageData {
		// 父层不存在则直接引用
		// If storage didn't exist (or was deleted) in the parent, overwrite blindly
		if _, ok := parent.storageData[accountHash]; !ok {
			parent.storageData[accountHash] = storage
			continue
		}

		// 两层都存在，则合并到父层
		// Storage exists in both parent and child, merge the slots
		comboData := parent.storageData[accountHash]
		for storageHash, data := range storage {
			comboData[storageHash] = data
		}

		parent.storageData[accountHash] = comboData
	}

	// Return the combo parent
	// 通过上面的操作，dl 数据已被合并到 parent，即两层合一
	// 这里返回合并后，形成的新的 diffLayer，作为被递归调用的父节点..
	return &diffLayer{
		parent:      parent.parent, // 指向 祖父节点
		origin:      parent.origin,
		root:        dl.root,
		destructSet: parent.destructSet, // 当前层的数据已写入 parent
		accountData: parent.accountData, // 当前层的数据已写入 parent
		storageData: parent.storageData, // 当前层的数据已写入 parent
		storageList: make(map[common.Hash][]common.Hash),
		diffed:      dl.diffed,
		memory:      parent.memory + dl.memory,
	}
}

// AccountList returns a sorted list of all accounts in this diffLayer, including
// the deleted ones.
//
// Note, the returned slice is not a copy, so do not modify it.
func (dl *diffLayer) AccountList() []common.Hash {
	// If an old list already exists, return it
	dl.lock.RLock()
	list := dl.accountList
	dl.lock.RUnlock()

	if list != nil {
		return list
	}

	// No old sorted account list exists, generate a new one
	dl.lock.Lock()
	defer dl.lock.Unlock()

	// 重新构造 dl.accountList
	dl.accountList = make([]common.Hash, 0, len(dl.destructSet)+len(dl.accountData))
	for hash := range dl.accountData {
		dl.accountList = append(dl.accountList, hash)
	}

	for hash := range dl.destructSet {
		if _, ok := dl.accountData[hash]; !ok {
			dl.accountList = append(dl.accountList, hash)
		}
	}

	sort.Sort(hashes(dl.accountList))
	dl.memory += uint64(len(dl.accountList) * common.HashLength)
	return dl.accountList
}

// StorageList returns a sorted list of all storage slot hashes in this diffLayer
// for the given account. If the whole storage is destructed in this layer, then
// an additional flag *destructed = true* will be returned, otherwise the flag is
// false. Besides, the returned list will include the hash of deleted storage slot.
// Note a special case is an account is deleted in a prior tx but is recreated in
// the following tx with some storage slots set. In this case the returned list is
// not empty but the flag is true.
//
// Note, the returned slice is not a copy, so do not modify it.
// @return bool Storage Trie 整颗树是否 *曾经* 被删除 (删除后重建将返回 true)
func (dl *diffLayer) StorageList(accountHash common.Hash) ([]common.Hash, bool) {
	dl.lock.RLock()
	_, destructed := dl.destructSet[accountHash]
	if _, ok := dl.storageData[accountHash]; !ok {
		// Account not tracked by this layer
		dl.lock.RUnlock()
		return nil, destructed
	}

	// If an old list already exists, return it
	if list, exist := dl.storageList[accountHash]; exist {
		dl.lock.RUnlock()
		return list, destructed // the cached list can't be nil
	}

	dl.lock.RUnlock()

	// No old sorted account list exists, generate a new one
	dl.lock.Lock()
	defer dl.lock.Unlock()

	// 重新构造 dl.storageList[accountHash]
	storageMap := dl.storageData[accountHash]
	storageList := make([]common.Hash, 0, len(storageMap))
	for k := range storageMap {
		storageList = append(storageList, k)
	}

	sort.Sort(hashes(storageList))
	dl.storageList[accountHash] = storageList

	dl.memory += uint64(len(dl.storageList)*common.HashLength + common.HashLength)
	return storageList, destructed
}
