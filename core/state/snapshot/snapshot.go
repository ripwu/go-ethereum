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

// Package snapshot implements a journalled, dynamic state dump.
package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

var (
	snapshotCleanAccountHitMeter   = metrics.NewRegisteredMeter("state/snapshot/clean/account/hit", nil)
	snapshotCleanAccountMissMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/account/miss", nil)
	snapshotCleanAccountInexMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/account/inex", nil)
	snapshotCleanAccountReadMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/account/read", nil)
	snapshotCleanAccountWriteMeter = metrics.NewRegisteredMeter("state/snapshot/clean/account/write", nil)

	snapshotCleanStorageHitMeter   = metrics.NewRegisteredMeter("state/snapshot/clean/storage/hit", nil)
	snapshotCleanStorageMissMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/storage/miss", nil)
	snapshotCleanStorageInexMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/storage/inex", nil)
	snapshotCleanStorageReadMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/storage/read", nil)
	snapshotCleanStorageWriteMeter = metrics.NewRegisteredMeter("state/snapshot/clean/storage/write", nil)

	snapshotDirtyAccountHitMeter   = metrics.NewRegisteredMeter("state/snapshot/dirty/account/hit", nil)
	snapshotDirtyAccountMissMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/account/miss", nil)
	snapshotDirtyAccountInexMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/account/inex", nil)
	snapshotDirtyAccountReadMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/account/read", nil)
	snapshotDirtyAccountWriteMeter = metrics.NewRegisteredMeter("state/snapshot/dirty/account/write", nil)

	snapshotDirtyStorageHitMeter   = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/hit", nil)
	snapshotDirtyStorageMissMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/miss", nil)
	snapshotDirtyStorageInexMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/inex", nil)
	snapshotDirtyStorageReadMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/read", nil)
	snapshotDirtyStorageWriteMeter = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/write", nil)

	snapshotDirtyAccountHitDepthHist = metrics.NewRegisteredHistogram("state/snapshot/dirty/account/hit/depth", nil, metrics.NewExpDecaySample(1028, 0.015))
	snapshotDirtyStorageHitDepthHist = metrics.NewRegisteredHistogram("state/snapshot/dirty/storage/hit/depth", nil, metrics.NewExpDecaySample(1028, 0.015))

	snapshotFlushAccountItemMeter = metrics.NewRegisteredMeter("state/snapshot/flush/account/item", nil)
	snapshotFlushAccountSizeMeter = metrics.NewRegisteredMeter("state/snapshot/flush/account/size", nil)
	snapshotFlushStorageItemMeter = metrics.NewRegisteredMeter("state/snapshot/flush/storage/item", nil)
	snapshotFlushStorageSizeMeter = metrics.NewRegisteredMeter("state/snapshot/flush/storage/size", nil)

	snapshotBloomIndexTimer = metrics.NewRegisteredResettingTimer("state/snapshot/bloom/index", nil)
	snapshotBloomErrorGauge = metrics.NewRegisteredGaugeFloat64("state/snapshot/bloom/error", nil)

	snapshotBloomAccountTrueHitMeter  = metrics.NewRegisteredMeter("state/snapshot/bloom/account/truehit", nil)
	snapshotBloomAccountFalseHitMeter = metrics.NewRegisteredMeter("state/snapshot/bloom/account/falsehit", nil)
	snapshotBloomAccountMissMeter     = metrics.NewRegisteredMeter("state/snapshot/bloom/account/miss", nil)

	snapshotBloomStorageTrueHitMeter  = metrics.NewRegisteredMeter("state/snapshot/bloom/storage/truehit", nil)
	snapshotBloomStorageFalseHitMeter = metrics.NewRegisteredMeter("state/snapshot/bloom/storage/falsehit", nil)
	snapshotBloomStorageMissMeter     = metrics.NewRegisteredMeter("state/snapshot/bloom/storage/miss", nil)

	// ErrSnapshotStale is returned from data accessors if the underlying snapshot
	// layer had been invalidated due to the chain progressing forward far enough
	// to not maintain the layer's original state.
	ErrSnapshotStale = errors.New("snapshot stale")

	// ErrNotCoveredYet is returned from data accessors if the underlying snapshot
	// is being generated currently and the requested data item is not yet in the
	// range of accounts covered.
	ErrNotCoveredYet = errors.New("not covered yet")

	// ErrNotConstructed is returned if the callers want to iterate the snapshot
	// while the generation is not finished yet.
	ErrNotConstructed = errors.New("snapshot is not constructed")

	// errSnapshotCycle is returned if a snapshot is attempted to be inserted
	// that forms a cycle in the snapshot tree.
	errSnapshotCycle = errors.New("snapshot cycle")
)

// Snapshot represents the functionality supported by a snapshot storage layer.
type Snapshot interface {
	// Root returns the root hash for which this snapshot was made.
	Root() common.Hash

	// Account directly retrieves the account associated with a particular hash in
	// the snapshot slim data format.
	Account(hash common.Hash) (*Account, error)

	// AccountRLP directly retrieves the account RLP associated with a particular
	// hash in the snapshot slim data format.
	AccountRLP(hash common.Hash) ([]byte, error)

	// Storage directly retrieves the storage data associated with a particular hash,
	// within a particular account.
	Storage(accountHash, storageHash common.Hash) ([]byte, error)
}

// snapshot is the internal version of the snapshot data layer that supports some
// additional methods compared to the public API.
type snapshot interface {
	Snapshot

	// Parent returns the subsequent layer of a snapshot, or nil if the base was
	// reached.
	//
	// Note, the method is an internal helper to avoid type switching between the
	// disk and diff layers. There is no locking involved.
	Parent() snapshot

	// Update creates a new layer on top of the existing snapshot diff tree with
	// the specified data items.
	//
	// Note, the maps are retained by the method to avoid copying everything.
	Update(blockRoot common.Hash, destructs map[common.Hash]struct{}, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) *diffLayer

	// Journal commits an entire diff hierarchy to disk into a single journal entry.
	// This is meant to be used during shutdown to persist the snapshot without
	// flattening everything down (bad for reorgs).
	Journal(buffer *bytes.Buffer) (common.Hash, error)

	// Stale return whether this layer has become stale (was flattened across) or
	// if it's still live.
	Stale() bool

	// AccountIterator creates an account iterator over an arbitrary layer.
	AccountIterator(seek common.Hash) AccountIterator

	// StorageIterator creates a storage iterator over an arbitrary layer.
	StorageIterator(account common.Hash, seek common.Hash) (StorageIterator, bool)
}

// Tree is an Ethereum state snapshot tree. It consists of one persistent base
// layer backed by a key-value store, on top of which arbitrarily many in-memory
// diff layers are topped. The memory diffs can form a tree with branching, but
// the disk layer is singleton and common to all. If a reorg goes deeper than the
// disk layer, everything needs to be deleted.
//
// The goal of a state snapshot is twofold: to allow direct access to account and
// storage data to avoid expensive multi-level trie lookups; and to allow sorted,
// cheap iteration of the account/storage tries for sync aid.
//
// Tree 结构
// Snapshot 使用 Tree 表达，它是一个持久层 layer (diskLayer，如 HEAD-128)，及基于它的多个内存中的 diffLayers 组成
// 当新的区块提交时，不直接持久化，而是先写到内存 diffLayer 中，跟在前一 diffLayer 之后，理论上应该是一条链
// 为了节省内存，仅保存最近的 128 层 diffLayers
// 如果区块重组发生在这 128 层 diffLayers 之内，则可以直接找到分叉所在的 diffLayer，基于它构建新的 diffLayers
// 因此，实际的 diffLayers 构成了一颗树
// 如果重组的区块，比 持久化的 diskLayer 区块 还小，则整颗树数据都无效，此时的逻辑待确认 TODO
//
// 作用：直接访问 account 和 storage 数据；并支持顺序迭代
// 文档：
//   [Ask about Geth: Snapshot acceleration](https://blog.ethereum.org/2020/07/17/ask-about-geth-snapshot-acceleration/)
//   [Geth v1.10.0](https://blog.ethereum.org/2021/03/03/geth-v1-10-0/)
//   [Dodging a bullet: Ethereum State Problems](https://blog.ethereum.org/2021/05/18/eth_state_problems/)
//
// - A snapshot is a secondary data structure for storing the Ethereum state in a flat format, which can be built fully online, during the live operation of a Geth node.
// - benefit
//   - DOS attack-protection
//     - Instead of doing O(log N) disk reads (x LevelDB overhead: 7 levels) to access an account / storage slot, the snapshot can provide direct, O(1) access time (x LevelDB overhead).
//       - on mainnet with 140 million accounts, snapshots can save about 8 database lookups per account read.
//       - Whilst snapshots do grant us a 10x read performance, EVM execution also writes data, and these writes need to be Merkle proven. The Merkle proof requirement retains the necessity for O(logN) disk access on writes.
//   - Call
//   - Sync
//     - With the current Merkle-Patricia state model, these benefactors read 16TB of data off disk to serve a syncing node. Snapshots enable serving nodes to read only 96GB of data off disk to get a new node joined into the network.
//     - [Ethereum Snapshot Protocol (SNAP)](https://github.com/ethereum/devp2p/blob/master/caps/snap.md)
// - downside
//   - snapshot generation: 1 day to 1 week
//   - the raw account and storage data is essentially duplicated. In the case of mainnet, this means an extra 25GB of SSD space used.
//
// A Snapshot is a complete view of the Ethereum state at a given block. Abstract implementation wise, it is a dump of all accounts and storage slots, represented by a flat key-value store.
type Tree struct {
	diskdb ethdb.KeyValueStore      // Persistent database to store the snapshot
	triedb *trie.Database           // In-memory cache to access the trie through
	cache  int                      // Megabytes permitted to use for read caches

	// key 是 blockRoot，单位是区块; value 含义 TODO
	layers map[common.Hash]snapshot // Collection of all known layers

	// TODO 掌握 lock 的使用场景
	// 感觉是控制对 Tree.layers 的并发，主要在 diskRoot()
	lock   sync.RWMutex

	// Test hooks
	onFlatten func() // Hook invoked when the bottom most diff layers are flattened
}

// New attempts to load an already existing snapshot from a persistent key-value
// store (with a number of memory layers from a journal), ensuring that the head
// of the snapshot matches the expected one.
//
// If the snapshot is missing or the disk layer is broken, the snapshot will be
// reconstructed using both the existing data and the state trie.
// The repair happens on a background thread.
//
// If the memory layers in the journal do not match the disk layer (e.g. there is
// a gap) or the journal is missing, there are two repair cases:
//
// - if the 'recovery' parameter is true, all memory diff-layers will be discarded.
//   This case happens when the snapshot is 'ahead' of the state trie.
// - otherwise, the entire snapshot is considered invalid and will be recreated on
//   a background thread.
func New(diskdb ethdb.KeyValueStore, triedb *trie.Database, cache int, root common.Hash, async bool, rebuild bool, recovery bool) (*Tree, error) {
	// Create a new, empty snapshot tree
	snap := &Tree{
		diskdb: diskdb,
		triedb: triedb,
		cache:  cache,
		layers: make(map[common.Hash]snapshot),
	}
	if !async {
		defer snap.waitBuild()
	}

	// Attempt to load a previously persisted snapshot and rebuild one if failed
	head, disabled, err := loadSnapshot(diskdb, triedb, cache, root, recovery)
	if disabled {
		log.Warn("Snapshot maintenance disabled (syncing)")
		return snap, nil
	}
	if err != nil {
		if rebuild {
			log.Warn("Failed to load snapshot, regenerating", "err", err)
			snap.Rebuild(root)
			return snap, nil
		}
		return nil, err // Bail out the error, don't rebuild automatically.
	}

	// Existing snapshot loaded, seed all the layers
	for head != nil {
		snap.layers[head.Root()] = head
		head = head.Parent()
	}

	return snap, nil
}

// waitBuild blocks until the snapshot finishes rebuilding. This method is meant
// to be used by tests to ensure we're testing what we believe we are.
func (t *Tree) waitBuild() {
	// Find the rebuild termination channel
	var done chan struct{}

	t.lock.RLock()
	for _, layer := range t.layers {
		if layer, ok := layer.(*diskLayer); ok {
			done = layer.genPending
			break
		}
	}
	t.lock.RUnlock()

	// Wait until the snapshot is generated
	if done != nil {
		<-done
	}
}

// Disable interrupts any pending snapshot generator, deletes all the snapshot
// layers in memory and marks snapshots disabled globally. In order to resume
// the snapshot functionality, the caller must invoke Rebuild.
func (t *Tree) Disable() {
	// Interrupt any live snapshot layers
	t.lock.Lock()
	defer t.lock.Unlock()

	for _, layer := range t.layers {
		switch layer := layer.(type) {
		case *diskLayer:
			// If the base layer is generating, abort it
			if layer.genAbort != nil {
				abort := make(chan *generatorStats)
				layer.genAbort <- abort
				<-abort
			}
			// Layer should be inactive now, mark it as stale
			layer.lock.Lock()
			layer.stale = true
			layer.lock.Unlock()

		case *diffLayer:
			// If the layer is a simple diff, simply mark as stale
			layer.lock.Lock()
			atomic.StoreUint32(&layer.stale, 1)
			layer.lock.Unlock()

		default:
			panic(fmt.Sprintf("unknown layer type: %T", layer))
		}
	}
	t.layers = map[common.Hash]snapshot{}

	// Delete all snapshot liveness information from the database
	batch := t.diskdb.NewBatch()

	rawdb.WriteSnapshotDisabled(batch)
	rawdb.DeleteSnapshotRoot(batch)
	rawdb.DeleteSnapshotJournal(batch)
	rawdb.DeleteSnapshotGenerator(batch)
	rawdb.DeleteSnapshotRecoveryNumber(batch)
	// Note, we don't delete the sync progress

	if err := batch.Write(); err != nil {
		log.Crit("Failed to disable snapshots", "err", err)
	}
}

// Snapshot retrieves a snapshot belonging to the given block root, or nil if no
// snapshot is maintained for that block.
func (t *Tree) Snapshot(blockRoot common.Hash) Snapshot {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.layers[blockRoot]
}

// Snapshots returns all visited layers from the topmost layer with specific
// root and traverses downward. The layer amount is limited by the given number.
// If nodisk is set, then disk layer is excluded.
// 调用来源：Pruner.Prune() / Pruner.RecoverPruning()
// @param root 某个区块的 State Trie 根哈希
// @return 返回 root 表示的某个区块的前 limits 层 (含 root)
func (t *Tree) Snapshots(root common.Hash, limits int, nodisk bool) []Snapshot {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if limits == 0 {
		return nil
	}
	layer := t.layers[root]
	if layer == nil {
		return nil
	}
	var ret []Snapshot
	for {
		if _, isdisk := layer.(*diskLayer); isdisk && nodisk {
			break
		}
		ret = append(ret, layer)
		limits -= 1
		if limits == 0 {
			break
		}
		parent := layer.Parent()
		if parent == nil {
			break
		}
		layer = parent
	}
	return ret
}

// Update adds a new snapshot into the tree, if that can be linked to an existing
// old parent. It is disallowed to insert a disk layer (the origin of all).
// 唯一调用来源：StateDB.Commit() -> Snapshot.Update() + Snapshot.Cap()
// 在提交新区块的状态时，会调用当前函数，参数 blockRoot 为新区块的根哈希，parentRoot 为上一区块的根哈希
// 基于 parentRoot 添加一层 diffLayer，由 blockRoot 表示新的根哈希
func (t *Tree) Update(blockRoot common.Hash, parentRoot common.Hash, destructs map[common.Hash]struct{}, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) error {
	// Reject noop updates to avoid self-loops in the snapshot tree. This is a
	// special case that can only happen for Clique networks where empty blocks
	// don't modify the state (0 block subsidy).
	//
	// Although we could silently ignore this internally, it should be the caller's
	// responsibility to avoid even attempting to insert such a snapshot.
	if blockRoot == parentRoot {
		return errSnapshotCycle
	}

	// Generate a new snapshot on top of the parent
	parent := t.Snapshot(parentRoot)
	if parent == nil {
		return fmt.Errorf("parent [%#x] snapshot missing", parentRoot)
	}

	// 基于 parent 添加一层 diffLayer，由 blockRoot 表示新的根哈希
	snap := parent.(snapshot).Update(blockRoot, destructs, accounts, storage)

	// Save the new snapshot for later
	t.lock.Lock()
	defer t.lock.Unlock()

	t.layers[snap.root] = snap
	return nil
}

// Cap traverses downwards the snapshot tree from a head block hash until the
// number of allowed layers are crossed. All layers beyond the permitted number
// are flattened downwards.
//
// Note, the final diff layer count in general will be one more than the amount
// requested. This happens because the bottom-most diff layer is the accumulator
// which may or may not overflow and cascade to disk. Since this last layer's
// survival is only known *after* capping, we need to omit it from the count if
// we want to ensure that *at least* the requested number of diff layers remain.
// 调用来源一：
// Prune.prune() -> Tree.Cap(); 此时参数 layers 为 0
// 调用来源二：
// StateDB.Commit() -> Tree.Update() + Tree.Cap()；
// StateDB.Commit() 先调用 Tree.Update()，基于前一区块 diffLayer 构建新区块的 diffLayer，
// 然后调用当前函数 Tree.Cap()，传入参数 root 为新区块的根哈希，layers 固定为 128
func (t *Tree) Cap(root common.Hash, layers int) error {
	// Retrieve the head snapshot to cap from
	snap := t.Snapshot(root)
	if snap == nil {
		return fmt.Errorf("snapshot [%#x] missing", root)
	}

	diff, ok := snap.(*diffLayer)
	if !ok {
		return fmt.Errorf("snapshot [%#x] is disk layer", root)
	}

	// If the generator is still running, use a more aggressive cap
	diff.origin.lock.RLock()
	if diff.origin.genMarker != nil && layers > 8 {
		layers = 8
	}
	diff.origin.lock.RUnlock()

	// Run the internal capping and discard all stale layers
	t.lock.Lock()
	defer t.lock.Unlock()

	// Flattening the bottom-most diff layer requires special casing since there's
	// no child to rewire to the grandparent. In that case we can fake a temporary
	// child for the capping and then remove it.
	// 仅在由 Prune.prune() -> Snapshot.Cap() 时，参数 layers 为 0
	if layers == 0 {
		// If full commit was requested, flatten the diffs and merge onto disk
		diff.lock.RLock()
		base := diffToDisk(diff.flatten().(*diffLayer))
		diff.lock.RUnlock()

		// Replace the entire snapshot tree with the flat base
		t.layers = map[common.Hash]snapshot{base.root: base}

		return nil
	}

	// 返回被修改的 diskLayer；如果未修改 diskLayer，则返回 nil
	persisted := t.cap(diff, layers)

	// Remove any layer that is stale or links into a stale layer
	children := make(map[common.Hash][]common.Hash)
	for root, snap := range t.layers {
		if diff, ok := snap.(*diffLayer); ok {
			parent := diff.parent.Root()
			children[parent] = append(children[parent], root)
		}
	}
	var remove func(root common.Hash)
	remove = func(root common.Hash) {
		delete(t.layers, root)
		for _, child := range children[root] {
			remove(child)
		}
		delete(children, root)
	}
	for root, snap := range t.layers {
		if snap.Stale() {
			remove(root)
		}
	}

	// If the disk layer was modified, regenerate all the cumulative blooms
	// 如果 diskLayer 有修改，自底向上更新每一层的过滤器
	if persisted != nil {
		var rebloom func(root common.Hash)
		rebloom = func(root common.Hash) {
			if diff, ok := t.layers[root].(*diffLayer); ok {
				diff.rebloom(persisted)
			}

			// 注意这里是个递归，将上层过滤器合并到本层，顺序为：
			// diffLayer1 <-pull diffLayer0
			// diffLayer2 <-pull diffLayer1
			// ...
			// diffLayerY <-pull diffLayerX
			// 用 for 遍历 children[root] 的意思，是同一父层可能由多层子层 (即分叉)
			for _, child := range children[root] {
				rebloom(child)
			}
		}

		rebloom(persisted.root)
	}

	return nil
}

// cap traverses downwards the diff tree until the number of allowed layers are
// crossed. All diffs beyond the permitted number are flattened downwards. If the
// layer limit is reached, memory cap is also enforced (but not before).
//
// The method returns the new disk layer if diffs were persisted into it.
//
// Note, the final diff layer count in general will be one more than the amount
// requested. This happens because the bottom-most diff layer is the accumulator
// which may or may not overflow and cascade to disk. Since this last layer's
// survival is only known *after* capping, we need to omit it from the count if
// we want to ensure that *at least* the requested number of diff layers remain.
// 参数 layers 表示自 diff 往下，保留的 diffLayer 层数；
// 更深的多层 diffLayers 将通过 flatten() 合并为一层 diffLayer
func (t *Tree) cap(diff *diffLayer, layers int) *diskLayer {
	// Dive until we run out of layers or reach the persistent database
	for i := 0; i < layers-1; i++ {
		// If we still have diff layers below, continue down
		if parent, ok := diff.parent.(*diffLayer); ok {
			diff = parent
		} else {
			// Diff stack too shallow, return without modifications
			return nil
		}
	}

	// diffLayer{N+layers-1} <- 参数 diff
	// ...
	// diffLayerN+1 <- 临时变量 diff'
	// diffLayerN <- 临时变量 parent
	// ...
	// diffLayer1
	// diffLayer0
	// diskLayer
	//
	// 处理
	// 1.找到符合参数 layers 的 diffLayerN，记为 parent
	// 2.通过 flatten() 合并 parent 到 diffLayer0
	//
	// diffLayer{N+layers-1} <- 参数 diff
	// ...
	// diffLayerN+1 <- diff'
	// diffLayer0 <- flattened
	// diskLayer

	// We're out of layers, flatten anything below, stopping if it's the disk or if
	// the memory limit is not yet exceeded.
	switch parent := diff.parent.(type) {
	case *diskLayer:
		return nil

	case *diffLayer:
		// Hold the write lock until the flattened parent is linked correctly.
		// Otherwise, the stale layer may be accessed by external reads in the
		// meantime.
		diff.lock.Lock()
		defer diff.lock.Unlock()

		// Flatten the parent into the grandparent. The flattening internally obtains a
		// write lock on grandparent.
		// flattened 表示合并后形成的新的 diffLayer
		flattened := parent.flatten().(*diffLayer)
		t.layers[flattened.root] = flattened

		// Invoke the hook if it's registered. Ugly hack.
		if t.onFlatten != nil {
			t.onFlatten()
		}

		// 指向合并得到的 diffLayer
		diff.parent = flattened

		// 未超过内存限制，且 diskLayer 不在后台生成中，则直接返回 nil，表示 diskLayer 未修改
		// 否则，需要中断已有的生成过程，然后将当前的内存数据写入 diskLayer，再重启生成过程
		if flattened.memory < aggregatorMemoryLimit {
			// Accumulator layer is smaller than the limit, so we can abort, unless
			// there's a snapshot being generated currently. In that case, the trie
			// will move from underneath the generator so we **must** merge all the
			// partial data down into the snapshot and restart the generation.
			if flattened.parent.(*diskLayer).genAbort == nil {
				return nil
			}
		}
	default:
		panic(fmt.Sprintf("unknown data layer: %T", parent))
	}

	// If the bottom-most layer is larger than our memory cap, persist to disk
	// 此时 diff.parent 一定是 bottom diffLayer
	bottom := diff.parent.(*diffLayer)

	bottom.lock.RLock()

	// 将 bottom diffLayer 写入 diskLayer，得到新构建的 diskLayer
	// diffToDisk() 会将 bottom.stale 修改为 true，表示 bottom 已经失效
	base := diffToDisk(bottom)

	bottom.lock.RUnlock()

	// 指向新的 diskLayer
	t.layers[base.root] = base

	// bottom diffLayer 已经写入 diskLayer，需要丢弃 (bottom.stale 在 diffToDisk() 中设置为 true)
	// 因此 diff 成了 bottom diffLayer，parent 指向 diskLayer
	diff.parent = base

	// 返回新的 diskLayer
	return base
}

// diffToDisk merges a bottom-most diff into the persistent disk layer underneath
// it. The method will panic if called onto a non-bottom-most diff layer.
//
// The disk layer persistence should be operated in an atomic way. All updates should
// be discarded if the whole transition if not finished.
// 调用来源：Tree.Cap() / Tree.cap()
// 将 bottom diffLayer 写入 diskLayer.cached，返回新构建的 diskLayer
func diffToDisk(bottom *diffLayer) *diskLayer {
	var (
		base  = bottom.parent.(*diskLayer)
		batch = base.diskdb.NewBatch()
		stats *generatorStats
	)

	// If the disk layer is running a snapshot generator, abort it
	if base.genAbort != nil {
		abort := make(chan *generatorStats)
		base.genAbort <- abort
		stats = <-abort
	}

	// 删除数据库中此前保存的 snapshot 根节点
	// Put the deletion in the batch writer, flush all updates in the final step.
	rawdb.DeleteSnapshotRoot(batch)

	// Mark the original base as stale as we're going to create a new wrapper
	base.lock.Lock()
	if base.stale {
		panic("parent disk layer is stale") // we've committed into the same base from two children, boo
	}

	// 将 base.stale 设置为 true
	base.stale = true
	base.lock.Unlock()

	// Destroy all the destructed accounts from the database
	// 遍历被销毁的 accounts' hash
	for hash := range bottom.destructSet {
		// Skip any account not covered yet by the snapshot
		if base.genMarker != nil && bytes.Compare(hash[:], base.genMarker) > 0 {
			continue
		}

		// Remove all storage slots
		// 删除账户的 State Trie 节点
		rawdb.DeleteAccountSnapshot(batch, hash)
		base.cache.Set(hash[:], nil)

		// 遍历删除账户的 Storage Trie
		it := rawdb.IterateStorageSnapshots(base.diskdb, hash)
		for it.Next() {
			if key := it.Key(); len(key) == 65 { // TODO(karalabe): Yuck, we should move this into the iterator
				batch.Delete(key)
				base.cache.Del(key[1:])
				snapshotFlushStorageItemMeter.Mark(1)

				// Ensure we don't delete too much data blindly (contract can be
				// huge). It's ok to flush, the root will go missing in case of a
				// crash and we'll detect and regenerate the snapshot.
				if batch.ValueSize() > ethdb.IdealBatchSize {
					if err := batch.Write(); err != nil {
						log.Crit("Failed to write storage deletions", "err", err)
					}
					batch.Reset()
				}
			}
		}
		it.Release()
	}

	// Push all updated accounts into the database
	// 写入 State Trie
	for hash, data := range bottom.accountData {
		// Skip any account not covered yet by the snapshot
		if base.genMarker != nil && bytes.Compare(hash[:], base.genMarker) > 0 {
			continue
		}

		// Push the account to disk
		rawdb.WriteAccountSnapshot(batch, hash, data)
		base.cache.Set(hash[:], data)

		snapshotCleanAccountWriteMeter.Mark(int64(len(data)))

		snapshotFlushAccountItemMeter.Mark(1)
		snapshotFlushAccountSizeMeter.Mark(int64(len(data)))

		// Ensure we don't write too much data blindly. It's ok to flush, the
		// root will go missing in case of a crash and we'll detect and regen
		// the snapshot.
		if batch.ValueSize() > ethdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				log.Crit("Failed to write storage deletions", "err", err)
			}
			batch.Reset()
		}
	}

	// Push all the storage slots into the database
	// 写入 Storage Trie
	for accountHash, storage := range bottom.storageData {
		// Skip any account not covered yet by the snapshot
		if base.genMarker != nil && bytes.Compare(accountHash[:], base.genMarker) > 0 {
			continue
		}
		// Generation might be mid-account, track that case too
		midAccount := base.genMarker != nil && bytes.Equal(accountHash[:], base.genMarker[:common.HashLength])

		for storageHash, data := range storage {
			// Skip any slot not covered yet by the snapshot
			if midAccount && bytes.Compare(storageHash[:], base.genMarker[common.HashLength:]) > 0 {
				continue
			}
			if len(data) > 0 {
				rawdb.WriteStorageSnapshot(batch, accountHash, storageHash, data)
				base.cache.Set(append(accountHash[:], storageHash[:]...), data)
				snapshotCleanStorageWriteMeter.Mark(int64(len(data)))
			} else {
				rawdb.DeleteStorageSnapshot(batch, accountHash, storageHash)
				base.cache.Set(append(accountHash[:], storageHash[:]...), nil)
			}
			snapshotFlushStorageItemMeter.Mark(1)
			snapshotFlushStorageSizeMeter.Mark(int64(len(data)))
		}
	}

	// 向数据库写入 snapshot 新的根节点 bottom.root
	// Update the snapshot block marker and write any remainder data
	rawdb.WriteSnapshotRoot(batch, bottom.root)

	// Write out the generator progress marker and report
	journalProgress(batch, base.genMarker, stats)

	// Flush all the updates in the single db operation. Ensure the
	// disk layer transition is atomic.
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write leftover snapshot", "err", err)
	}

	log.Debug("Journalled disk layer", "root", bottom.root, "complete", base.genMarker == nil)

	// 构建新的 diskLayer
	// 注意这里未对 stale 字段初始化，因此为默认值 false
	res := &diskLayer{
		// 注意返回的 diskLayer.root 是原来的 diffLayer(bottom).root
		root:       bottom.root,

		cache:      base.cache,
		diskdb:     base.diskdb,
		triedb:     base.triedb,
		genMarker:  base.genMarker,
		genPending: base.genPending,
	}

	// If snapshot generation hasn't finished yet, port over all the starts and
	// continue where the previous round left off.
	//
	// Note, the `base.genAbort` comparison is not used normally, it's checked
	// to allow the tests to play with the marker without triggering this path.
	if base.genMarker != nil && base.genAbort != nil {
		res.genMarker = base.genMarker
		res.genAbort = make(chan chan *generatorStats)
		go res.generate(stats)
	}
	return res
}

// Journal commits an entire diff hierarchy to disk into a single journal entry.
// This is meant to be used during shutdown to persist the snapshot without
// flattening everything down (bad for reorgs).
//
// The method returns the root hash of the base layer that needs to be persisted
// to disk as a trie too to allow continuing any pending generation op.
// 功能：对内存 snapshot Tree 进行序列化，存储到日志中
// 日志使用：core.NewBlockChain() -> snapshot.New() -> loadSnapshot() -> loadAndParseJournal()
//
// 在 geth 节点即将退出时通过 BlockChain.Stop() 调用当前函数，参数 root 为 BlockChain.CurrentBlock().Root()
// 写入数据为 version + diskRootHash + diffLayer0Serialized + ... diffLayerCurrentBlockSerialized
// 其中：diffLayerNSerialized 为 diffLayer.rootHash + destructSet + accountData + storageData
func (t *Tree) Journal(root common.Hash) (common.Hash, error) {
	// Retrieve the head snapshot to journal from var snap snapshot
	snap := t.Snapshot(root)
	if snap == nil {
		return common.Hash{}, fmt.Errorf("snapshot [%#x] missing", root)
	}

	// Run the journaling
	t.lock.Lock()
	defer t.lock.Unlock()

	// 1.版本号
	// Firstly write out the metadata of journal
	journal := new(bytes.Buffer)
	if err := rlp.Encode(journal, journalVersion); err != nil {
		return common.Hash{}, err
	}

	diskroot := t.diskRoot()
	if diskroot == (common.Hash{}) {
		return common.Hash{}, errors.New("invalid disk root")
	}

	// 2.写入 diskroot (diskLayer 表示的根哈希)
	// Secondly write out the disk layer root, ensure the
	// diff journal is continuous with disk.
	if err := rlp.Encode(journal, diskroot); err != nil {
		return common.Hash{}, err
	}

	// 3.递归写入 diffLayer 序列化的数据
	// Finally write out the journal of each layer in reverse order.
	base, err := snap.(snapshot).Journal(journal)
	if err != nil {
		return common.Hash{}, err
	}

	// Store the journal into the database and return
	rawdb.WriteSnapshotJournal(t.diskdb, journal.Bytes())
	return base, nil
}

// Rebuild wipes all available snapshot data from the persistent database and
// discard all caches and diff layers. Afterwards, it starts a new snapshot
// generator with the given root hash.
func (t *Tree) Rebuild(root common.Hash) {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Firstly delete any recovery flag in the database. Because now we are
	// building a brand new snapshot. Also reenable the snapshot feature.
	rawdb.DeleteSnapshotRecoveryNumber(t.diskdb)
	rawdb.DeleteSnapshotDisabled(t.diskdb)

	// Iterate over and mark all layers stale
	for _, layer := range t.layers {
		switch layer := layer.(type) {
		case *diskLayer:
			// If the base layer is generating, abort it and save
			if layer.genAbort != nil {
				abort := make(chan *generatorStats)
				layer.genAbort <- abort
				<-abort
			}
			// Layer should be inactive now, mark it as stale
			layer.lock.Lock()
			layer.stale = true
			layer.lock.Unlock()

		case *diffLayer:
			// If the layer is a simple diff, simply mark as stale
			layer.lock.Lock()
			atomic.StoreUint32(&layer.stale, 1)
			layer.lock.Unlock()

		default:
			panic(fmt.Sprintf("unknown layer type: %T", layer))
		}
	}
	// Start generating a new snapshot from scratch on a background thread. The
	// generator will run a wiper first if there's not one running right now.
	log.Info("Rebuilding state snapshot")
	t.layers = map[common.Hash]snapshot{
		root: generateSnapshot(t.diskdb, t.triedb, t.cache, root),
	}
}

// AccountIterator creates a new account iterator for the specified root hash and
// seeks to a starting account hash.
// State Trie 的迭代器
func (t *Tree) AccountIterator(root common.Hash, seek common.Hash) (AccountIterator, error) {
	ok, err := t.generating()
	if err != nil {
		return nil, err
	}
	if ok {
		return nil, ErrNotConstructed
	}
	return newFastAccountIterator(t, root, seek)
}

// StorageIterator creates a new storage iterator for the specified root hash and
// account. The iterator will be move to the specific start position.
// Storage Trie 的迭代器
func (t *Tree) StorageIterator(root common.Hash, account common.Hash, seek common.Hash) (StorageIterator, error) {
	ok, err := t.generating()
	if err != nil {
		return nil, err
	}
	if ok {
		return nil, ErrNotConstructed
	}
	return newFastStorageIterator(t, root, account, seek)
}

// Verify iterates the whole state(all the accounts as well as the corresponding storages)
// with the specific root and compares the re-computed hash with the original one.
func (t *Tree) Verify(root common.Hash) error {
	acctIt, err := t.AccountIterator(root, common.Hash{})
	if err != nil {
		return err
	}
	defer acctIt.Release()

	got, err := generateTrieRoot(nil, acctIt, common.Hash{}, stackTrieGenerate, func(db ethdb.KeyValueWriter, accountHash, codeHash common.Hash, stat *generateStats) (common.Hash, error) {
		storageIt, err := t.StorageIterator(root, accountHash, common.Hash{})
		if err != nil {
			return common.Hash{}, err
		}
		defer storageIt.Release()

		hash, err := generateTrieRoot(nil, storageIt, accountHash, stackTrieGenerate, nil, stat, false)
		if err != nil {
			return common.Hash{}, err
		}
		return hash, nil
	}, newGenerateStats(), true)

	if err != nil {
		return err
	}
	if got != root {
		return fmt.Errorf("state root hash mismatch: got %x, want %x", got, root)
	}
	return nil
}

// disklayer is an internal helper function to return the disk layer.
// The lock of snapTree is assumed to be held already.
func (t *Tree) disklayer() *diskLayer {
	var snap snapshot

	// t.layers 是个 map，这里感觉是随便找个 snapshot 的意思
	for _, s := range t.layers {
		snap = s
		break
	}

	if snap == nil {
		return nil
	}

	// 判断 snapshot 类型
	switch layer := snap.(type) {
	case *diskLayer:
		return layer
	case *diffLayer:
		// 返回 snapshot 底层的 diskLayer
		return layer.origin
	default:
		panic(fmt.Sprintf("%T: undefined layer", snap))
	}
}

// diskRoot is an internal helper function to return the disk layer root.
// The lock of snapTree is assumed to be held already.
func (t *Tree) diskRoot() common.Hash {
	disklayer := t.disklayer()
	if disklayer == nil {
		return common.Hash{}
	}
	return disklayer.Root()
}

// generating is an internal helper function which reports whether the snapshot
// is still under the construction.
func (t *Tree) generating() (bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	layer := t.disklayer()
	if layer == nil {
		return false, errors.New("disk layer is missing")
	}
	layer.lock.RLock()
	defer layer.lock.RUnlock()
	return layer.genMarker != nil, nil
}

// DiskRoot is a external helper function to return the disk layer root.
func (t *Tree) DiskRoot() common.Hash {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.diskRoot()
}
