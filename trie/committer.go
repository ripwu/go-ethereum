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

package trie

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// leafChanSize is the size of the leafCh. It's a pretty arbitrary number, to allow
// some parallelism but not incur too much memory overhead.
const leafChanSize = 200

// leaf represents a trie leaf value
type leaf struct {
	size int         // size of the rlp data (estimate)
	hash common.Hash // hash of rlp data
	node node        // the node to commit
}

// committer is a type used for the trie Commit operation. A committer has some
// internal preallocated temp space, and also a callback that is invoked when
// leaves are committed. The leafs are passed through the `leafCh`,  to allow
// some level of parallelism.
// By 'some level' of parallelism, it's still the case that all leaves will be
// processed sequentially - onleaf will never be called in parallel or out of order.
type committer struct {
	tmp sliceBuffer
	sha crypto.KeccakState

	onleaf LeafCallback
	leafCh chan *leaf
}

// committers live in a global sync.Pool
var committerPool = sync.Pool{
	New: func() interface{} {
		return &committer{
			tmp: make(sliceBuffer, 0, 550), // cap is as large as a full fullNode.
			sha: sha3.NewLegacyKeccak256().(crypto.KeccakState),
		}
	},
}

// newCommitter creates a new committer or picks one from the pool.
func newCommitter() *committer {
	return committerPool.Get().(*committer)
}

func returnCommitterToPool(h *committer) {
	h.onleaf = nil
	h.leafCh = nil
	committerPool.Put(h)
}

// Commit collapses a node down into a hash node and inserts it into the database
// 这段代码要放在 Trie.Commit() 函数中理解：它在 Trie.Hash() 之后被调用
func (c *committer) Commit(n node, db *Database) (hashNode, int, error) {
	if db == nil {
		return nil, 0, errors.New("no db provided")
	}
	h, committed, err := c.commit(n, db)
	if err != nil {
		return nil, 0, err
	}
	return h.(hashNode), committed, nil
}

// commit collapses a node down into a hash node and inserts it into the database
func (c *committer) commit(n node, db *Database) (node, int, error) {
	// if this path is clean, use available cached data
	hash, dirty := n.cache()
	if hash != nil && !dirty {
		return hash, 0, nil
	}
	// Commit children, then parent, and remove remove the dirty flag.
	switch cn := n.(type) {
	case *shortNode:
		// Commit child
		collapsed := cn.copy()

		// If the child is fullNode, recursively commit,
		// otherwise it can only be hashNode or valueNode.
		var childCommitted int
		if _, ok := cn.Val.(*fullNode); ok {
			childV, committed, err := c.commit(cn.Val, db)
			if err != nil {
				return nil, 0, err
			}

			// XXX 注意这里：如果 Val 原本指向 分支节点，在这里会被修改为 childV (大部分情况下，此时 childV 应该是 hashNode 类型)
			// 隐藏的意思：如果 Val 原本指向 valueNode 或 hashNode，此时不变
			collapsed.Val, childCommitted = childV, committed
		}

		// The key needs to be copied, since we're delivering it to database
		collapsed.Key = hexToCompact(cn.Key)

		// 可以看到，在 insert 之前只有 Key 改成 Compact 编码，Val 是未修改的，因此保持原有的编码
		// 如果当前节点为叶子节点，Val 原有编码是什么? 感觉理论上要看当前这棵树的类型，但对于 State Trie 或 Storage Trie 的实际使用：
		// 如果是 State Trie，那么调用入口为 Trie.TryUpdateAccount()，参数为 types.StateAccount 四元组，该函数内部会先调用 rlp.EncodeToBytes 将其转为 []byte
		// 如果是 Storage Trie，那么调用来源为 stateObject.updateTrie()，该函数在调用 Trie.TryUpdate() 前，会先调用 rlp.EncodeToBytes 将 value 转为 []byte
		hashedNode := c.store(collapsed, db)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn, childCommitted + 1, nil
		}
		return collapsed, childCommitted, nil
	case *fullNode:
		hashedKids, childCommitted, err := c.commitChildren(cn, db)
		if err != nil {
			return nil, 0, err
		}

		collapsed := cn.copy()
		collapsed.Children = hashedKids

		hashedNode := c.store(collapsed, db)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn, childCommitted + 1, nil
		}
		return collapsed, childCommitted, nil
	case hashNode:
		// 理解：如果是 hashNode，说明 db 中的数据已经是最新的了，因此不需要再展开了
		return cn, 0, nil
	default:
		// nil, valuenode shouldn't be committed
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// commitChildren commits the children of the given fullnode
func (c *committer) commitChildren(n *fullNode, db *Database) ([17]node, int, error) {
	var (
		committed int
		children  [17]node
	)
	for i := 0; i < 16; i++ {
		child := n.Children[i]
		if child == nil {
			continue
		}
		// If it's the hashed child, save the hash value directly.
		// Note: it's impossible that the child in range [0, 15]
		// is a valueNode.
		if hn, ok := child.(hashNode); ok {
			children[i] = hn
			continue
		}
		// Commit the child recursively and store the "hashed" value.
		// Note the returned node can be some embedded nodes, so it's
		// possible the type is not hashNode.
		hashed, childCommitted, err := c.commit(child, db)
		if err != nil {
			return children, 0, err
		}
		children[i] = hashed
		committed += childCommitted
	}
	// For the 17th child, it's possible the type is valuenode.
	if n.Children[16] != nil {
		children[16] = n.Children[16]
	}
	return children, committed, nil
}

// store hashes the node n and if we have a storage layer specified, it writes
// the key/value pair to it and tracks any node->child references as well as any
// node->external trie references.
// 传入要存储的 n 节点，可能原样返回 n 节点，或者返回 n.nodeFlag.cache 存储的 hashNode
func (c *committer) store(n node, db *Database) node {
	// Larger nodes are replaced by their hash and stored in the database.
	var (
		hash, _ = n.cache()
		size    int
	)
	if hash == nil {
		// 调用来源为 Trie.Commit() -> Trie.Hash(), h.Commit() -> h.store()，即调用当前函数前，
		// 肯定先调用了 Trie.Hash() 计算了每个节点的 RLP 编码后的哈希并保存在 nodeFlags.cache 中；
		// 因此，如果这里为 nil，说明 Key + Val 编码少于 32 字节，即少于一个 hashNode 的大小，此时直接 return n

		// XXX 注意这里：因为直接 return，所以当前 n 不会被直接 insert()，但它会被嵌入到上层节
		// 点中，如 (fullNode.children[X])；在上层节点被 insert() 时，隐含 insert 了 当前节点

		// This was not generated - must be a small node stored in the parent.
		// In theory, we should apply the leafCall here if it's not nil(embedded
		// node usually contains value). But small value(less than 32bytes) is
		// not our target.
		return n
	} else {
		// We have the hash already, estimate the RLP encoding-size of the node.
		// The size is used for mem tracking, does not need to be exact
		size = estimateSize(n)
	}

	// If we're using channel-based leaf-reporting, send to channel.
	// The leaf channel will be active only when there an active leaf-callback
	if c.leafCh != nil {
		// 这里不管 node 是什么类型，都会写入 leafCh
		// commitLoop() 在处理 leafCh 时，实际回调前会检查 node 类型为叶子节点
		c.leafCh <- &leaf{
			size: size,
			hash: common.BytesToHash(hash), // 哈希
			node: n, // 实际节点内容
		}
	} else if db != nil {
		// No leaf-callback used, but there's still a database. Do serial
		// insertion
		db.lock.Lock()

		// 哈希 和 实际节点内容
		db.insert(common.BytesToHash(hash), size, n)

		db.lock.Unlock()
	}
	return hash
}

// commitLoop does the actual insert + leaf callback for nodes.
func (c *committer) commitLoop(db *Database) {
	for item := range c.leafCh {
		var (
			hash = item.hash
			size = item.size
			n    = item.node
		)
		// We are pooling the trie nodes into an intermediate memory cache
		db.lock.Lock()
		db.insert(hash, size, n)
		db.lock.Unlock()

		// 这里判断为叶子节点，才真的回调
		if c.onleaf != nil {
			switch n := n.(type) {
			case *shortNode:
				if child, ok := n.Val.(valueNode); ok {
					c.onleaf(nil, nil, child, hash)
				}
			case *fullNode:
				// For children in range [0, 15], it's impossible
				// to contain valueNode. Only check the 17th child.
				if n.Children[16] != nil {
					c.onleaf(nil, nil, n.Children[16].(valueNode), hash)
				}
			}
		}
	}
}

func (c *committer) makeHashNode(data []byte) hashNode {
	n := make(hashNode, c.sha.Size())
	c.sha.Reset()
	c.sha.Write(data)
	c.sha.Read(n)
	return n
}

// estimateSize estimates the size of an rlp-encoded node, without actually
// rlp-encoding it (zero allocs). This method has been experimentally tried, and with a trie
// with 1000 leafs, the only errors above 1% are on small shortnodes, where this
// method overestimates by 2 or 3 bytes (e.g. 37 instead of 35)
func estimateSize(n node) int {
	switch n := n.(type) {
	case *shortNode:
		// A short node contains a compacted key, and a value.
		return 3 + len(n.Key) + estimateSize(n.Val)
	case *fullNode:
		// A full node contains up to 16 hashes (some nils), and a key
		s := 3
		for i := 0; i < 16; i++ {
			if child := n.Children[i]; child != nil {
				s += estimateSize(child)
			} else {
				s++
			}
		}
		return s
	case valueNode:
		return 1 + len(n)
	case hashNode:
		return 1 + len(n)
	default:
		panic(fmt.Sprintf("node type %T", n))
	}
}
