// Copyright 2014 The go-ethereum Authors
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
	"fmt"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// [Modified Merkle Patricia Trie Specification (also Merkle Patricia Tree)](https://eth.wiki/en/fundamentals/patricia-tree)
var indices = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "[17]"}

type node interface {
	fstring(string) string
	cache() (hashNode, bool) // 子树坍缩后的 hash
}

type (
	fullNode struct { // 分支节点
		// 可能的父节点类型：fullNode，shortNode
		// 可能的子节点类型：
		//     Children[0-15] 可能是 fullNode, shortNode, hashNode 类型
		//     但一定不是 valueNode 类型 (这种情况应该是 shortNode({Key: 16(terminator, Val)}))
		//
		// Children[16] 如果存在的话，一定是 valueNode 类型
		// 实际中 Children[16] 应该不存在：
		//   因为 SecureTrie 对所有 key 做了哈希，路径都是 64 半字节。所以 Children[16] 如果存在，意味着这个节点的总路径已经为 64 半字节；
		//   而 fullNode 意味着还有更下层，即长度超过 65 半字节的路径，这不可能
		Children [17]node // Actual trie node data to encode/decode (needs custom encoder)

		flags    nodeFlag // flags 是小写，所以不会被 hashFullNodeChildren() encode....
	}

	shortNode struct { // 扩展节点/叶子节点
		// 可能的父节点类型：fullNode，不可能是 shortNode
		// 可能的子节点类型：
		//   如果 Key 是否有 terminator，则当前节点为叶子节点，此时 Val 为 valueNode 类型
		//   否则，Val 只可能是 fullNode 或 hashNode 类型，一定不是 valueNode 或 shortNode 类型
		Key   []byte
		Val   node

		flags nodeFlag // flags 是小写，所以不会被 hashShortNodeChildren() encode....
	}

	hashNode  []byte // 需要从 database 中加载后重新展开
	valueNode []byte // 叶子节点
)

// nilValueNode is used when collapsing internal trie nodes for hashing, since
// unset children need to serialize correctly.
var nilValueNode = valueNode(nil)

// EncodeRLP encodes a full node into the consensus RLP format.
func (n *fullNode) EncodeRLP(w io.Writer) error {
	var nodes [17]node

	// 如果 child 为 nil，直接调用 rlp.Encode 将 panic: reflect: call of reflect.Value.Type on zero Value
	// 因此，这里替换为 valueNode(nil)，使得其 RLP 编码正常，得到结果为 [128]
	for i, child := range &n.Children {
		if child != nil {
			nodes[i] = child
		} else {
			nodes[i] = nilValueNode
		}
	}
	return rlp.Encode(w, nodes)
}

func (n *fullNode) copy() *fullNode   { copy := *n; return &copy }
func (n *shortNode) copy() *shortNode { copy := *n; return &copy }

// nodeFlag contains caching-related metadata about a node.
type nodeFlag struct {
	hash  hashNode // cached hash of the node (may be nil)

	// dirty 含义：修改(树结构变化)后是否提交到 Database.dirties
	// 任何时候都注意：node 创建后就不修改了，包括 hash 和 dirty
	// 想要修改，都是新建节点
	dirty bool     // whether the node has changes that must be written to the database
}

func (n *fullNode) cache() (hashNode, bool)  { return n.flags.hash, n.flags.dirty }
func (n *shortNode) cache() (hashNode, bool) { return n.flags.hash, n.flags.dirty }
func (n hashNode) cache() (hashNode, bool)   { return nil, true }
func (n valueNode) cache() (hashNode, bool)  { return nil, true }

// Pretty printing.
func (n *fullNode) String() string  { return n.fstring("") }
func (n *shortNode) String() string { return n.fstring("") }
func (n hashNode) String() string   { return n.fstring("") }
func (n valueNode) String() string  { return n.fstring("") }

func (n *fullNode) fstring(ind string) string {
	resp := fmt.Sprintf("[\n%s  ", ind)
	for i, node := range &n.Children {
		if node == nil {
			resp += fmt.Sprintf("%s: <nil> ", indices[i])
		} else {
			resp += fmt.Sprintf("%s: %v", indices[i], node.fstring(ind+"  "))
		}
	}
	return resp + fmt.Sprintf("\n%s] ", ind)
}
func (n *shortNode) fstring(ind string) string {
	return fmt.Sprintf("{%x: %v} ", n.Key, n.Val.fstring(ind+"  "))
}
func (n hashNode) fstring(ind string) string {
	return fmt.Sprintf("<%x> ", []byte(n))
}
func (n valueNode) fstring(ind string) string {
	return fmt.Sprintf("%x ", []byte(n))
}

func mustDecodeNode(hash, buf []byte) node {
	n, err := decodeNode(hash, buf)
	if err != nil {
		panic(fmt.Sprintf("node %x: %v", hash, err))
	}
	return n
}

// decodeNode parses the RLP encoding of a trie node.
// 解码当前节点，不会递归
func decodeNode(hash, buf []byte) (node, error) {
	if len(buf) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	elems, _, err := rlp.SplitList(buf)
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}
	switch c, _ := rlp.CountValues(elems); c {
	case 2: // 扩展节点 或 叶子节点
		n, err := decodeShort(hash, elems)
		return n, wrapError(err, "short")
	case 17: // 分支节点
		n, err := decodeFull(hash, elems)
		return n, wrapError(err, "full")
	default:
		return nil, fmt.Errorf("invalid number of list elements: %v", c)
	}
}

// 解码当前节点，不会递归
func decodeShort(hash, elems []byte) (node, error) {
	kbuf, rest, err := rlp.SplitString(elems)
	if err != nil {
		return nil, err
	}

	// 设置 flag.hash 为 hash，dirty 为默认值 false
	flag := nodeFlag{hash: hash}
	key := compactToHex(kbuf)

	// 根据 key 是否有 terminator，分为 叶子节点 或 扩展节点
	if hasTerm(key) {
		// value node
		val, _, err := rlp.SplitString(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid value node: %v", err)
		}

		// 叶子节点，value 就是真实数据，类型为 valueNode
		return &shortNode{key, append(valueNode{}, val...), flag}, nil
	}

	// 否则，为 扩展节点，value 为到下一 分支节点 的引用
	r, _, err := decodeRef(rest)
	if err != nil {
		return nil, wrapError(err, "val")
	}
	return &shortNode{key, r, flag}, nil
}

func decodeFull(hash, elems []byte) (*fullNode, error) {
	n := &fullNode{flags: nodeFlag{hash: hash}}
	for i := 0; i < 16; i++ {
		cld, rest, err := decodeRef(elems)
		if err != nil {
			return n, wrapError(err, fmt.Sprintf("[%d]", i))
		}
		n.Children[i], elems = cld, rest
	}
	val, _, err := rlp.SplitString(elems)
	if err != nil {
		return n, err
	}
	if len(val) > 0 {
		// 如果存在，则一定是 valueNode 类型
		n.Children[16] = append(valueNode{}, val...)
	}
	return n, nil
}

const hashLen = len(common.Hash{})

// buf 可能是 hashNode，也可能是 rlp(key, value) < 32 的 shortNode 或 fullNode
func decodeRef(buf []byte) (node, []byte, error) {
	kind, val, rest, err := rlp.Split(buf)
	if err != nil {
		return nil, buf, err
	}
	switch {
	case kind == rlp.List:
		// 'embedded' node reference. The encoding must be smaller
		// than a hash in order to be valid.
		if size := len(buf) - len(rest); size > hashLen {
			err := fmt.Errorf("oversized embedded node (size is %d bytes, want size < %d)", size, hashLen)
			return nil, buf, err
		}

		// buf 可能是 shortNode 或 fullNode
		n, err := decodeNode(nil, buf)
		return n, rest, err
	case kind == rlp.String && len(val) == 0:
		// empty node
		return nil, rest, nil
	case kind == rlp.String && len(val) == 32:
		// val 确定是 hashNode
		return append(hashNode{}, val...), rest, nil
	default:
		return nil, nil, fmt.Errorf("invalid RLP string size %d (want 0 or 32)", len(val))
	}
}

// wraps a decoding error with information about the path to the
// invalid child node (for debugging encoding issues).
type decodeError struct {
	what  error
	stack []string
}

func wrapError(err error, ctx string) error {
	if err == nil {
		return nil
	}
	if decErr, ok := err.(*decodeError); ok {
		decErr.stack = append(decErr.stack, ctx)
		return decErr
	}
	return &decodeError{err, []string{ctx}}
}

func (err *decodeError) Error() string {
	return fmt.Sprintf("%v (decode path: %s)", err.what, strings.Join(err.stack, "<-"))
}
