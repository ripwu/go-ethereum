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

// Trie keys are dealt with in three distinct encodings:
//
// KEYBYTES encoding contains the actual key and nothing else. This encoding is the
// input to most API functions.
//
// HEX encoding contains one byte for each nibble of the key and an optional trailing
// 'terminator' byte of value 0x10 which indicates whether or not the node at the key
// contains a value. Hex key encoding is used for nodes loaded in memory because it's
// convenient to access.
//
// COMPACT encoding is defined by the Ethereum Yellow Paper (it's called "hex prefix
// encoding" there) and contains the bytes of the key and a flag. The high nibble of the
// first byte contains the flag; the lowest bit encoding the oddness of the length and
// the second-lowest encoding whether the node at the key is a value node. The low nibble
// of the first byte is zero in the case of an even number of nibbles and the first nibble
// in the case of an odd number. All remaining nibbles (now an even number) fit properly
// into the remaining bytes. Compact encoding is used for nodes stored on disk.

// 三种编码方式
// KEYBYTES 原生 [32]byte
// HEX 按 16 进制编码 (如果当前 key 有值，则结尾追加 terminator)
// COMPACT/HP 用于持久存储。Compact 的实际意思是两两字节又被作为半字节被编码为一字节，因此是压紧了 (忽略为了区分 terminator/odd 而引入的前半字节/一字节)

func hexToCompact(hex []byte) []byte {
	terminator := byte(0)

	// 以 \16 结尾，说明当前节点是叶子节点
	// 结尾来源：在 Trie.TryUpdate() 中会统一对 Key 调用 keybytesToHex() 转为 hex 编码并追加 \16 结尾
	// Compact 编码时需要记录是否以 \16 结尾的标志，这样从 Compact 解码为 Hex 时才能正确还原
	if hasTerm(hex) {
		terminator = 1
		hex = hex[:len(hex)-1]
	}

	buf := make([]byte, len(hex)/2+1)
	buf[0] = terminator << 5 // the flag byte

	// 根据黄皮书，要处理奇偶的原因，主要是为了让数据长度正好为偶数
	// 理解如下：如果不处理奇偶，编码时因为 nibbles 两辆组队，因此对于奇数长度的 hex，最后一个字符 nibble 无人配对，
	// 此时它只能在高 16 位，与低16位的 0 组成一个字节；解码时，无法确认低 16 位的 0，是原有数据还是 padding 数据
	if len(hex)&1 == 1 {
		buf[0] |= 1 << 4 // odd flag
		buf[0] |= hex[0] // first nibble is contained in the first byte
		hex = hex[1:]
	}

	decodeNibbles(hex, buf[1:])
	return buf
}

// hexToCompactInPlace places the compact key in input buffer, returning the length
// needed for the representation
func hexToCompactInPlace(hex []byte) int {
	var (
		hexLen    = len(hex) // length of the hex input
		firstByte = byte(0)
	)
	// Check if we have a terminator there
	if hexLen > 0 && hex[hexLen-1] == 16 {
		firstByte = 1 << 5
		hexLen-- // last part was the terminator, ignore that
	}
	var (
		binLen = hexLen/2 + 1
		ni     = 0 // index in hex
		bi     = 1 // index in bin (compact)
	)
	if hexLen&1 == 1 {
		firstByte |= 1 << 4 // odd flag
		firstByte |= hex[0] // first nibble is contained in the first byte
		ni++
	}
	for ; ni < hexLen; bi, ni = bi+1, ni+2 {
		hex[bi] = hex[ni]<<4 | hex[ni+1]
	}
	hex[0] = firstByte
	return binLen
}

func compactToHex(compact []byte) []byte {
	if len(compact) == 0 {
		return compact
	}

	// keybytesToHex 会添加尾部的 \16
	base := keybytesToHex(compact)

	// 这里根据情况，可能将尾部的 \16 删除
	// delete terminator flag
	if base[0] < 2 {
		base = base[:len(base)-1]
	}

	// 根据奇偶指向实际数据起始地址
	// apply odd flag
	chop := 2 - base[0]&1
	return base[chop:]
}

func keybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}

	// 注意这里末尾会补上 16 作为 terminator，用于区分 叶子节点 或 扩展节点
	// 参考 hasTerm() 的使用
	nibbles[l-1] = 16
	return nibbles
}

// hexToKeybytes turns hex nibbles into key bytes.
// This can only be used for keys of even length.
func hexToKeybytes(hex []byte) []byte {
	if hasTerm(hex) {
		hex = hex[:len(hex)-1]
	}
	if len(hex)&1 != 0 {
		panic("can't convert hex key of odd length")
	}
	key := make([]byte, len(hex)/2)
	decodeNibbles(hex, key)
	return key
}

func decodeNibbles(nibbles []byte, bytes []byte) {
	for bi, ni := 0, 0; ni < len(nibbles); bi, ni = bi+1, ni+2 {
		bytes[bi] = nibbles[ni]<<4 | nibbles[ni+1]
	}
}

// prefixLen returns the length of the common prefix of a and b.
func prefixLen(a, b []byte) int {
	var i, length = 0, len(a)
	if len(b) < length {
		length = len(b)
	}
	for ; i < length; i++ {
		if a[i] != b[i] {
			break
		}
	}
	return i
}

// hasTerm returns whether a hex key has the terminator flag.
func hasTerm(s []byte) bool {
	return len(s) > 0 && s[len(s)-1] == 16
}
