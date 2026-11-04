// 暗号化済みの最大32packetを連続領域へ直接生成し、GSOへ渡すiovecを一本にまとめる。
package quicv1

import (
	"sync"
	"sync/atomic"
)

type cipherBlock struct {
	data []byte
	used int
	refs atomic.Int32
}

var cipherBlocks = sync.Pool{New: func() any { return &cipherBlock{data: make([]byte, 64<<10)} }}
var cipherPackets = sync.Pool{New: func() any { return new(packetBuffer) }}

// release はactorの構築権とsenderの各packetの所有権がすべてなくなってから領域を返す。
func (b *cipherBlock) release() {
	remaining := b.refs.Add(-1)
	if remaining < 0 {
		panic("QUIC cipher block reference underflow")
	}
	if remaining == 0 {
		b.used = 0
		cipherBlocks.Put(b)
	}
}

// packetStorage は再送用平文と別の領域を使い、各packetのappend可能範囲を固定する。
// 一度senderへ渡したblockには追記せず、同時送受信でも暗号文の早期再利用を防ぐ。
func (c *Conn) packetStorage(space, size int) *packetBuffer {
	if !c.batching || space != spaceApplication || size > 1452 || size <= 1100 && c.cipherBatch == nil {
		return sendBuffers.Get().(*packetBuffer)
	}
	if c.cipherBatch == nil {
		c.cipherBatch = cipherBlocks.Get().(*cipherBlock)
		c.cipherBatch.refs.Store(1)
	}
	block := c.cipherBatch
	if size > len(block.data)-block.used {
		return sendBuffers.Get().(*packetBuffer)
	}
	b := cipherPackets.Get().(*packetBuffer)
	b.owner, b.offset = block, block.used
	b.data = block.data[block.used : block.used+size : block.used+size]
	block.used += size
	block.refs.Add(1)
	return b
}

// contiguousCiphertext は所有者とoffsetを照合し、連続した暗号文だけを一つのI/Oへまとめる。
// 異なるblockや通常bufferが混ざれば既存のscatter送信へ戻す。
func contiguousCiphertext(packets []*packetBuffer, count int) []byte {
	if len(packets) < count || count == 0 || packets[0].owner == nil {
		return nil
	}
	owner, start := packets[0].owner, packets[0].offset
	end := start
	for _, packet := range packets[:count] {
		if packet.owner != owner || packet.offset != end {
			return nil
		}
		end += len(packet.data)
	}
	return owner.data[start:end:end]
}
