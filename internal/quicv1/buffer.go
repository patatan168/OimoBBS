// ACK・損失・PTOをまたぐ平文bufferの所有権を接続actorだけで管理する。
package quicv1

import "sync"

type sendBlock struct {
	data   []byte
	refs   int
	single []*sendBlock
	large  bool
}

func makeSendBlock(size int, large bool) *sendBlock {
	b := &sendBlock{data: make([]byte, 0, size), large: large}
	b.single = []*sendBlock{b}
	return b
}

var smallBlocks = sync.Pool{New: func() any { return makeSendBlock(4352, false) }}
var largeBlocks = sync.Pool{New: func() any { return makeSendBlock(70<<10, true) }}

func getSendBlock(size int) *sendBlock {
	var b *sendBlock
	if size <= 4352 {
		b = smallBlocks.Get().(*sendBlock)
	} else {
		b = largeBlocks.Get().(*sendBlock)
	}
	b.refs = 1
	b.data = b.data[:size]
	return b
}
func (b *sendBlock) release() {
	b.refs--
	if b.refs < 0 {
		panic("QUIC buffer reference underflow")
	}
	if b.refs == 0 {
		if b.large {
			largeBlocks.Put(b)
		} else {
			smallBlocks.Put(b)
		}
	}
}
func releaseRefs(refs []*sendBlock) {
	for _, b := range refs {
		b.release()
	}
}
func retainRefs(refs []*sendBlock) {
	for _, b := range refs {
		b.refs++
	}
}
