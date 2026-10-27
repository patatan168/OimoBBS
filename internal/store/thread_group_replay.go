// 署名照合済みの本文blockと一致するprefixを保持し、復旧途中の再停止でも進捗を引き継ぐ。
package store

import (
	"bytes"
	"errors"
	"io"
)

// replayThreadGroupPlans は全対象を再確認してから、不一致以降だけ修復する。
// 一致済みのfileもSyncし、全Sync/Close成功後だけ再実行WALを削除する。
func replayThreadGroupPlans(parent string, plans []*threadGroupReplay) (err error) {
	defer func() { err = errors.Join(err, closeThreadGroupReplays(plans)) }()
	scratch := make([]byte, 64<<10)
	for _, plan := range plans {
		plan.inspectReplayPrefix(scratch)
	}
	for _, plan := range plans {
		if err = plan.replayMissingBlocks(); err != nil {
			return err
		}
	}
	if err = closeThreadGroupReplays(plans); err != nil {
		return err
	}
	return removeThreadGroup(parent)
}

// inspectReplayPrefix は必須prefix検証時のfile長から、一致する完全blockだけを保持する。
// 未checkpoint末尾の読込失敗は検証済みWALから修復する。必須prefixの検査はopenで済ませる。
func (p *threadGroupReplay) inspectReplayPrefix(scratch []byte) {
	p.matched = 0
	offset := p.start
	for _, block := range p.blocks {
		if p.size-offset < int64(len(block)) {
			return
		}
		same, err := equalReplayBytes(p.file, offset, block, scratch)
		if err != nil || !same {
			return
		}
		p.matched++
		offset += int64(len(block))
	}
}

// equalReplayBytes は最大64KiBの作業領域を再利用し、比較対象の全byteを読む。
func equalReplayBytes(file io.ReaderAt, offset int64, want, scratch []byte) (bool, error) {
	if len(scratch) == 0 {
		return false, ErrCorrupt
	}
	for len(want) > 0 {
		size := min(len(want), len(scratch))
		n, err := file.ReadAt(scratch[:size], offset)
		if err != nil {
			return false, err
		}
		if n != size {
			return false, io.ErrUnexpectedEOF
		}
		if !bytes.Equal(scratch[:size], want[:size]) {
			return false, nil
		}
		offset += int64(size)
		want = want[size:]
	}
	return true, nil
}

// replayMissingBlocks は一致済みprefixを切り詰めず、残りを修復する。書込ゼロでもSyncは省略しない。
func (p *threadGroupReplay) replayMissingBlocks() error {
	if p.matched < len(p.blocks) {
		offset := p.start
		for _, block := range p.blocks[:p.matched] {
			offset += int64(len(block))
		}
		if err := p.file.Truncate(offset); err != nil {
			return err
		}
		if _, err := p.file.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		for _, block := range p.blocks[p.matched:] {
			if err := writeFull(p.file, block); err != nil {
				return err
			}
		}
	}
	return p.file.Sync()
}

// closeThreadGroupReplays は全fileを一度ずつ閉じ、一つのClose失敗でも復旧WALを保持できるよう返す。
func closeThreadGroupReplays(plans []*threadGroupReplay) (err error) {
	for _, plan := range plans {
		if plan.file != nil {
			file := plan.file
			plan.file = nil
			err = errors.Join(err, file.Close())
		}
	}
	return err
}
