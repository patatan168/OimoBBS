// 耐久済み共有WALから固定長bufferで本文へまとめ書きし、二重書込の細分化を避ける。
package store

import (
	"hash/crc32"
	"io"
	"slices"
)

// threadGroupRange は共有WAL内の既存blockの位置だけを保持する。本文のコピーは持たない。
type threadGroupRange struct {
	offset int64
	size   int
	crc    uint32
}

// flushBodies は同じ本文のblockを順に連結して反映する。最大64KiBを一度だけ確保し、
// 全本文のSyncが終わるまで共有WALを残す。失敗後は呼出元が所有者を停止する。
func (g *ThreadCommitGroup) flushBodies() error {
	logs := make([]*ThreadLog, 0, len(g.pending))
	for log := range g.pending {
		logs = append(logs, log)
	}
	slices.SortFunc(logs, func(a, b *ThreadLog) int {
		if a.header.Key < b.header.Key {
			return -1
		}
		if a.header.Key > b.header.Key {
			return 1
		}
		return 0
	})
	buffer := make([]byte, 64<<10)
	for _, log := range logs {
		if err := g.flushBody(log, buffer); err != nil {
			return err
		}
	}
	return nil
}

// flushBody は共有WALから借りた範囲を入力順に読み、独立本文のfile位置だけを進める。
// logical end/stateはCommitで確定済みなので、ここでは更新しない。
func (g *ThreadCommitGroup) flushBody(log *ThreadLog, buffer []byte) error {
	w := log.writer
	w.mu.Lock()
	defer w.mu.Unlock()
	used := 0
	for _, part := range g.pending[log] {
		var crc uint32
		for part.size > 0 {
			size := min(part.size, len(buffer)-used)
			if _, err := g.file.ReadAt(buffer[used:used+size], part.offset); err != nil {
				return err
			}
			crc = crc32.Update(crc, crcTable, buffer[used:used+size])
			used += size
			part.offset += int64(size)
			part.size -= size
			if used == len(buffer) {
				if err := writeThreadGroupBody(w, buffer[:used]); err != nil {
					return err
				}
				used = 0
			}
		}
		if crc != part.crc {
			return ErrCorrupt
		}
	}
	if used > 0 {
		return writeThreadGroupBody(w, buffer[:used])
	}
	return nil
}

// writeThreadGroupBody は短い書込みも保存失敗とし、実際の書込件数とbyte数だけを集計する。
func writeThreadGroupBody(w *Writer, raw []byte) error {
	w.stats.Writes++
	n, err := w.file.Write(raw)
	if n > 0 {
		w.stats.Bytes += uint64(n)
	}
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}
