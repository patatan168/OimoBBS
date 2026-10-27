// 共有WALの耐久化後だけ公開し、個別本文へのまとめ書きと中断時の再実行を検査する。
package store

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type groupReadFault struct{ threadGroupFile }

func (f groupReadFault) ReadAt([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestThreadGroupBodyReservationLifecycle(t *testing.T) {
	g, batches, create := newThreadGroupTest(t)
	var held uint64
	var releases int
	g.reserveBodies = func(size uint64) (func(), error) {
		held += size
		return func() { held -= size; releases++ }, nil
	}
	if result := g.Commit(batches); result.Status != Durable || held == 0 || releases != 0 {
		t.Fatal("本文反映前に容量予約を解放した", result, held, releases)
	}
	if err := g.Checkpoint(); err != nil || held != 0 || releases != 1 {
		t.Fatal("耐久化後に容量予約を解放しなかった", err, held, releases)
	}
	for i := range batches {
		batches[i].Frames = [][]byte{packReply(t, create, 3)}
	}
	if result := g.Commit(batches); result.Status != Durable {
		t.Fatal(result)
	}
	batches[1].Log.writer.file = &faultWriter{short: true}
	if err := g.Checkpoint(); err == nil || held == 0 || releases != 1 {
		t.Fatal("本文反映失敗で容量予約を解放した", err, held, releases)
	}
}

func TestThreadGroupBodyReservationRejectsBeforeWrite(t *testing.T) {
	g, batches, _ := newThreadGroupTest(t)
	want := errors.New("capacity")
	g.reserveBodies = func(uint64) (func(), error) { return nil, want }
	if result := g.Commit(batches); result.Status != NotWritten || !errors.Is(result.Err, want) || g.Stats().Writes != 0 || g.file != nil {
		t.Fatal("容量不足で共有WALを書き始めた", result, g.Stats())
	}
}

func TestThreadGroupBodyReadFailureKeepsReplay(t *testing.T) {
	g, batches, _ := newThreadGroupTest(t)
	if result := g.Commit(batches); result.Status != Durable {
		t.Fatal(result)
	}
	g.file = groupReadFault{g.file}
	if err := g.Checkpoint(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("共有WALの読取り失敗を無視した", err)
	}
	if _, err := os.Stat(filepath.Join(g.parent, ThreadGroupFile)); err != nil || !g.stopped {
		t.Fatal("読取り失敗後の復旧元を失った", err)
	}
}

func TestThreadGroupBodyReadCorruptionKeepsReplay(t *testing.T) {
	g, batches, _ := newThreadGroupTest(t)
	if result := g.Commit(batches); result.Status != Durable {
		t.Fatal(result)
	}
	part := g.pending[batches[0].Log][0]
	var raw [1]byte
	if _, err := g.file.ReadAt(raw[:], part.offset); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(g.parent, ThreadGroupFile), os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	_, err = f.WriteAt(raw[:], part.offset)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Checkpoint(); !errors.Is(err, ErrCorrupt) {
		t.Fatal("再読取りした破損blockを採用した", err)
	}
	if _, err := os.Stat(filepath.Join(g.parent, ThreadGroupFile)); err != nil || !g.stopped {
		t.Fatal("再読取り破損で共有WALを捨てた", err)
	}
}

func TestThreadGroupCoalescesBodyWrites(t *testing.T) {
	g, batches, create := newThreadGroupTest(t)
	prefix := make([][]byte, len(batches))
	for i, batch := range batches {
		prefix[i], _ = os.ReadFile(batch.Log.file.Name())
	}
	for seq := uint32(2); seq <= 9; seq++ {
		for i := range batches {
			batches[i].Frames = [][]byte{packReply(t, create, seq)}
		}
		if result := g.Commit(batches); result.Status != Durable {
			t.Fatal(result)
		}
	}
	for i, batch := range batches {
		got, err := os.ReadFile(batch.Log.file.Name())
		if err != nil || !bytes.Equal(got, prefix[i]) || batch.Log.CommitStats().Writes != 1 {
			t.Fatal("checkpoint前に個別本文へ書き込んだ", err)
		}
		if batch.Log.State().Revision != 9 {
			t.Fatal("共有WALの耐久済み状態を失った")
		}
	}
	if err := g.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	for _, batch := range batches {
		if batch.Log.CommitStats().Writes != 2 {
			t.Fatal("小さい追記を一回へまとめていない", batch.Log.CommitStats())
		}
		reopened, err := OpenThread(g.parent, g.owner, batch.Log.header.Key)
		if err != nil {
			t.Fatal(err)
		}
		if reopened.State().Revision != 9 {
			t.Fatal("まとめ書きで本文を失った")
		}
		reopened.Close()
	}
}

// TestThreadGroupCheckpointInterruptedReplay は途中まで書いた本文を共有WALから冪等に復元する。
func TestThreadGroupCheckpointInterruptedReplay(t *testing.T) {
	g, batches, create := newThreadGroupTest(t)
	var frames [][]byte
	for seq := uint32(2); seq <= 9; seq++ {
		frame := packReply(t, create, seq)
		frames = append(frames, frame)
		for i := range batches {
			batches[i].Frames = [][]byte{frame}
		}
		if result := g.Commit(batches); result.Status != Durable {
			t.Fatal(result)
		}
	}
	batches[1].Log.writer.file = groupFaultFile{File: batches[1].Log.file, short: true}
	if err := g.Checkpoint(); err == nil {
		t.Fatal("途中書込みを成功扱いした")
	}
	g.file.Close()
	g.file = nil
	for _, batch := range batches {
		batch.Log.file.Close()
	}
	if err := RecoverThreadCommitGroup(g.parent, g.owner, func(_ uint64, raw []byte) error {
		for _, frame := range frames {
			if bytes.Equal(frame, raw) {
				return nil
			}
		}
		return ErrCorrupt
	}); err != nil {
		t.Fatal(err)
	}
	for _, batch := range batches {
		log, err := OpenThread(g.parent, g.owner, batch.Log.header.Key)
		if err != nil {
			t.Fatal(err)
		}
		if log.State().Revision != 9 {
			t.Fatal("部分反映後に耐久済み投稿を失った")
		}
		log.Close()
	}
}

// TestThreadGroupBodyBufferBoundary は64KiBを跨ぐ連結も既存WAL blockとbyte一致させる。
func TestThreadGroupBodyBufferBoundary(t *testing.T) {
	g, batches, create := newThreadGroupTest(t)
	batches = batches[:1]
	log := batches[0].Log
	want, err := os.ReadFile(log.file.Name())
	if err != nil {
		t.Fatal(err)
	}
	var seq uint32 = 2
	for range 63 {
		var frames [][]byte
		for range 8 {
			frames = append(frames, packReply(t, create, seq))
			seq++
		}
		batches[0].Frames = frames
		block, err := EncodeWALBlock(frames)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, block...)
		if result := g.Commit(batches); result.Status != Durable {
			t.Fatal(result)
		}
	}
	if len(want) < 64<<10 {
		t.Fatal("buffer境界を跨がないfixture", len(want))
	}
	if err := g.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(log.file.Name())
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("buffer境界で既存WAL形式を変更した", err)
	}
}

func TestThreadGroupBodyFailureKeepsReplay(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "short"}[short], func(t *testing.T) {
			g, batches, _ := newThreadGroupTest(t)
			if result := g.Commit(batches); result.Status != Durable {
				t.Fatal(result)
			}
			batches[1].Log.writer.file = &faultWriter{short: short, writeErr: errors.New("body failure")}
			if err := g.Checkpoint(); err == nil {
				t.Fatal("本文反映の失敗を無視した")
			}
			if _, err := os.Stat(filepath.Join(g.parent, ThreadGroupFile)); err != nil {
				t.Fatal("復旧元を削除した", err)
			}
			if result := g.Commit(batches); result.Status != Unknown {
				t.Fatal("本文反映失敗後に保存を再開した", result)
			}
		})
	}
}
