// 複数の既存圧縮blockを一度だけ同期し、保存形式・圧縮率・失敗時の停止を保つことを検査する。
package store

import (
	"bytes"
	"errors"
	"io"
	"oimobbs/internal/domain"
	"testing"
)

func TestWALSeriesKeepsBlocksAndDurableBoundary(t *testing.T) {
	var frames [][]byte
	for seq := 1; seq <= MaxCommitSeriesFrames; seq++ {
		raw, err := EncodeFrame(Frame{uint64(seq), []Record{{domain.NewID(), []byte(`{"value":"合成データだけを保存する繰り返し"}`), nil}}})
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, raw)
	}
	var expected []byte
	for i := 0; i < len(frames); i += MaxCommitFrames {
		b, err := EncodeWALBlock(frames[i : i+MaxCommitFrames])
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, b...)
	}
	for _, mode := range []string{"ok", "capacity", "short", "write", "sync", "invalid", "count"} {
		t.Run(mode, func(t *testing.T) {
			file := &batchSyncWriter{faultWriter: &faultWriter{}}
			writer := NewWriter(file)
			input := append([][]byte(nil), frames...)
			switch mode {
			case "short":
				file.short = true
			case "write":
				file.writeErr = io.ErrClosedPipe
			case "sync":
				file.syncErr = io.ErrClosedPipe
			case "invalid":
				input[len(input)-1] = []byte("invalid")
			case "count":
				input = append(input, frames[0])
			}
			before := func(size int64) error {
				if size != int64(len(expected)) {
					t.Fatal(size, len(expected))
				}
				if mode == "capacity" {
					return io.ErrShortBuffer
				}
				return nil
			}
			result := writer.CommitSeriesChecked(input, before)
			switch mode {
			case "ok":
				if result.Status != Durable || file.writes != 1 || file.syncs != 1 || !bytes.Equal(file.Bytes(), expected) {
					t.Fatal("blockの圧縮結果か耐久境界が変化した", result)
				}
				reader := bytes.NewReader(file.Bytes())
				total := 0
				for reader.Len() > 0 {
					block, _, err := ReadWALBlock(reader)
					if err != nil || len(block) != MaxCommitFrames {
						t.Fatal(err, len(block))
					}
					total += len(block)
				}
				if total != len(frames) {
					t.Fatal(total)
				}
			case "capacity", "invalid", "count":
				if result.Status != NotWritten || file.writes != 0 || file.syncs != 0 {
					t.Fatal("全件検査前に書込みを開始した", result)
				}
			default:
				if result.Status != Unknown || writer.CommitSeriesChecked(frames, nil).Status != Unknown || file.writes != 1 {
					t.Fatal("不明結果の後に再開した", result)
				}
			}
		})
	}
	file := &batchSyncWriter{faultWriter: &faultWriter{}}
	if r := NewWriter(file).CommitBatch(frames[:MaxCommitFrames+1]); r.Status != NotWritten || file.writes != 0 {
		t.Fatal("通常一括追記の64件上限が変化した", r)
	}
	reader := bytes.NewReader(expected[:len(expected)-1])
	for range 3 {
		if _, _, err := ReadWALBlock(reader); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := ReadWALBlock(reader); !errors.Is(err, ErrIncomplete) {
		t.Fatal("最後のblock切断を区別しなかった", err)
	}
	large, err := EncodeFrame(Frame{1, []Record{{domain.NewID(), []byte(`{"a":1}`), make([]byte, 3<<20)}}})
	if err != nil {
		t.Fatal(err)
	}
	if r := NewWriter(file).CommitSeriesChecked([][]byte{large, large, large}, nil); r.Status != NotWritten || file.writes != 0 {
		t.Fatal("列全体の8MiB上限を超えた", r)
	}
	c := &ControlLog{header: Header{Kind: 2}}
	if r := c.AppendSeriesChecked(frames, nil); r.Status != NotWritten {
		t.Fatal("非kind8の操作へ上限拡張を適用した", r)
	}
}
