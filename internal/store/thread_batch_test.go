// 一括返信の全件事前検査と、書込/同期失敗で候補を交換しないことを検査する。
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"testing"
)

func TestThreadBatchFailureAndRecovery(t *testing.T) {
	for _, failure := range []string{"none", "invalid", "short", "write", "sync"} {
		t.Run(failure, func(t *testing.T) {
			owner, create := fixtureCreate(t)
			root := privateTemp(t)
			log, e := CreateThread(root, owner, 1, create)
			if e != nil {
				t.Fatal(e)
			}
			defer log.Close()
			old := log.State()
			initial, ok := log.FirstRecord()
			if !ok {
				t.Fatal("initial")
			}
			if _, ok := log.DedupRecord(initial.Dedup, initial.Committed); !ok {
				t.Fatal("保存済み再送の索引作成に失敗")
			}
			f, _, _ := ReadFrame(bytes.NewReader(create))
			op, e := domain.ParseOperation(f.Records[0].JSON)
			if e != nil {
				t.Fatal(e)
			}
			var payload domain.Create
			if e = json.Unmarshal(op.Payload, &payload); e != nil {
				t.Fatal(e)
			}
			var frames [][]byte
			for seq := uint32(2); seq <= 4; seq++ {
				post := payload.Posts[0]
				post.Number = seq
				op.Type = "append"
				op.Revision = domain.U64(seq)
				op.Versions.Thread = 1
				op.After.PostCount = seq
				op.After.UserCount = seq
				op.After.DATBytes = domain.U64(len(f.Records[0].DAT)) * domain.U64(seq)
				op.Dedup.PostNumber = seq
				op.Dedup.Request[0] = byte(seq)
				(*op.Dedup.RequestID)[0] = byte(seq)
				op.Payload, _ = json.Marshal(domain.Append{Posts: []domain.Post{post}})
				raw, _ := json.Marshal(op)
				frame, e := EncodeFrame(Frame{uint64(seq), []Record{{domain.NewID(), raw, f.Records[0].DAT}}})
				if e != nil {
					t.Fatal(e)
				}
				frames = append(frames, frame)
			}
			mock := &batchSyncWriter{faultWriter: &faultWriter{}}
			if failure == "short" {
				mock.short = true
			}
			if failure == "write" {
				mock.writeErr = errors.New("write")
			}
			if failure == "sync" {
				mock.syncErr = errors.New("sync")
			}
			if failure != "none" {
				log.writer = NewWriter(mock)
			}
			if failure == "invalid" {
				frames[2] = create
			}
			r := log.AppendBatch(frames)
			if old.After.PostCount != 1 {
				t.Fatal("old state changed")
			}
			if failure == "none" {
				saved, _ := json.Marshal(log.State())
				for _, frame := range frames {
					for i := range frame {
						frame[i] = 0
					}
				}
				actual, _ := json.Marshal(log.State())
				if !bytes.Equal(saved, actual) {
					t.Fatal("追記元bufferの再利用が確定状態へ波及した")
				}
				if r.Status != Durable || log.State().After.PostCount != 4 {
					t.Fatal(r)
				}
				for _, record := range log.Records() {
					if found, ok := log.DedupRecord(record.Dedup, record.Committed); !ok || found.ID != record.ID {
						t.Fatal("追記後の再送索引を更新しなかった")
					}
				}
				_ = log.Close()
				reopened, e := OpenThread(root, owner, 1)
				if e != nil {
					t.Fatal(e)
				}
				defer reopened.Close()
				if reopened.State().After.PostCount != 4 {
					t.Fatal("recovery lost batch")
				}
			} else {
				want := Unknown
				if failure == "invalid" {
					want = NotWritten
				}
				if r.Status != want || log.State() != old {
					t.Fatal(r, want)
				}
				if failure == "invalid" && log.CommitStats().Writes != 0 {
					t.Fatal("invalid tail wrote earlier frames")
				}
				if failure == "sync" && mock.syncs != 1 {
					t.Fatal(mock.syncs)
				}
				if want == Unknown && log.AppendBatch(frames).Status != Unknown {
					t.Fatal("unknown writer restarted")
				}
			}
		})
	}
}
