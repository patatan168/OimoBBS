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
				if r.Status != Durable || log.State().After.PostCount != 4 {
					t.Fatal(r)
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
