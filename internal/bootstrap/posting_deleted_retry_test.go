// 失効・時計逆行・再起動後も、元期限内の要求IDでスレッドを再作成しない。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestExpiredCreateRequestCannotRecreate(t *testing.T) {
	for _, mode := range []string{"explicit", "implicit"} {
		t.Run(mode, func(t *testing.T) {
			cfg, repo, board := postingRepositoryFixture(t)
			defer func() { _ = repo.Close() }()
			if e := repo.EnableThreadRetention(context.Background()); e != nil {
				t.Fatal(e)
			}
			raw := persistentFrame(t)
			f, _, e := store.ReadFrame(bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			op, e := domain.ParseOperation(f.Records[0].JSON)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "implicit" {
				op.Dedup.Mode, op.Dedup.RequestID = mode, nil
				op.Dedup.Expires = op.Committed + domain.Time(30*time.Second)
				f.Records[0].JSON, _ = json.Marshal(op)
				raw, e = store.EncodeFrame(f)
				if e != nil {
					t.Fatal(e)
				}
			}
			capture := []byte(`{"fixture":true}`)
			created := repo.Post(context.Background(), board.ID, 0, raw, capture)
			if created.Status != store.Durable {
				t.Fatal(created)
			}
			snapshot, e := repo.Thread(context.Background(), board.ID, created.ThreadKey)
			if e != nil || snapshot == nil {
				t.Fatal(snapshot, e)
			}
			b := repo.posting[board.ID]
			_, e = b.worker.Submit(context.Background(), func() (any, error) {
				b.clock = func() time.Time { return time.Unix(0, int64(snapshot.Expires)) }
				_, e := b.scanExpiry(true)
				b.clock = time.Now
				return nil, e
			})
			if e != nil {
				t.Fatal(e)
			}
			assertRejected := func() {
				t.Helper()
				before := repo.posting[board.ID].control.State().Seq
				got := repo.Post(context.Background(), board.ID, 0, raw, capture)
				if got.Status != store.NotWritten || got.Err == nil || got.ThreadKey != created.ThreadKey || !got.Duplicate {
					t.Fatal("expired request recreated/succeeded", got)
				}
				if repo.posting[board.ID].control.State().Seq != before {
					t.Fatal("rejected retry reserved another key")
				}
			}
			assertRejected()
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postingCaptureFixture)
			if e != nil {
				t.Fatal(e)
			}
			assertRejected()
		})
	}
}
