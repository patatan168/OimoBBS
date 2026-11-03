// 一括検算と逐次検算の同値性、元状態の隔離、失敗後の候補破棄を検査する。
package domain

import (
	"encoding/hex"
	"encoding/json"
	"oimobbs/internal/textcodec"
	"os"
	"reflect"
	"testing"
)

// batchFixture は保存fixtureから同じ本文の連続返信を作る。
func batchFixture(t testing.TB, count int) (*Thread, [][]byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	dat, err := hex.DecodeString(fixture.DAT)
	if err != nil {
		t.Fatal(err)
	}
	op, err := ParseOperation(fixture.Operation)
	if err != nil {
		t.Fatal(err)
	}
	old, err := Apply(nil, op, dat)
	if err != nil {
		t.Fatal(err)
	}
	var create Create
	if err = json.Unmarshal(op.Payload, &create); err != nil {
		t.Fatal(err)
	}
	rows := make([][]byte, count)
	for i := range rows {
		number := uint32(i + 2)
		post := create.Posts[0]
		post.Number = number
		op.Type = "append"
		op.Revision = U64(number)
		op.Versions.Thread = 1
		op.After.PostCount = number
		op.After.UserCount = number
		op.After.DATBytes = U64(len(dat)) * U64(number)
		op.Dedup.PostNumber = number
		op.Payload, err = MarshalAppend(Append{Posts: []Post{post}})
		if err == nil {
			rows[i], err = MarshalOperation(op)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return old, rows, dat
}

func TestThreadBatchIsolation(t *testing.T) {
	old, rows, dat := batchFixture(t, 16)
	before, _ := json.Marshal(old)
	batch := NewThreadBatch(old)
	want := old
	for _, raw := range rows {
		var err error
		want, _, err = ApplyEncoded(want, raw, dat)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = batch.ApplyEncoded(raw, dat); err != nil {
			t.Fatal(err)
		}
	}
	got, err := batch.Finish()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("逐次検算と不一致", err)
	}
	got.Posts[0].Body = "変更"
	got.Lines[0] = nil
	after, _ := json.Marshal(old)
	if string(before) != string(after) {
		t.Fatal("元状態へ候補の変更が波及した")
	}
	if _, err = batch.Finish(); err == nil {
		t.Fatal("候補を再公開した")
	}
	if _, err = batch.ApplyEncoded(rows[0], dat); err == nil {
		t.Fatal("公開後に候補を更新した")
	}
}

func TestThreadBatchRejectsPartialResult(t *testing.T) {
	for _, bad := range []string{"syntax", "after", "dat", "revision"} {
		t.Run(bad, func(t *testing.T) {
			old, rows, dat := batchFixture(t, 8)
			before, _ := json.Marshal(old)
			batch := NewThreadBatch(old)
			for _, raw := range rows[:7] {
				if _, err := batch.ApplyEncoded(raw, dat); err != nil {
					t.Fatal(err)
				}
			}
			raw, body := rows[7], dat
			switch bad {
			case "syntax":
				raw = append(append([]byte(nil), raw...), '!')
			case "dat":
				body = []byte("不正")
			default:
				op, _ := ParseOperation(raw)
				if bad == "after" {
					op.After.DATBytes++
				} else {
					op.Revision++
				}
				raw, _ = MarshalOperation(op)
			}
			if _, err := batch.ApplyEncoded(raw, body); err == nil {
				t.Fatal("不正な末尾を受理した")
			}
			if got, err := batch.Finish(); err == nil || got != nil {
				t.Fatal("失敗した群の一部を公開した")
			}
			if _, err := batch.ApplyEncoded(rows[7], dat); err == nil {
				t.Fatal("失敗後に再開した")
			}
			after, _ := json.Marshal(old)
			if string(before) != string(after) {
				t.Fatal("失敗で元状態が変化した")
			}
		})
	}
	if _, err := NewThreadBatch(nil).Finish(); err == nil {
		t.Fatal("空の候補を公開した")
	}
}

func TestThreadBatchMixedTransitions(t *testing.T) {
	old, rows, dat := batchFixture(t, 1)
	before, _ := json.Marshal(old)
	batch := NewThreadBatch(old)
	want, op, err := ApplyEncoded(old, rows[0], dat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = batch.ApplyEncoded(rows[0], dat); err != nil {
		t.Fatal(err)
	}
	id, key, hash := NewID(), uint32(1), Hash{}
	actor := Actor{Kind: "admin", ID: &id, Reason: "moderation", Request: &hash, Idempotency: &hash, KeyID: &key}
	for _, kind := range []string{"redact", "move_link", "update_policy", "archive", "hide"} {
		next := Operation{Type: kind, Revision: want.Revision + 1, Committed: op.Committed, Versions: Versions{Site: 1, Board: 1, Thread: want.Policy.Version}, Actor: actor, After: want.After}
		var payload any
		var body []byte
		switch kind {
		case "redact":
			post := want.Posts[0]
			post.Visibility, post.Name, post.Mail, post.Body, post.Identity = "aboon", "あぼーん", "", "あぼーん", Identity{DateText: "あぼーん"}
			body, err = textcodec.Encode("あぼーん<><>あぼーん<>あぼーん<>example\n", false)
			if err != nil {
				t.Fatal(err)
			}
			post.DATLength = uint32(len(body))
			payload = Redact{Posts: []Post{post}}
			next.After.DATBytes = next.After.DATBytes - U64(len(want.Lines[0])) + U64(len(body))
			next.After.DATGeneration++
			next.After.LegacyRangeDisabled = true
		case "move_link":
			payload = Move{Target: "https://example.invalid/thread"}
		case "update_policy":
			policy := want.Policy
			policy.Version++
			payload = UpdatePolicy{Policy: policy}
		case "archive":
			reason := "manual"
			payload = Archive{Reason: reason}
			next.After.State, next.After.EndReason = "archived", &reason
		case "hide":
			payload = Hide{DeletionID: NewID()}
			next.After.State = "hidden"
		}
		next.Payload, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := MarshalOperation(next)
		if err != nil {
			t.Fatal(err)
		}
		want, _, err = ApplyEncoded(want, raw, body)
		if err != nil {
			t.Fatal(kind, err)
		}
		if _, err = batch.ApplyEncoded(raw, body); err != nil {
			t.Fatal(kind, err)
		}
	}
	got, err := batch.Finish()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("管理操作の検算と不一致", err)
	}
	after, _ := json.Marshal(old)
	if string(before) != string(after) {
		t.Fatal("管理操作で元状態が変化した")
	}
}

func BenchmarkThreadBatch(b *testing.B) {
	old, rows, dat := batchFixture(b, 563)
	for _, raw := range rows[:499] {
		var err error
		old, _, err = ApplyEncoded(old, raw, dat)
		if err != nil {
			b.Fatal(err)
		}
	}
	rows = rows[499:]
	for _, batched := range []bool{false, true} {
		name := "sequential"
		if batched {
			name = "batch"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if batched {
					batch := NewThreadBatch(old)
					for _, raw := range rows {
						if _, err := batch.ApplyEncoded(raw, dat); err != nil {
							b.Fatal(err)
						}
					}
					if _, err := batch.Finish(); err != nil {
						b.Fatal(err)
					}
				} else {
					state := old
					for _, raw := range rows {
						var err error
						state, _, err = ApplyEncoded(state, raw, dat)
						if err != nil {
							b.Fatal(err)
						}
					}
				}
			}
		})
	}
}
