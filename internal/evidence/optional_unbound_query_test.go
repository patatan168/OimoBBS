// 受付前拒否/閲覧を受理操作の記録から分け、板不明・別板・期限切れを返さない。
package evidence

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOptionalUnboundQueryBoardSelectionExpiryAndProjection(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	site, board := domain.NewID(), domain.NewID()
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now()
	r := optionalFixture()
	r.Site, r.Board = site, &board
	r.Received = domain.Time(now.Add(-time.Hour).UnixNano())
	r.Finished, r.Until = r.Received+100, r.Received+domain.Time(OptionalRetention)
	if e = s.Write(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"view", "accepted", "unresolved", "other_board"} {
		v := r
		v.ID = domain.NewID()
		switch mode {
		case "view":
			v.Kind, v.Route, v.Outcome, v.Status = "access", "board", "served", 200
		case "accepted":
			id := domain.NewID()
			v.Operation, v.Outcome = &id, "accepted"
		case "unresolved":
			v.Board = nil
		case "other_board":
			id := domain.NewID()
			v.Board = &id
		}
		if e = s.Write(context.Background(), v); e != nil {
			t.Fatal(e)
		}
	}
	scope := OptionalQueryScope{Board: board, From: r.Received, To: r.Received + 1000}
	rows, e := s.QueryUnbound(context.Background(), scope, now)
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	plain, _ := json.Marshal(rows[0].ProjectUnbound(false))
	if strings.Contains(string(plain), r.Peer.IP) || strings.Contains(string(plain), "user_agent") {
		t.Fatal("unselected connection leaked", string(plain))
	}
	selected, _ := json.Marshal(rows[0].ProjectUnbound(true))
	if !strings.Contains(string(selected), r.Peer.IP) {
		t.Fatal(string(selected))
	}
	scope.Records = []domain.ID{r.ID}
	rows, e = s.QueryUnbound(context.Background(), scope, now)
	if e != nil || len(rows) != 1 || rows[0].Record.ID != r.ID {
		t.Fatal(rows, e)
	}
	rows, e = s.QueryUnbound(context.Background(), scope, now.Add(8*24*time.Hour))
	if e != nil || len(rows) != 0 {
		t.Fatal("expired observation returned", rows, e)
	}
	if _, e = s.Query(context.Background(), scope, now); !errors.Is(e, ErrOptionalQueryScope) {
		t.Fatal("ordinary scope broadened", e)
	}
}

// 日付をまたぐ日本時間とナノ秒を維持し、原記録の日時を表示のために変更しない。
func TestOptionalUnboundProjectionUTCJSTAcrossMidnight(t *testing.T) {
	received := time.Date(2026, 10, 5, 15, 1, 2, 123456789, time.UTC)
	r := OptionalEvidence{Record: OptionalRecord{Received: domain.Time(received.UnixNano()), Finished: domain.Time(received.Add(time.Second).UnixNano())}}
	before := r.Record
	data := r.ProjectUnbound(false)
	for name, want := range map[string]string{
		"received_at_utc": "2026-10-05T15:01:02.123456789Z",
		"received_at_jst": "2026-10-06T00:01:02.123456789+09:00",
		"finished_at_utc": "2026-10-05T15:01:03.123456789Z",
		"finished_at_jst": "2026-10-06T00:01:03.123456789+09:00",
	} {
		if data[name] != want {
			t.Fatalf("%s: got %v, want %s", name, data[name], want)
		}
	}
	if r.Record.Received != before.Received || r.Record.Finished != before.Finished {
		t.Fatal("projection changed source timestamps")
	}
}

func TestOptionalUnboundProjectionPreservesResponseFailure(t *testing.T) {
	r := optionalFixture()
	r.Status, r.Outcome, r.WriteFailed, r.Canceled, r.Bytes = 0, "interrupted", true, true, 17
	if e := r.Validate(); e != nil {
		t.Fatal(e)
	}
	before := r
	out := (OptionalEvidence{Record: r}).ProjectUnbound(false)
	assertUnboundResponseFailure(t, out)
	if r != before {
		t.Fatal("source observation mutated")
	}
	r.Status = 503
	out = (OptionalEvidence{Record: r}).ProjectUnbound(false)
	if out["http_status"] != 503 || len(out["missing_fields"].([]MissingField)) != 0 {
		t.Fatal("observed status lost")
	}
}

func assertUnboundResponseFailure(t *testing.T, out map[string]any) {
	t.Helper()
	if out["http_status"] != nil || out["write_failed"] != true || out["request_canceled"] != true || out["written_bytes"] != domain.U64(17) || out["finish_stage"] != "handler_return" {
		t.Fatal("unknown/failed response reported as success", out)
	}
	missing := out["missing_fields"].([]MissingField)
	if len(missing) != 1 || missing[0] != (MissingField{Field: "http_status", Reason: "not_observed"}) {
		t.Fatal("unknown status not explained", missing)
	}
}

// 時計逆行時も壁時計の差で補完せず、保存された単調経過を照会する。
func TestOptionalUnboundProjectionPreservesMonotonicElapsed(t *testing.T) {
	r := optionalFixture()
	r.Finished, r.Elapsed = r.Received-1, 987654321
	if e := r.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, connection := range []bool{false, true} {
		out := (OptionalEvidence{Record: r}).ProjectUnbound(connection)
		if out["monotonic_elapsed_ns"] != r.Elapsed || out["finished_at_ns"] != r.Finished || out["received_at_ns"] != r.Received {
			t.Fatal("stored clock observations changed", out)
		}
	}
	r.Elapsed = 0
	if out := (OptionalEvidence{Record: r}).ProjectUnbound(false); out["monotonic_elapsed_ns"] != domain.U64(0) {
		t.Fatal("zero elapsed replaced", out)
	}
}
