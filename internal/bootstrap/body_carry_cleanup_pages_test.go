// 実投稿から128行を超えるcarryを作り、周期保守の分割削除と再起動を検査する。
package bootstrap

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestBodyCarryCleanupMaintenancePagesAndRestart(t *testing.T) {
	cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, false)
	b := r.posting[owner]
	frame, at := expiredRequiredFrame(t)
	for number := uint32(2); number <= 66; number++ {
		raw := expiredCarryReply(t, frame, at, number)
		value, e := b.worker.Submit(t.Context(), func() (any, error) {
			b.clock = func() time.Time { return time.Unix(0, int64(at)) }
			defer func() { b.clock = time.Now }()
			return b.post(key, raw, []byte(`{"fixture":true}`)), nil
		})
		if e != nil || value.(RepositoryPostingResult).Status != store.Durable {
			t.Fatal(number, value, e)
		}
	}
	if e := r.ReclaimPublicBodies(t.Context(), 1); e != nil {
		t.Fatal(e)
	}
	before := carryRowsInState(b.deletions[key].State())
	if before <= 128 {
		t.Fatal("fixture too small", before)
	}
	runCarryMaintenance(t, r)
	if got := carryRowsInState(b.deletions[key].State()); got != before-128 {
		t.Fatal("page limit", before, got)
	}
	if _, found := b.deletions[key].SnapshotIdentity(); found {
		t.Fatal("snapshot before last page")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	runCarryMaintenance(t, reopened)
	assertCarrySourceSnapshot(t, filepath.Join(cfg.DataDir, "expiry", owner.String(), fmt.Sprint(key)), owner, key)
	assertCarryRateCount(t, reopened.posting[owner], key, 0)
}

// expiredCarryReply は同じ古い公開スレッドへ連番の確定投稿frameを作る。
func expiredCarryReply(t *testing.T, create []byte, at domain.Time, number uint32) []byte {
	t.Helper()
	f, _, e := store.ReadFrame(bytes.NewReader(persistentReply(t, create, time.Unix(0, int64(at)))))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	op.Revision = domain.U64(number)
	op.Versions.Thread = 1
	op.After.PostCount, op.After.UserCount = number, number
	op.After.DATBytes = domain.U64(len(f.Records[0].DAT)) * domain.U64(number)
	op.Dedup.PostNumber = number
	binary.BigEndian.PutUint32((*op.Dedup.RequestID)[:4], number)
	binary.BigEndian.PutUint32(op.Dedup.Request[:4], number)
	var appendValue domain.Append
	if e = json.Unmarshal(op.Payload, &appendValue); e != nil {
		t.Fatal(e)
	}
	appendValue.Posts[0].Number = number
	op.Payload, _ = json.Marshal(appendValue)
	f.FirstSeq = uint64(number)
	f.Records[0].JSON, _ = json.Marshal(op)
	raw, e := store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
