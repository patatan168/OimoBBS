// 日末署名を含む実投稿のオンラインコピーと期限検査の整合を確認する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"path/filepath"
	"testing"
	"time"
)

func TestOnlineBackupValidatesCheckpointWithoutInventedExpiry(t *testing.T) {
	_, r, info := postingRepositoryFixture(t)
	frame, at := agedRejectedFrame(t)
	b := r.posting[info.ID]
	value, err := b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return time.Unix(0, int64(at)) }
		defer func() { b.clock = time.Now }()
		return b.post(0, frame, []byte(`{"fixture":true}`)), nil
	})
	if err != nil || value.(RepositoryPostingResult).Status != store.Durable {
		t.Fatal(value, err)
	}
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	err = r.reconcileRequiredRetentionLocked(t.Context())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	day := time.Unix(0, int64(at)).UTC().Format("20060102")
	if _, ok := b.control.State().Rows["evidence_checkpoint:"+day]; !ok {
		t.Fatal("daily checkpoint missing")
	}
	pin, err := r.PinBoardBackup(t.Context(), info.ID, OnlineBackupGroupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	root := onlineOutput(t, "checkpoint")
	cut, err := pin.Copy(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	control, err := store.OpenControlWithValidators(filepath.Join(root, "board", info.ID.String(), "control"), 2, info.ID, 0, validateBoardValue, snapshotBoardValue)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if err = validateOnlineBoardCopy(t.Context(), root, b, control, cut.Captures); err != nil {
		t.Fatal("checkpoint rejected as expired personal record", err)
	}
	assertCheckpointBackupRetainsExpiry(t, cut, at)
}

// assertCheckpointBackupRetainsExpiry は日末固定で元の投稿期限が変わらないことを検査する。
func assertCheckpointBackupRetainsExpiry(t *testing.T, cut OnlineBackupGroupCapture, at domain.Time) {
	t.Helper()
	want := domain.Time(domain.SixMonths(time.Unix(0, int64(at))).UnixNano())
	for _, capture := range cut.Captures {
		if capture.Kind == "evidence" && capture.Capture.Expires != want {
			t.Fatal("checkpoint changed original retention", capture.Capture.Expires, want)
		}
	}
}
