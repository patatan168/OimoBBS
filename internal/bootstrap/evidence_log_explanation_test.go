// 実日別原本の確認/欠落と、非必須集計の未確認状態を表示用説明へ反映する。
package bootstrap

import (
	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEvidenceLogExplanationActualGapAndUnconfirmedDay(t *testing.T) {
	cfg, r, info := postingRepositoryFixture(t)
	raw, at := agedRejectedFrame(t)
	key, e := r.ReserveThreadKey(t.Context(), info.ID, time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	appendRejectedProposal(t, r, info.ID, key, raw, at)
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	e = r.reconcileRequiredRetentionLocked(t.Context())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	scope := disclosure.Scope{Board: info.ID, From: at - 1, To: at + 1}
	r.mu.Lock()
	text, e := r.evidenceLogExplanationLocked(scope)
	r.mu.Unlock()
	if e != nil || !strings.Contains(text, "原本へ照合 1日") || !strings.Contains(text, "集計がなく未確認") {
		t.Fatal(text, e)
	}
	path := filepath.Join(cfg.DataDir, "evidence", info.ID.String(), time.Unix(0, int64(at)).UTC().Format("20060102"))
	if e = os.RemoveAll(path); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	text, e = r.evidenceLogExplanationLocked(scope)
	r.mu.Unlock()
	if e != nil || !strings.Contains(text, "欠落・照合失敗 1日") {
		t.Fatal(text, e)
	}
}

func TestOptionalLossExplanationDoesNotClaimCaseCount(t *testing.T) {
	text := optionalLossExplanation(OptionalLossStatus{HasSnapshot: true, PersistFailed: true, Summary: &evidence.OptionalLossSummary{UnknownFrom: 1}, UnknownRange: "不明区間", Known: evidence.OptionalLossCounts{Failed: 7}})
	for _, want := range []string{"案件単位の件数ではありません", "保存失敗 7", "欠測件数は不明", "集計保存に失敗", "範囲外"} {
		if !strings.Contains(text, want) {
			t.Fatal(want, text)
		}
	}
}
