// 回収登録を含む実site snapshotの作成・切替・再起動で、固定署名と期限なし行を維持する。
package bootstrap

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestCaseRetirementRegistrationSurvivesSiteSnapshotActivation(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	intent := registerRetirementForTest(t, r, candidate)
	row := r.site.State().Rows["case_retirement:"+intent.Fingerprint.String()]
	input := prepareRetirementSnapshotForTest(t, r)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if result, e := ActivateControlSnapshot(t.Context(), cfg, input, postingCaptureFixture); e != nil || !result.Activated {
		t.Fatal(result, e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	saved := reopened.site.State().Rows["case_retirement:"+intent.Fingerprint.String()]
	if !reflect.DeepEqual(row, saved) {
		t.Fatal("snapshot changed retirement receipt or metadata")
	}
	checkCaseRetirementStoredRow(t, reopened, candidate, saved)
}

func prepareRetirementSnapshotForTest(t *testing.T, r *Repository) string {
	t.Helper()
	for range 2 {
		if result, e := r.EnableControlSnapshots(t.Context()); e != nil || !result.AuditComplete {
			t.Fatal(result, e)
		}
	}
	input := filepath.Join(candidateParent(t), "retirement-snapshot")
	if result, e := r.PrepareControlSnapshot(t.Context(), input, 6); e != nil || !result.Verified {
		t.Fatal(result, e)
	}
	return input
}
