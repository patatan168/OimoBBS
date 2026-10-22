// 原本回収前の案件metadata検査が署名/readerを維持し、未完了コピーの補完をしないことを確認する。
package disclosure

import (
	"errors"
	"os"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestInspectCaseMetadataBeforePendingHTTPCopy(t *testing.T) {
	s, _, c, _, _, _, _, key := reservedHTTPFixture(t)
	root := s.root
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	cases, e := InspectCaseMetadataVersion(root, key, 42)
	if e != nil || len(cases) != 1 || cases[0].ETag() != c.ETag() {
		t.Fatal(cases, e)
	}
	if _, e = os.Stat(s.artifactDir(c.ID, "http")); !os.IsNotExist(e) {
		t.Fatal("metadata inspection created copy directory", e)
	}
	if _, e = InspectCaseMetadataVersion(root, key, 41); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("metadata inspection bypassed reader42", e)
	}
	if e = InspectVersion(root, key, 42); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("full inspection skipped pending copy", e)
	}
	cases[0].HTTP.Items[0].Record = domain.NewID()
	cases[0].HTTP.Reservation.Binding.Operations[0] = domain.NewID()
	second, e := InspectCaseMetadataVersion(root, key, 42)
	if e != nil || len(second) != 1 || second[0].HTTP.Items[0].Record != c.HTTP.Items[0].Record || second[0].HTTP.Reservation.Binding.Operations[0] != c.HTTP.Reservation.Binding.Operations[0] {
		t.Fatal("metadata result changed signed intent", second, e)
	}
}
