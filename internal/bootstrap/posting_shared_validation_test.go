// 一括検証の再利用を同じ元byte・成功したflushへ限定し、拒否結果の持越しを防ぐ。
package bootstrap

import (
	"errors"
	"testing"
)

func TestPostingVerifiedCaptureScope(t *testing.T) {
	raw := []byte(`{"capture":"accepted"}`)
	g := &postingGroup{rejected: map[int]error{}, validations: []postingValidation{{index: 0, check: func() error { return nil }, capture: raw}}}
	if g.captureVerified(raw) {
		t.Fatal("used before validation")
	}
	g.validateCandidates()
	if !g.captureVerified(append([]byte{}, raw...)) {
		t.Fatal("same bytes not shared")
	}
	changed := append([]byte{}, raw...)
	changed[len(changed)-3] = 'x'
	if g.captureVerified(changed) {
		t.Fatal("changed bytes accepted")
	}
	g.rebuild = true
	if g.captureVerified(raw) {
		t.Fatal("failed group reused")
	}
	g.rebuild = false
	g.validations[0].check = func() error { return errors.New("bad capture") }
	g.validateCandidates()
	if g.captureVerified(raw) {
		t.Fatal("failed validation reused")
	}
	if (*postingGroup)(nil).captureVerified(raw) {
		t.Fatal("shared outside group")
	}
}
