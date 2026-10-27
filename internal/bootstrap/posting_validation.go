// 元byteだけに依存する照合をCPU数以内で分担し、保存前に全候補の結果を所有列へ戻す。
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"oimobbs/internal/domain"
	"oimobbs/internal/parallel"
)

type postingValidation struct {
	index   int
	check   func() error
	capture []byte
}

// validateCandidates は私的な検査結果だけを並行生成し、入力順に拒否・再構築へ反映する。
// 候補の予約は全workerの終了まで解放せず、検査中に所有状態やfileを変更しない。
func (g *postingGroup) validateCandidates() {
	errs := make([]error, len(g.validations))
	parallel.CPU(len(g.validations), func(i int) { errs[i] = g.validations[i].check() })
	g.verifiedCaptures = make(map[domain.Hash][]byte, len(g.validations))
	for i, err := range errs {
		if err != nil {
			g.rejected[g.validations[i].index] = err
			g.rebuild = true
		} else if raw := g.validations[i].capture; len(raw) > 0 {
			g.verifiedCaptures[sha256.Sum256(raw)] = raw
		}
	}
}

// captureVerified は同じflush内の完全検査済み元byteだけを共有する。全worker終了後にだけ使う。
// 書換えたbyte・別flush・失敗した候補の結果は再利用しない。
func (g *postingGroup) captureVerified(raw []byte) bool {
	if g == nil || g.rebuild {
		return false
	}
	known, ok := g.verifiedCaptures[sha256.Sum256(raw)]
	return ok && bytes.Equal(known, raw)
}
