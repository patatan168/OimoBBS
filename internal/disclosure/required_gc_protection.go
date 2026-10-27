// 署名照合済み案件と元予約から、一回の原本回収に限定した保護集合を作る。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

type requiredGCKey struct {
	board domain.ID
	id    domain.ID
}

// RequiredGCProtection は本文を保持しない原本回収用の固定集合。
// 作成から回収終了まで呼出元が案件承認と元予約の共通排他を保持する。
type RequiredGCProtection struct {
	at                  domain.Time
	originals           map[requiredGCKey]domain.Hash
	rejectedConnections map[requiredGCKey]domain.Hash
}

// PrepareRequiredGCProtection は署名検査済みの全集合を横断照合して保護を固定する。
// floorには案件履歴と元履歴の最新時計床を渡す。未照合の入力や過去時刻を拒否する。
// 完成copyの物理検査は呼出元が回収前に別途行う。
func PrepareRequiredGCProtection(rows []RequiredCaseInspection, sources []app.RequiredHoldReceipt, renewals []app.RequiredHoldRenewalReceipt, now, floor domain.Time) (*RequiredGCProtection, error) {
	if now <= 0 || now < floor {
		return nil, evidence.ErrRetirementClock
	}
	if e := CheckRequiredCaseReservationsWithRenewals(rows, sources, renewals); e != nil {
		return nil, e
	}
	g := &RequiredGCProtection{at: now, originals: map[requiredGCKey]domain.Hash{}, rejectedConnections: map[requiredGCKey]domain.Hash{}}
	if e := g.addIntents(rows); e != nil {
		return nil, e
	}
	projected := requiredGCSourceDeadlines(rows)
	for _, r := range sources {
		if e := g.addSource(r, projected[r.Binding.Case]); e != nil {
			return nil, e
		}
	}
	return g, nil
}

// addIntents は予約保存前の中断でも署名済み固定対象を原期限後まで保護する。
func (g *RequiredGCProtection) addIntents(rows []RequiredCaseInspection) error {
	for _, row := range rows {
		if e := g.addIntent(row); e != nil {
			return e
		}
	}
	return nil
}

func (g *RequiredGCProtection) addIntent(row RequiredCaseInspection) error {
	c := row.Current
	if e := g.checkIntentClock(row); e != nil {
		return e
	}
	if e := g.addRejectedIntent(c); e != nil {
		return e
	}
	if row.Intent == nil || c.State != "preparing" && c.State != "partial" || c.RetentionUntil() <= g.at {
		return nil
	}
	if len(row.Intent.Items) > app.MaxRequiredHoldPostings {
		return ErrLimit
	}
	for _, item := range row.Intent.Items {
		if e := g.add(c.Scope.Board, item.Record, item.Source); e != nil {
			return e
		}
	}
	return nil
}

// checkIntentClock は未反映の承認を含む署名済み時刻より過去の回収を拒否する。
func (g *RequiredGCProtection) checkIntentClock(row RequiredCaseInspection) error {
	if row.Current.Created > g.at || row.Intent != nil && row.Intent.At > g.at {
		return evidence.ErrRetirementClock
	}
	if x := row.Current.RequiredExtension; x != nil && x.Requested > g.at {
		return evidence.ErrRetirementClock
	}
	return nil
}

// requiredGCSourceDeadlines は非終端の先行承認だけを元の回収保護期限へ投影する。
func requiredGCSourceDeadlines(rows []RequiredCaseInspection) map[domain.ID]domain.Time {
	result := map[domain.ID]domain.Time{}
	for _, row := range rows {
		c := row.Current
		if c.State == "preparing" || c.State == "partial" {
			result[c.ID] = c.RetentionUntil()
		}
	}
	return result
}

func (g *RequiredGCProtection) addSource(r app.RequiredHoldReceipt, approved domain.Time) error {
	if r.At > g.at {
		return evidence.ErrRetirementClock
	}
	if r.State != "active" || max(r.Binding.Until, approved) <= g.at {
		return nil
	}
	for _, p := range r.Postings {
		if e := g.addPair(r.Binding.Board, p.Identity); e != nil {
			return e
		}
	}
	return nil
}

func (g *RequiredGCProtection) addPair(board domain.ID, p evidence.RequiredPostingIdentity) error {
	if e := g.add(board, p.ProposalID, p.ProposalSHA); e != nil {
		return e
	}
	return g.add(board, p.DecisionID, p.DecisionSHA)
}

func (g *RequiredGCProtection) add(board, id domain.ID, sha domain.Hash) error {
	if board == (domain.ID{}) || id == (domain.ID{}) || sha == (domain.Hash{}) {
		return store.ErrCorrupt
	}
	k := requiredGCKey{board, id}
	if old, ok := g.originals[k]; ok && old != sha {
		return store.ErrCorrupt
	}
	g.originals[k] = sha
	return nil
}

// PairHeld は照合済み受理対応の片側が保護対象なら両側の回収を拒否する。
// 必ずJournal.PruneRequiredのidentity選択内で両原本に適用する。
// 別時刻への再利用と同一IDのhash差替えを拒否する。
func (g *RequiredGCProtection) PairHeld(board domain.ID, p evidence.RequiredPostingIdentity, now domain.Time) (bool, error) {
	if g == nil || now != g.at {
		return false, ErrConflict
	}
	a, e := g.matches(board, p.ProposalID, p.ProposalSHA)
	if e != nil {
		return false, e
	}
	b, e := g.matches(board, p.DecisionID, p.DecisionSHA)
	return a || b, e
}

func (g *RequiredGCProtection) matches(board, id domain.ID, sha domain.Hash) (bool, error) {
	expected, ok := g.originals[requiredGCKey{board, id}]
	if ok && expected != sha {
		return false, store.ErrCorrupt
	}
	return ok, nil
}

// addRejectedIntent は元予約の別台帳を増やさず、署名済み未完成案件から元GCを保護する。
func (g *RequiredGCProtection) addRejectedIntent(c Case) error {
	if c.Rejected == nil || c.Rejected.State != "preparing" || c.State != "preparing" || c.RetentionUntil() <= g.at {
		return nil
	}
	for _, ref := range c.Rejected.Sources {
		k := requiredGCKey{c.Scope.Board, ref.Record}
		if prior, exists := g.rejectedConnections[k]; exists && prior != ref.ProposalSHA {
			return store.ErrCorrupt
		}
		g.rejectedConnections[k] = ref.ProposalSHA
	}
	return nil
}

// RejectedConnectionHeld は未完成接続コピーだけを保護し、本文の24時間回収を延長しない。
func (g *RequiredGCProtection) RejectedConnectionHeld(board domain.ID, p evidence.RequiredPostingIdentity, now domain.Time) (bool, error) {
	held, e := g.PairHeld(board, p, now)
	if e != nil {
		return false, e
	}
	expected, found := g.rejectedConnections[requiredGCKey{board, p.ProposalID}]
	if found && expected != p.ProposalSHA {
		return false, store.ErrCorrupt
	}
	return held || found, nil
}
