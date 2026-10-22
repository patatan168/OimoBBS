// 必須元lease延長の先行承認・旧開示期限・元更新確認を案件署名へ束縛する。
package disclosure

import (
	"math"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"slices"
	"time"
)

// RequiredHoldExtension はreader47の必須元延長intent。確認前の開示期限はPreviousのまま。
type RequiredHoldExtension struct {
	Previous  domain.Time              `json:"previous_until_ns"`
	Until     domain.Time              `json:"requested_until_ns"`
	Requested domain.Time              `json:"requested_at_ns"`
	Revision  domain.U64               `json:"intent_revision"`
	Actor     domain.ID                `json:"actor_id"`
	State     string                   `json:"state"`
	Original  app.RequiredHoldReceipt  `json:"original_reservation"`
	Confirmed *app.RequiredHoldReceipt `json:"confirmed_reservation"`
}

func requiredExtensionPending(c Case) bool {
	return c.RequiredExtension != nil && c.RequiredExtension.State == "pending"
}

// validateRequiredExtensionAudit は新しい先行承認の要求者/版/時刻を署名操作へ固定する。
func validateRequiredExtensionAudit(a Audit) error {
	if a.Action == "required_extend_intent" {
		x := a.Case.RequiredExtension
		if x == nil || x.State != "pending" || x.Actor != a.Actor || x.Revision != a.Seq || x.Requested != a.At {
			return store.ErrCorrupt
		}
	}
	return validateRequiredExtension(a.Case, a.At)
}

// validateRequiredExtension は先行承認・元固定対象・段階状態/期限の完全型を照合する。
func validateRequiredExtension(c Case, at domain.Time) error {
	x := c.RequiredExtension
	if x == nil {
		return nil
	}
	if !validRequiredExtensionTimes(c, *x, at) || c.Required == nil || x.Actor == (domain.ID{}) || x.Revision == 0 || x.Revision > c.Revision {
		return store.ErrCorrupt
	}
	if !requiredExtensionIntentClock(c, *x, at) {
		return store.ErrCorrupt
	}
	if e := validateRequiredExtensionOriginal(c, *x); e != nil {
		return e
	}
	if x.State == "pending" {
		return validateRequiredPendingExtension(c, *x, at)
	}
	return validateRequiredCompleteExtension(c, *x, at)
}

// requiredExtensionIntentClock はintent自身の署名時刻を承認時刻へ固定する。
func requiredExtensionIntentClock(c Case, x RequiredHoldExtension, at domain.Time) bool {
	return x.Revision != c.Revision || x.Requested == at
}

// validateRequiredCompleteExtension は確認済み元参照と新期限の同時確定を検査する。
func validateRequiredCompleteExtension(c Case, x RequiredHoldExtension, at domain.Time) error {
	if x.State != "complete" || x.Confirmed == nil || c.Until < x.Until {
		return store.ErrCorrupt
	}
	if !requiredExtensionReceiptMatches(x, *x.Confirmed, at) || !sameRequiredReceipt(c.Required.Reservation, *x.Confirmed) {
		return store.ErrCorrupt
	}
	return nil
}

// validRequiredExtensionTimes は旧期限内承認と承認起算180日上限を検査する。
func validRequiredExtensionTimes(c Case, x RequiredHoldExtension, at domain.Time) bool {
	if x.Previous <= c.Created || x.Until <= x.Previous || x.Requested < c.Created || x.Requested >= x.Previous || x.Requested > at {
		return false
	}
	if x.Requested > domain.Time(math.MaxInt64-int64(180*24*time.Hour)) {
		return false
	}
	return x.Until <= x.Requested+domain.Time(180*24*time.Hour)
}

// validateRequiredExtensionOriginal は元の初回版/範囲/全対象と旧期限を承認へ固定する。
func validateRequiredExtensionOriginal(c Case, x RequiredHoldExtension) error {
	if e := app.ValidateRequiredHoldReceipt(x.Original); e != nil {
		return e
	}
	r := x.Original
	if r.State != "active" || r.Binding.Until != x.Previous || r.Binding.Revision >= x.Revision || r.At > x.Requested || !requiredBindingMatchesScope(c, r.Binding) {
		return store.ErrCorrupt
	}
	return requiredItemsMatchReceipt(c.Items, r)
}

// validateRequiredPendingExtension は旧期限を維持し、取消後だけ承認済み元参照の採用を許す。
func validateRequiredPendingExtension(c Case, x RequiredHoldExtension, at domain.Time) error {
	if x.Confirmed != nil || c.Until != x.Previous || httpExtensionPending(c) {
		return store.ErrCorrupt
	}
	if c.State == "active" || c.State == "draft" {
		return store.ErrCorrupt
	}
	if sameRequiredReceipt(c.Required.Reservation, x.Original) {
		return nil
	}
	if c.State != "closed" && c.State != "releasing" {
		return store.ErrCorrupt
	}
	if !requiredExtensionReceiptMatches(x, c.Required.Reservation, at) {
		return store.ErrCorrupt
	}
	return nil
}

// requiredExtensionReceiptMatches は期限だけが増えた現在元を承認済み全固定集合へ照合する。
func requiredExtensionReceiptMatches(x RequiredHoldExtension, r app.RequiredHoldReceipt, at domain.Time) bool {
	if app.ValidateRequiredHoldReceipt(r) != nil || r.State != "active" || r.Sequence <= x.Original.Sequence || r.At < x.Requested || r.At > at {
		return false
	}
	b := x.Original.Binding
	b.Until = x.Until
	return r.Binding == b && slices.Equal(r.Postings, x.Original.Postings)
}

// RequiredExtensionApproval は先行署名済み案件intentの承認を元所有列へ渡す。
func (c Case) RequiredExtensionApproval() (app.RequiredHoldApproval, error) {
	if !requiredExtensionPending(c) {
		return app.RequiredHoldApproval{}, ErrConflict
	}
	return app.RequiredHoldApproval{Revision: c.RequiredExtension.Revision, At: c.RequiredExtension.Requested}, nil
}

// PrepareRequiredExtension は未完了copyの元予約へ延長intentを先行署名する。copy/開示期限は変えない。
func (s *Store) PrepareRequiredExtension(id, actor domain.ID, etag, key, purpose string, until domain.Time, now time.Time) (Case, error) {
	return s.PrepareRequiredExtensionWithSource(id, actor, etag, key, purpose, until, now, nil)
}

// PrepareRequiredExtensionWithSource は未反映の現在元参照と延長intentを同じ署名行に保存する。
// 呼出元は元署名/現在性/物理原本とreader47を先に確認する。別行の束縛で要求CASを消費しない。
func (s *Store) PrepareRequiredExtensionWithSource(id, actor domain.ID, etag, key, purpose string, until domain.Time, now time.Time, source *app.RequiredHoldReceipt) (Case, error) {
	input := struct {
		Purpose string      `json:"purpose"`
		Until   domain.Time `json:"hold_until_ns"`
	}{purpose, until}
	replay, ok, e := s.Replay(id, actor, "required_extend_intent", etag, key, input)
	if e != nil {
		return replay, e
	}
	if ok {
		return s.currentRequiredExtension(replay)
	}
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	c, e = s.requiredExtensionSource(c, source)
	if e != nil {
		return c, e
	}
	if e = requiredExtensionPrepareReady(c, until, now); e != nil {
		return c, e
	}
	at := domain.Time(now.UnixNano())
	r := c.Required.Reservation
	r.Postings = slices.Clone(r.Postings)
	c.RequiredExtension = &RequiredHoldExtension{Previous: c.Until, Until: until, Requested: at, Revision: c.Revision + 1, Actor: actor, State: "pending", Original: r}
	return s.append(c, actor, "required_extend_intent", purpose, nil, etag, key, input, now)
}

// requiredExtensionSource は既存参照の完全一致か、最初の署名intentに合う未反映元だけを採用する。
func (s *Store) requiredExtensionSource(c Case, source *app.RequiredHoldReceipt) (Case, error) {
	if source == nil {
		return c, nil
	}
	if c.Required != nil {
		if !sameRequiredReceipt(c.Required.Reservation, *source) {
			return c, store.ErrCorrupt
		}
		return c, nil
	}
	if e := s.CheckRequiredRenewal(c, *source, nil); e != nil {
		return c, e
	}
	r := *source
	r.Postings = slices.Clone(source.Postings)
	c.Required = &RequiredSourceHold{Reservation: r}
	return c, nil
}

// httpExtensionPending は二種類の先行延長が同時に進むことを防ぐ。
func httpExtensionPending(c Case) bool { return c.Extension != nil && c.Extension.State == "pending" }

// requiredExtensionPrepareReady は現在元の期限と案件状態を延長要求へ束縛する。
func requiredExtensionPrepareReady(c Case, until domain.Time, now time.Time) error {
	if requiredExtensionPending(c) || c.Required == nil || httpExtensionPending(c) {
		return ErrConflict
	}
	if c.Required.Released != nil || c.State != "preparing" && c.State != "partial" {
		return ErrConflict
	}
	return requiredExtensionDeadlineReady(c, until, domain.Time(now.UnixNano()))
}

// requiredExtensionDeadlineReady は旧期限の一致と承認起算180日上限を要求する。
func requiredExtensionDeadlineReady(c Case, until, at domain.Time) error {
	if c.Required.Reservation.Binding.Until != c.Until || until <= c.Until {
		return ErrInvalid
	}
	if at > domain.Time(math.MaxInt64-int64(180*24*time.Hour)) || until > at+domain.Time(180*24*time.Hour) {
		return ErrInvalid
	}
	return nil
}

// currentRequiredExtension は同じ要求再送を現在intentへ束縛し、後続intentを飛ばさない。
func (s *Store) currentRequiredExtension(replay Case) (Case, error) {
	current, e := s.Get(replay.ID)
	if e != nil {
		return current, e
	}
	if replay.RequiredExtension == nil || current.RequiredExtension == nil || replay.RequiredExtension.Revision != current.RequiredExtension.Revision {
		return current, ErrConflict
	}
	if current.State == "closed" || current.State == "releasing" {
		return current, ErrExpired
	}
	return current, nil
}

// CompleteRequiredExtension は元の直後CAS/承認を確認してから元参照と案件期限を同時署名する。
// checkは同じ元所有列で現在性・承認・時計を確認し、待ち後の現在認可/CAS/新期限も検査する。
func (s *Store) CompleteRequiredExtension(id, actor domain.ID, etag string, proof app.RequiredHoldRenewalReceipt, now time.Time, check func() error) (Case, error) {
	c, e := s.requiredExtensionConfirmationReady(id, etag, proof, now, check)
	if e != nil {
		return c, e
	}
	if e = check(); e != nil {
		return c, e
	}
	c, e = s.Get(id)
	if e != nil {
		return c, e
	}
	if c.ETag() != etag {
		return c, ErrRevision
	}
	if c.State == "closed" || c.State == "releasing" {
		return c, ErrExpired
	}
	if c.RequiredExtension.State == "complete" {
		return c, nil
	}
	if e = s.requiredExtensionCommitClock(c, now); e != nil {
		return c, e
	}
	return s.saveRequiredExtensionComplete(c, actor, proof.Current, now)
}

// requiredExtensionConfirmationReady は所有者待ちの前に版・証明・確認手段を検査する。
func (s *Store) requiredExtensionConfirmationReady(id domain.ID, etag string, proof app.RequiredHoldRenewalReceipt, now time.Time, check func() error) (Case, error) {
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.ETag() != etag {
		return c, ErrRevision
	}
	if check == nil || c.RequiredExtension == nil || c.State == "closed" || c.State == "releasing" {
		return c, ErrConflict
	}
	return c, checkRequiredExtensionProof(*c.RequiredExtension, proof, domain.Time(now.UnixNano()))
}

// requiredExtensionCommitClock は新期限と最終署名以降の時計を確認する。
func (s *Store) requiredExtensionCommitClock(c Case, now time.Time) error {
	at := domain.Time(now.UnixNano())
	if at >= c.RequiredExtension.Until {
		return ErrExpired
	}
	last, e := s.lastAudit(c.ID)
	if e != nil {
		return e
	}
	if at < last.At {
		return ErrExpired
	}
	return nil
}

// checkRequiredExtensionProof は元履歴の旧CAS/承認を先行案件の完全一致へ束縛する。
func checkRequiredExtensionProof(x RequiredHoldExtension, p app.RequiredHoldRenewalReceipt, at domain.Time) error {
	expected := app.RequiredHoldApproval{Revision: x.Revision, At: x.Requested}
	if p.Approval != expected || !sameRequiredReceipt(p.Original, x.Original) || !requiredExtensionReceiptMatches(x, p.Current, at) {
		return store.ErrCorrupt
	}
	if x.State == "complete" && (x.Confirmed == nil || !sameRequiredReceipt(*x.Confirmed, p.Current)) {
		return store.ErrCorrupt
	}
	return nil
}

// saveRequiredExtensionComplete は参照採用/新期限/確認metadataを同じ署名行へ確定する。
func (s *Store) saveRequiredExtensionComplete(c Case, actor domain.ID, r app.RequiredHoldReceipt, now time.Time) (Case, error) {
	x := *c.RequiredExtension
	r.Postings = slices.Clone(r.Postings)
	x.State, x.Confirmed = "complete", &r
	h := *c.Required
	h.Reservation = r
	c.Required = &h
	c.RequiredExtension = &x
	c.Until = x.Until
	c.Review = x.Until - domain.Time(7*24*time.Hour)
	return s.append(c, actor, "required_extend_complete", "required_source_lease_confirmed", nil, "", "", nil, now)
}

// authorizeRequiredCancellation は旧開示期限後も先行承認の新期限内なら取消だけを許す。
// 開示認可はAuthorizeStateに残し、時計逆行/終端/古い版/新期限満了は救済しない。
func (s *Store) authorizeRequiredCancellation(id domain.ID, etag string, now time.Time) (Case, error) {
	c, e := s.AuthorizeState(id, etag, now)
	if e != ErrExpired || !requiredExtensionPending(c) {
		return c, e
	}
	if c.State != "preparing" && c.State != "partial" {
		return c, e
	}
	return c, s.requiredExtensionCommitClock(c, now)
}
