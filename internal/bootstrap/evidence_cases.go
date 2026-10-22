// 制限領域の案件保存と現在の管理権限・投稿所有列・定期回収を接続する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/adminaccess"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func inspectEvidenceCases(root string, reader uint32, allowPending bool, state store.ControlState) error {
	entries, e := os.ReadDir(filepath.Join(root, "cases"))
	if e != nil {
		return e
	}
	if len(entries) == 0 {
		return nil
	}
	if reader < 38 {
		return errors.New("evidence cases require reader38")
	}
	seed, e := readPrivate(filepath.Join(root, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	if !allowPending {
		cases, e := disclosure.InspectCasesVersion(filepath.Join(root, "cases"), key, reader)
		if e != nil {
			return e
		}
		return requireOptionalHoldActivationForCases(state, cases)
	}
	s, e := disclosure.Open(filepath.Join(root, "cases"), key)
	if e != nil {
		return e
	}
	defer s.Close()
	cases, e := s.Cases()
	if e != nil {
		return e
	}
	if e = requireOptionalHoldActivationForCases(state, cases); e != nil {
		return e
	}
	for _, c := range cases {
		if c.HTTP != nil && c.HTTP.Unbound && reader < 57 {
			return store.ErrCorrupt
		}
		if c.HTTP != nil && c.HTTP.Released != nil && reader < 43 {
			return errors.New("HTTP source release references require reader43")
		}
		if c.HTTP != nil && c.HTTP.Reservation != nil && reader < 42 {
			return errors.New("HTTP source reservation references require reader42")
		}
		if c.Extension != nil && reader < 44 {
			return errors.New("case extension intents require reader44")
		}
		if c.HTTP != nil && reader < 41 {
			return errors.New("HTTP case hold requires reader41")
		}
	}
	return nil
}
func (r *Repository) openEvidenceCases() error {
	seed, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	r.evidenceCases, e = disclosure.Open(filepath.Join(r.cfg.DataDir, "cases"), key)
	if e != nil {
		return e
	}
	r.evidenceCases.SetLogExplanation(r.evidenceLogExplanationLocked)
	if e = r.bindCaseRetirementsLocked(time.Now()); e != nil {
		return e
	}
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	e = r.reconcileRequiredRetentionLocked(context.Background())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	r.evidenceCleanupFailed = e != nil
	return e
}

// startEvidenceCleanup は公開系整理の有効設定と独立に、1分ごと案件・生成物期限を回収する。
func (r *Repository) startEvidenceCleanup() {
	ctx, cancel := context.WithCancel(context.Background())
	r.evidenceCancel = cancel
	r.evidenceDone = make(chan struct{})
	go func() {
		defer close(r.evidenceDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.optionalHoldLifecycleMu.Lock()
				r.mu.Lock()
				if !r.closed {
					e := r.reconcileRequiredRetentionLocked(ctx)
					r.evidenceCleanupFailed = e != nil
				}
				r.mu.Unlock()
				r.optionalHoldLifecycleMu.Unlock()
			}
		}
	}()
}

// authorizeEvidence はsite_adminにも追加権限を要求し、担当板と再認証を現在値で検査する。
func (r *Repository) authorizeEvidence(s adminauth.Session, permission string, board domain.ID, fresh bool) error {
	a, e := r.currentAdminSession(s)
	if e != nil {
		return e
	}
	definition, known := adminaccess.LookupPermission(permission)
	rank, valid := adminaccess.Rank(a.Role)
	minimum, _ := adminaccess.Rank(definition.MinimumRole)
	if !known || !strings.HasPrefix(permission, "evidence.") || !valid || rank < minimum {
		return &adminFailure{status: 403, code: "EVIDENCE_PERMISSION_REQUIRED"}
	}
	if !adminaccess.Granted(a.Role, a.Permissions, permission) {
		return &adminFailure{status: 403, code: "EVIDENCE_PERMISSION_REQUIRED"}
	}
	if board != (domain.ID{}) {
		if e = authorizeAdministrator(a, "moderator", board); e != nil {
			return e
		}
	}
	if fresh && !s.Reauthenticated(time.Now()) {
		return &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
	}
	return nil
}

// collectEvidence は投稿所有列の確定済み集合を取得する。公開threadが削除されてもjournalを参照する。
func (r *Repository) collectEvidence(ctx context.Context, scope disclosure.Scope) ([]app.AcceptedEvidence, error) {
	b := r.posting[scope.Board]
	if b == nil {
		return nil, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	return collectPostingEvidence(ctx, b, scope)
}

// collectPostingEvidence は呼出元が固定した板の所有列でのみ確定済み原本を選ぶ。
func collectPostingEvidence(ctx context.Context, b *postingBoard, scope disclosure.Scope) ([]app.AcceptedEvidence, error) {
	result, e := b.worker.Submit(ctx, func() (any, error) {
		journals := make([]*evidence.Journal, 0, len(b.journals))
		for _, j := range b.journals {
			journals = append(journals, j)
		}
		rows, err := app.AcceptedRecordsInRange(journals, func(owner domain.ID, key domain.U64, at domain.Time, id domain.ID) bool {
			return owner == scope.Board && (scope.Thread == 0 || scope.Thread == key) && at >= scope.From && at < scope.To && (len(scope.Records) == 0 || slices.Contains(scope.Records, id))
		}, disclosure.MaxRecords)
		if err != nil {
			if errors.Is(err, app.ErrEvidenceSelectionLimit) {
				return nil, disclosure.ErrLimit
			}
			return nil, err
		}
		selected := []app.AcceptedEvidence{}
		for _, row := range rows {
			if disclosure.Matches(scope, row) {
				selected = append(selected, row)
				if len(selected) > disclosure.MaxRecords {
					return nil, disclosure.ErrLimit
				}
			}
		}
		return selected, nil
	})
	if e != nil {
		return nil, e
	}
	return result.([]app.AcceptedEvidence), nil
}
func evidenceError(e error) error {
	switch {
	case errors.Is(e, disclosure.ErrRevision):
		return &adminFailure{status: 412, code: "EVIDENCE_REVISION_CONFLICT"}
	case errors.Is(e, disclosure.ErrConflict):
		return &adminFailure{status: 409, code: "EVIDENCE_CONFLICT"}
	case errors.Is(e, disclosure.ErrExpired):
		return &adminFailure{status: 410, code: "EVIDENCE_EXPIRED"}
	case errors.Is(e, disclosure.ErrLimit):
		return &adminFailure{status: 422, code: "EVIDENCE_SCOPE_LIMIT"}
	case errors.Is(e, disclosure.ErrInvalid):
		return &adminFailure{status: 400, code: "INVALID_EVIDENCE_INPUT"}
	case errors.Is(e, os.ErrNotExist):
		return &adminFailure{status: 404, code: "EVIDENCE_NOT_FOUND"}
	default:
		return e
	}
}

// requireOptionalHoldActivationForCases は元予約/解除参照のある案件にactiveサイト有効化行を要求する。
func requireOptionalHoldActivationForCases(state store.ControlState, cases []disclosure.Case) error {
	for _, c := range cases {
		if c.HTTP == nil || c.HTTP.Reservation == nil && c.HTTP.Released == nil {
			continue
		}
		for _, key := range []string{"optional_http:http", "optional_holds:http"} {
			row, exists := state.Rows[key]
			var a optionalLogActivation
			if !exists || strictjson.Decode(row.Value, &a) != nil || a.Phase != "active" || a.Site != c.HTTP.Site {
				return store.ErrCorrupt
			}
		}
	}
	return nil
}
