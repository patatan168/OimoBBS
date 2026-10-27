// Cookie説明と利用規約を、権限・CAS・再送照合・監査付きで保存する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// AdminConsent は規約の編集値と自動計算された変更日時・保存版を返す。
type AdminConsent struct {
	Consent  PostingConsent `json:"consent"`
	Terms    domain.U64     `json:"terms_revision"`
	Revision domain.U64     `json:"revision"`
}

func (v AdminConsent) ETag() string { return fmt.Sprintf(`"consent:%d"`, v.Revision) }
func consentView(site siteState, revision domain.U64) AdminConsent {
	return AdminConsent{site.postingConsent(), site.Terms, revision}
}
func (r *Repository) adminConsent(s adminauth.Session) (AdminConsent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.currentAdministrator(s); e != nil {
		return AdminConsent{}, e
	}
	row := r.site.State().Rows["site:state"]
	var site siteState
	if e := strictjson.Decode(row.Value, &site); e != nil {
		return AdminConsent{}, e
	}
	return consentView(site, row.Revision), nil
}

// updateConsent は本文が変わる場合だけ規約版とJST表示用日時を更新する。
// receiptには元の結果の版と変更時刻を残し、後日の再送でも日時を作り直さない。
func (r *Repository) updateConsent(s adminauth.Session, text ConsentText, etag, key string) (AdminConsent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.currentAdministrator(s); e != nil {
		return AdminConsent{}, e
	}
	text.CookieNotice = strings.ReplaceAll(strings.ReplaceAll(text.CookieNotice, "\r\n", "\n"), "\r", "\n")
	text.TermsText = strings.ReplaceAll(strings.ReplaceAll(text.TermsText, "\r\n", "\n"), "\r", "\n")
	if !validConsentText(text.CookieNotice, 4096) || !validConsentText(text.TermsText, 24<<10) {
		return AdminConsent{}, &adminFailure{status: 422, code: "INVALID_CONSENT_TEXT"}
	}
	if !adminRequestKey.MatchString(key) {
		return AdminConsent{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminConsent{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	master, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if e != nil {
		return AdminConsent{}, e
	}
	defer clear(master)
	secret, e := identity.DeriveKey(master, "dedup", 8)
	if e != nil {
		return AdminConsent{}, e
	}
	defer clear(secret[:])
	requestKey := identity.MAC(secret[:], "oimo/admin-key/v1", s.Admin[:], []byte(key))
	raw, _ := json.Marshal(text)
	request := identity.MAC(secret[:], "oimo/posting-consent-update/v1", s.Admin[:], raw, []byte(etag))
	now := domain.Time(time.Now().UnixNano())
	state := r.site.State()
	row := state.Rows["site:state"]
	var site siteState
	if e = strictjson.Decode(row.Value, &site); e != nil {
		return AdminConsent{}, e
	}
	if prior, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var receipt adminReceipt
		// 別の管理操作の再送キーも、同じ名前空間で衝突として拒否する。
		if e = json.Unmarshal(prior.Value, &receipt); e != nil {
			return AdminConsent{}, e
		}
		if receipt.Created > now {
			return AdminConsent{}, ErrPostingUnavailable
		}
		if receipt.Expires > now {
			if receipt.Request != request {
				return AdminConsent{}, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			parts := strings.Split(receipt.Name, ":")
			if len(parts) != 3 || parts[0] != "consent" {
				return AdminConsent{}, ErrPostingUnavailable
			}
			revision, e := strconv.ParseUint(parts[1], 10, 64)
			if e != nil {
				return AdminConsent{}, e
			}
			changed, e := strconv.ParseInt(parts[2], 10, 64)
			if e != nil {
				return AdminConsent{}, e
			}
			return AdminConsent{PostingConsent{text.CookieNotice, text.TermsText, domain.Time(changed)}, domain.U64(revision), receipt.Revision}, nil
		}
	}
	current := consentView(site, row.Revision)
	if current.ETag() != etag {
		return AdminConsent{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) || site.Terms == ^domain.U64(0) {
		return AdminConsent{}, ErrPostingUnavailable
	}
	consent := site.postingConsent()
	changed := consent.text() != text
	if changed {
		consent = PostingConsent{text.CookieNotice, text.TermsText, now}
		site.Consent = &consent
		site.Terms++
		site.MinimumReader = max(site.MinimumReader, 98)
		site.PublicRevision = state.Seq + 1
	}
	id := domain.NewID()
	seq := state.Seq + 1
	// Nameは既存receipt形式の結果ラベル。本文を重複保存せず版と自動日時だけを符号化する。
	receipt := adminReceipt{ID: id, Admin: s.Admin, Key: requestKey, Request: request, Name: fmt.Sprintf("consent:%d:%d", site.Terms, consent.Changed), Revision: row.Revision, Created: now, Expires: now + 86400e9}
	changes := []store.Mutation{}
	if changed {
		receipt.Revision = seq
		changes = append(changes, mutation("site", "state", site, nil))
	}
	changes = append(changes, mutation("admin_receipt", requestKey.String(), receipt, nil))
	kid := uint32(8)
	frame, e := controlFrame(state, id, now, "posting_consent_update", changes, []string{site.ID.String()}, domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "posting_consent_update", Request: &request, Idempotency: &requestKey, KeyID: &kid})
	if e != nil {
		return AdminConsent{}, e
	}
	if r.site.Append(frame).Status != store.Durable {
		r.stopped = true
		return AdminConsent{}, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	if changed {
		r.liveConsent.Store(newPostingConsentState(site))
		r.publicRevision.Store(uint64(site.PublicRevision))
	}
	return consentView(site, receipt.Revision), nil
}
