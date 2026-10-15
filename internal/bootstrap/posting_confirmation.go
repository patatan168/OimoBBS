// 投稿確認は板ワーカー内で再検証し、キー予約・再送照合より先に判定する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postinput"
	"time"
)

var ErrConfirmationRequired = errors.New("posting confirmation required")

// ConfirmationPreview は表示可能な入力のみ。資格秘密・再送HMACを含めない。
type ConfirmationPreview struct {
	Cap   string `json:"cap,omitempty"`
	Name  string `json:"name"`
	Trip  string `json:"trip"`
	Mail  string `json:"mail"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// ConfirmationChallenge は確認画面とCookie発行に必要な一時値。保存/logへ渡さない。
// Tokenは専用Cookieへ設定し、HTMLの表示本文には含めない。
type ConfirmationChallenge struct {
	Management      bool                `json:"management_command,omitempty"`
	Token           string              `json:"-"`
	Expires         int64               `json:"expires"`
	Terms           domain.U64          `json:"terms_revision"`
	Preview         ConfirmationPreview `json:"preview"`
	IDMode          string              `json:"id_mode"`
	SlipMode        string              `json:"slip_mode"`
	PublicIP        bool                `json:"public_ip"`
	NoReprint       bool                `json:"no_reprint,omitempty"`
	CapOnly         bool                `json:"cap_only,omitempty"`
	RequireID       bool                `json:"require_id"`
	RequireSlipHash bool                `json:"require_slip_hash"`
}

// LegacyFormResult は未受理の確認要求と確定した投稿結果を区別する。
type LegacyFormResult struct {
	Management      bool
	AnonymousCookie *http.Cookie `json:"-"`
	RepositoryPostingResult
	Confirmation *ConfirmationChallenge
}

func legacyResult(r RepositoryPostingResult) LegacyFormResult {
	return LegacyFormResult{RepositoryPostingResult: r}
}
func legacyFailure(e error) LegacyFormResult { return legacyResult(formFailure(e)) }

// confirmation は正規化入力・規約・実効公開条件に署名を束縛する。未確認時は保存しない。
func (b *postingBoard) confirmation(token string, input postinput.Input, d domain.Dedup, site siteState, settings boardSettings, key uint64, now time.Time) (*ConfirmationChallenge, error) {
	policy := initialPostingPolicy(settings)
	versions := domain.Versions{Site: site.PublicRevision, Board: settings.Version}
	if key != 0 && !(key == reportReceiptKey && b.receipt.Load() != nil) {
		p := b.threads[key]
		if p == nil {
			return nil, postinput.ErrInput
		}
		var ok bool
		policy, ok = p.PostingPolicy(domain.Time(now.UnixNano()))
		if !ok {
			return nil, postinput.ErrInput
		}
		versions.Thread = policy.Version
	}
	if key == 0 && input.CapOnly {
		policy.CapOnly = true
	}
	if e := postinput.CheckDisplayCommands(input.Controls, settings.Identity.DisplayCommands); e != nil {
		return nil, e
	}
	policy, e := postinput.DisplayPolicy(policy, input.Controls, settings.Identity.AllowStrengthen)
	if e != nil {
		return nil, e
	}
	digest, e := confirmationPolicy(b.confirmKey, versions, policy, settings.Input, settings.Presentation.reprintDenied())
	if e != nil {
		return nil, e
	}
	want := abuse.Confirmation{Board: b.owner, Terms: uint64(site.Terms), Request: d.Request, Policy: digest, Issued: now.Unix(), Expires: now.Unix() + 600}
	if abuse.VerifyConfirmation(token, want, b.confirmKey[:], 5, now) == nil {
		return nil, nil
	}
	signed, e := abuse.IssueConfirmation(want, b.confirmKey[:], 5)
	if e != nil {
		return nil, e
	}
	name, mail := input.Name, input.Mail
	if name == "" || settings.Input.ForceNoname {
		name = settings.Input.Noname
	}
	if settings.Input.HideMail {
		mail = ""
	}
	return &ConfirmationChallenge{Token: signed, Expires: want.Expires, Terms: site.Terms, Preview: ConfirmationPreview{Name: name, Trip: input.Trip, Mail: mail, Title: input.Title, Body: input.Body}, IDMode: policy.IDMode, SlipMode: policy.SlipMode, PublicIP: postinput.HasPublicIP(policy), NoReprint: settings.Presentation.reprintDenied(), CapOnly: policy.CapOnly, RequireID: policy.RequireID, RequireSlipHash: policy.RequireSlipHash}, nil
}

// confirmationPolicy は投稿番号や日時を含めず、公開条件と版の変更だけで再確認させる。
func confirmationPolicy(key domain.Hash, versions domain.Versions, policy domain.Policy, input boardInput, noReprint ...bool) (domain.Hash, error) {
	denied := len(noReprint) > 0 && noReprint[0]
	raw, e := json.Marshal(struct {
		Versions  domain.Versions `json:"versions"`
		Policy    domain.Policy   `json:"policy"`
		Input     boardInput      `json:"input"`
		NoReprint bool            `json:"no_reprint,omitempty"`
	}{versions, policy, input, denied})
	if e != nil {
		return domain.Hash{}, e
	}
	return identity.MAC(key[:], "oimo/confirmation-policy/v1", raw), nil
}

// initialPostingPolicy は確認表示と新規投稿構築で同じ実効条件を使う。
func initialPostingPolicy(settings boardSettings) domain.Policy {
	return domain.Policy{Version: 1, IDMode: settings.Identity.IDMode, SlipMode: settings.Identity.SlipMode, RequirePublicIP: settings.Identity.RequireIP, UserPostLimit: settings.Thread.PostLimit, DATUserLimit: settings.Thread.DATLimit, Commands: append([]string{}, settings.Posting.Commands...), AutoNext: settings.Thread.AutoNext, Pinned: settings.Thread.AllowPinned}
}
