// 投稿時のCookie説明・利用規約と、旧保存形式の既定値を定義する。
package bootstrap

import (
	"crypto/sha256"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ConsentText は管理画面で編集する平文。HTMLとして解釈しない。
type ConsentText struct {
	CookieNotice string `json:"cookie_notice"`
	TermsText    string `json:"terms_text"`
}

// PostingConsent は公開する規約と、システムが設定する変更日時を保持する。
type PostingConsent struct {
	CookieNotice string      `json:"cookie_notice"`
	TermsText    string      `json:"terms_text"`
	Changed      domain.Time `json:"changed_at_ns"`
}

// postingConsentState は本文の指紋を発行・編集時に一度だけ計算して共有する。
// 配備時に既定文が変わった場合も、旧文への同意を流用できない。
type postingConsentState struct {
	Site   siteState
	Digest domain.Hash
}

func newPostingConsentState(site siteState) *postingConsentState {
	raw, _ := json.Marshal(site.postingConsent().text())
	return &postingConsentState{site, domain.Hash(sha256.Sum256(raw))}
}

func defaultPostingConsent() PostingConsent {
	return PostingConsent{
		CookieNotice: "本掲示板はCookieを使用します。匿名の継続識別、荒らし対策、投稿の安全性の確認、および利用規約への同意状態の保存に使用します。同意状態のCookieは最長1年間保存します。Cookieを削除した場合や有効期限が切れた場合、利用規約が変更された場合は、次の書き込み時に再度同意を確認します。",
		TermsText: `【適用・準拠法】
本掲示板の利用および本規約には日本法を適用します。日本の法令と公序良俗を守り、各板のローカルルールと投稿画面の公開条件を確認して利用してください。

【禁止事項】
誹謗中傷、名誉・信用を傷つける投稿、侮辱、脅迫、差別や嫌がらせを目的とする投稿を禁止します。
他人の住所・電話番号・私生活に関する情報などの無断掲載、プライバシー・肖像権・著作権その他の権利を侵害する投稿を禁止します。
犯罪の予告・勧誘・助長、違法な取引、荒らし・連投・不正アクセスその他の運営を妨げる行為を禁止します。

【投稿者の責任と運営の対応】
投稿前に内容と他者の権利を確認してください。投稿内容によっては民事上・刑事上の責任が生じる場合があります。
規約違反や権利侵害のおそれがある場合、運営者は投稿の非表示・削除、投稿制限などの対応を行うことがあります。権利侵害や削除については「削除依頼・照会」から連絡してください。情報の開示・提供は、日本の法令に基づく手続に従って対応します。

【転載・再配信】
無断転載禁止の板では、その板の転載に関する案内に従ってください。それ以外の板への投稿については、投稿者が権利を持つ投稿内容の転載・再配信を許可するものとします。

【記録と保存期限】
受理した投稿内容と、接続元IPアドレス・ポート・日時などの接続記録を、投稿の確定日時から6暦月、非公開の記録として保持します。公開表示を削除した後も、この保存期限は継続します。
投稿試行・閲覧などの接続と処理結果の通常保存期限は7日です。未受理が確定した投稿の一時保存本文は、投稿準備時の記録日時から24時間が保存期限です。運営者が対象を指定して案件保全したコピーは、指定した保全期限まで保持します。

【規約の変更】
規約の変更日は日本標準時（JST）で表示します。Cookieの説明または利用規約を変更した場合、次の書き込み時に改めて同意を確認します。`,
	}
}

func (s siteState) postingConsent() PostingConsent {
	if s.Consent != nil {
		return *s.Consent
	}
	return defaultPostingConsent()
}
func (p PostingConsent) text() ConsentText { return ConsentText{p.CookieNotice, p.TermsText} }
func validConsentText(s string, limit int) bool {
	if strings.TrimSpace(s) == "" || len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return false
		}
	}
	return true
}
func (p PostingConsent) valid() bool {
	return p.Changed > 0 && validConsentText(p.CookieNotice, 4096) && validConsentText(p.TermsText, 24<<10)
}

// ChangedDate はOSのタイムゾーンに依存せず、JSTの日付を表示する。
func (p PostingConsent) ChangedDate() string {
	if p.Changed == 0 {
		return "初期設定"
	}
	return time.Unix(0, int64(p.Changed)).In(time.FixedZone("JST", 9*3600)).Format("2006年01月02日")
}

// UnmarshalJSON は旧サイトで追加項目が省略されている場合だけ既定値を補う。
func (s *siteState) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if e := strictjson.Decode(raw, &fields); e != nil {
		return e
	}
	if _, ok := fields["posting_consent"]; !ok {
		fields["posting_consent"] = json.RawMessage("null")
	}
	normalized, e := json.Marshal(fields)
	if e != nil {
		return e
	}
	type plain siteState
	var v plain
	if e = strictjson.Decode(normalized, &v); e != nil {
		return e
	}
	*s = siteState(v)
	return nil
}
