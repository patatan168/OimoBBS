// 現在の規約を、同意Cookieの有無によらず閲覧できる公開画面へ渡す。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
)

var publicConsentTemplate = webui.Template("public-consent")

func (r *Repository) publicConsentPage(w http.ResponseWriter, req *http.Request) {
	if !listingMethod(w, req) {
		return
	}
	r.mu.Lock()
	var site siteState
	e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site)
	r.mu.Unlock()
	if e != nil {
		threadError(w, req, 503, "現在閲覧できません。")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	if req.Method == "HEAD" {
		return
	}
	_ = publicConsentTemplate.Execute(w, struct {
		Consent PostingConsent
		Terms   domain.U64
		Board   string
	}{Consent: site.postingConsent(), Terms: site.Terms})
}
