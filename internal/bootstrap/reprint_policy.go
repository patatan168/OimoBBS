// 板単位の転載案内と、公開内容を収集するクローラーへの制限を管理する。
package bootstrap

import (
	"fmt"
	"io"
	"net/http"
	"oimobbs/internal/strictjson"
	"sort"
	"strconv"
	"strings"
)

// reprintDenied は未設定の旧板をOFFとして解決する。
func (p boardPresentation) reprintDenied() bool { return p.NoReprint != nil && *p.NoReprint }

// reprintNotice はローカルルールと投稿確認で共通の案内を返す。
func reprintNotice() []ruleParagraph {
	return []ruleParagraph{
		{Kind: "paragraph", Text: "【無断転載禁止】投稿者が自ら創作した文章・画像等の著作権は、投稿者に帰属します。投稿によって著作権が運営者へ譲渡されることはありません。"},
		{Kind: "paragraph", Text: "投稿者は、本掲示板での表示、専用ブラウザへの配信、保存および管理に必要な範囲で、運営者が投稿内容を利用することを許諾します。"},
		{Kind: "paragraph", Text: "権利者の許諾なく、投稿内容を外部サイト・SNS・動画等へ転載・再配信することを禁止します。ただし、著作権法上認められる引用その他の利用を除きます。"},
		{Kind: "paragraph", Text: "引用（著作権法32条）：公表済みの著作物を、公正な慣行に沿い、報道・批評・研究等の目的上正当な範囲で利用してください。引用部分を明確に区別し、本文が主・引用が従となる関係で、必要な範囲にとどめることが判断の目安です。出所（投稿URL・レス番号等）も明示してください（48条）。出所を示すだけでは無断転載が適法になるわけではありません。"},
	}
}

// ReprintNotice は確認画面に表示する転載案内を返す。
func (c ConfirmationChallenge) ReprintNotice() []ruleParagraph { return reprintNotice() }

// publicLocalRules は板ワーカー内で、保存されたルールに生成した案内を前置する。
// 編集用のルールや既存投稿のDATは変更しない。
func (b *postingBoard) publicLocalRules() (AdminLocalRules, error) {
	rules, err := b.localRules()
	if err != nil {
		return rules, err
	}
	var state boardValue
	if err := strictjson.Decode(b.control.State().Rows["board:state"].Value, &state); err != nil {
		return rules, err
	}
	if state.Settings.Presentation.reprintDenied() {
		rules.Settings.Rules = append(reprintNotice(), rules.Settings.Rules...)
	}
	return rules, nil
}

// protectedBoardSlugs は転載禁止・隠し板の公開制限を保存完了時に更新したキャッシュから読む。
func (repo *Repository) protectedBoardSlugs() []string {
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	slugs := []string{}
	for _, b := range repo.posting {
		if b.noReprint.Load() || b.hidden.Load() {
			slugs = append(slugs, b.slug)
		}
	}
	return slugs
}

// robotsPage は転載禁止または隠し板ONの板について巡回禁止を通知する。
func (repo *Repository) robotsPage(w http.ResponseWriter, r *http.Request) {
	if !listingMethod(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache")
	var body strings.Builder
	body.WriteString("User-agent: *\n")
	slugs := repo.protectedBoardSlugs()
	sort.Strings(slugs)
	for _, slug := range slugs {
		fmt.Fprintf(&body, "Disallow: /%s/\nDisallow: /test/read.cgi/%s/\nDisallow: /web/post?*bbs=%s$\nDisallow: /web/post?*bbs=%s&\n", slug, slug, slug, slug)
	}
	if len(slugs) > 0 {
		body.WriteString("Disallow: /search\nDisallow: /test/bbs.cgi\n")
	}
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	if r.Method != "HEAD" {
		_, _ = w.Write([]byte(body.String()))
	}
}

// reprintCrawlerGate は経路を正規化した公開ルーターで、DAT処理前にも適用する。
func (repo *Repository) reprintCrawlerGate(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, bool) {
	slugs := repo.protectedBoardSlugs()
	protected := false
	path := r.URL.Path
	for _, slug := range slugs {
		if strings.HasPrefix(path, "/"+slug+"/") || strings.HasPrefix(path, "/test/read.cgi/"+slug+"/") || path == "/web/post" && r.URL.Query().Get("bbs") == slug {
			protected = true
			break
		}
	}
	// 検索は複数板のタイトルを返す。CGIは本文を読む前に制限する。
	if len(slugs) > 0 && (path == "/search" || path == "/test/bbs.cgi") {
		protected = true
	}
	if !protected {
		return w, false
	}
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, nosnippet")
	wrapped := &reprintResponseWriter{ResponseWriter: w}
	if knownContentCrawler(r.UserAgent()) {
		wrapped.Header().Set("Cache-Control", "no-store")
		wrapped.WriteHeader(http.StatusForbidden)
		if r.Method != "HEAD" {
			_, _ = wrapped.Write([]byte("この板ではクローラーによる取得を許可していません。"))
		}
		return wrapped, true
	}
	return wrapped, false
}

// reprintResponseWriter は下流のキャッシュ設定後もUAによる応答差を明示する。
type reprintResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

// Unwrap は送信期限等のResponseControllerを下流へ接続する。
func (w *reprintResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WriteHeader は下流のVaryを保持し、共有キャッシュ利用を抑止する。
func (w *reprintResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.prepareHeaders(status)
	w.ResponseWriter.WriteHeader(status)
}

// prepareHeaders は本文の送信経路に関係なくUA差と共有cacheの境界を設定する。
func (w *reprintResponseWriter) prepareHeaders(status int) {
	h := w.Header()
	found := false
	for _, value := range h.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "User-Agent") || strings.TrimSpace(field) == "*" {
				found = true
			}
		}
	}
	if !found {
		h.Add("Vary", "User-Agent")
	}
	// 取得可能な本文を共有キャッシュからクローラーへ配布させない。
	if status != http.StatusForbidden && !strings.Contains(h.Get("Cache-Control"), "no-store") {
		h.Set("Cache-Control", "private, no-cache")
	}
}

// WriteResponseChecked は転載制限ヘッダを保ち、一括応答でも各送信片の公開検査を下流へ渡す。
func (w *reprintResponseWriter) WriteResponseChecked(status int, body []byte, check func() error) (int, error) {
	if writer, ok := w.ResponseWriter.(interface {
		WriteResponseChecked(int, []byte, func() error) (int, error)
	}); ok && !w.wroteHeader {
		w.prepareHeaders(status)
		n, err := writer.WriteResponseChecked(status, body, check)
		w.wroteHeader = err == nil || n > 0
		return n, err
	}
	if check != nil {
		if err := check(); err != nil {
			return 0, err
		}
	}
	w.WriteHeader(status)
	return writeCheckedFallback(w.ResponseWriter, body, check)
}

// WriteResponse は公開リースを持たない設定本文等にも、転載制限付き一括送信を適用する。
func (w *reprintResponseWriter) WriteResponse(status int, body []byte) (int, error) {
	return w.WriteResponseChecked(status, body, nil)
}

// writeCheckedFallback は帯域writerがない内部HTTPでも16KiBごとの公開検査を省かない。
func writeCheckedFallback(w http.ResponseWriter, body []byte, check func() error) (int, error) {
	total := 0
	for len(body) > 0 {
		if check != nil {
			if err := check(); err != nil {
				return total, err
			}
		}
		size := min(len(body), 16<<10)
		n, err := w.Write(body[:size])
		total += n
		if err != nil {
			return total, err
		}
		if n != size {
			return total, io.ErrShortWrite
		}
		body = body[size:]
	}
	return total, nil
}

// Write は暗黙の200にもクローラー用キャッシュ境界を適用する。
func (w *reprintResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}
