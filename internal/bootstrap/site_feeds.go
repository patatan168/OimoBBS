// 公開メタデータと確定snapshotを専ブラ用menu・subject・設定・DATへ変換する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
	"strconv"
	"strings"
	"time"
)

type legacyMenuBoard struct {
	Name string `json:"board_name"`
	URL  string `json:"url"`
}
type legacyCategory struct {
	Name   string            `json:"category_name"`
	Boards []legacyMenuBoard `json:"category_content"`
}

func (repo *Repository) legacyMenu(w http.ResponseWriter, r *http.Request, title string, boards []publicBoard) {
	if !listingMethod(w, r) {
		return
	}
	groups := groupPublicBoards(title, boards)
	categories := make([]legacyCategory, 0, len(groups))
	if len(groups) == 0 {
		categories = append(categories, legacyCategory{title, []legacyMenuBoard{}})
	}
	for _, group := range groups {
		rows := make([]legacyMenuBoard, 0, len(group.Boards))
		for _, b := range group.Boards {
			rows = append(rows, legacyMenuBoard{b.Name, strings.TrimSuffix(repo.cfg.Public.BaseURL, "/") + "/" + b.Key + "/"})
		}
		categories = append(categories, legacyCategory{group.Name, rows})
	}
	if r.URL.Path == "/bbsmenu.json" {
		body, e := json.Marshal(struct {
			List []legacyCategory `json:"menu_list"`
		}{categories})
		repo.writeFeed(w, r, "application/json; charset=UTF-8", body, e)
		return
	}
	var menu strings.Builder
	menu.WriteString(`<!doctype html><html lang="ja"><head><meta charset="Shift_JIS"></head><body>`)
	for _, group := range categories {
		menu.WriteString(`<b>` + html.EscapeString(group.Name) + `</b><br>`)
		for _, b := range group.Boards {
			fmt.Fprintf(&menu, `<a href="%s">%s</a><br>`, html.EscapeString(b.URL), html.EscapeString(b.Name))
		}
	}
	menu.WriteString(`</body></html>`)
	body, e := textcodec.Encode(menu.String(), true)
	repo.writeFeed(w, r, "text/html; charset=Shift_JIS", body, e)
}
func legacyFeedPath(path string) bool {
	p := strings.Split(path, "/")
	if len(p) == 3 {
		return p[2] == "subject.txt" || p[2] == "SETTING.TXT" || p[2] == "head.txt"
	}
	return len(p) == 4 && p[2] == "dat" && strings.HasSuffix(p[3], ".dat")
}
func (repo *Repository) legacyFeed(w http.ResponseWriter, r *http.Request, board publicBoard) {
	var denied bool
	w, denied = repo.readingBoardGate(w, r, board.ID)
	if denied {
		return
	}
	publicDataHeaders(w)
	if !listingMethod(w, r) {
		return
	}
	if len(strings.Split(r.URL.Path, "/")) == 4 {
		repo.legacyDAT(w, r, board)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/subject.txt") {
		rows, e := repo.threadListing(r, board.ID)
		if e != nil {
			threadError(w, r, 503, "現在閲覧できません。")
			return
		}
		feed, e := repo.subjectBody(r, board.ID, rows)
		writer, leaseErr := repo.publicListingWriter(w, r, board.ID, rows)
		if leaseErr != nil {
			threadError(w, r, 503, "現在閲覧できません。")
			return
		}
		defer writer.Close()
		repo.writeRenderedFeed(writer, r, "text/plain; charset=Shift_JIS", feed, e)
		return
	}
	b, e := repo.postingOwner(board.ID)
	if e != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	value, e := b.worker.Submit(r.Context(), func() (any, error) {
		var state boardValue
		if err := strictjson.Decode(b.control.State().Rows["board:state"].Value, &state); err != nil {
			return nil, err
		}
		if strings.HasSuffix(r.URL.Path, "/head.txt") {
			rules, err := b.localRules()
			if err != nil {
				return nil, err
			}
			custom, err := localRulesHead(rules.Settings.Rules)
			if err != nil || !state.Settings.Presentation.reprintDenied() {
				return custom, err
			}
			prefix, err := localRulesHead(reprintNotice())
			return append(prefix, custom...), err
		}
		state.Name = b.boardName()
		return legacySettings(state)
	})
	if e != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	repo.writeFeed(w, r, "text/plain; charset=Shift_JIS", value.([]byte), nil)
}

// writeFeed はキャッシュを使わない本文にも同じ検証子と送信契約を適用する。
func (repo *Repository) writeFeed(w http.ResponseWriter, r *http.Request, contentType string, body []byte, err error) {
	if err != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	repo.writeRenderedFeed(w, r, contentType, compat.RenderedFeed{Body: body, Tag: compat.FeedTag(body)}, nil)
}

// writeRenderedFeed は生成時の検証子を使い、公開検査を持つwriterへ毎回接続する。
func (repo *Repository) writeRenderedFeed(w http.ResponseWriter, r *http.Request, contentType string, feed compat.RenderedFeed, err error) {
	repo.writeRenderedFeedProfile(w, r, contentType, feed, err, false)
}

// writeRenderedFeedProfile は更新中HTMLのgzipだけを軽量化し、公開検査と条件応答を共用する。
func (repo *Repository) writeRenderedFeedProfile(w http.ResponseWriter, r *http.Request, contentType string, feed compat.RenderedFeed, err error, live bool) {
	if err != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	if strings.HasPrefix(contentType, "text/plain;") || strings.HasPrefix(contentType, "application/json;") {
		publicDataHeaders(w)
	}
	tag := feed.Tag
	gzipSuffix, compress := compat.GzipETagSuffix, repo.feedCompression.Compress
	if live {
		gzipSuffix, compress = compat.GzipLiveETagSuffix, repo.feedCompression.CompressLive
	}
	compat.ServeDAT(w, r, compat.Representation{DAT: feed.Body, ContentType: contentType, DisableRange: true, ETagIdentity: `"` + tag + `-identity"`, ETagGzip: `"` + tag + gzipSuffix + `"`, ETagZstd: `"` + tag + compat.ZstdETagSuffix + `"`, Compress: compress})
}

// legacyDAT は期限判定とsnapshotの取得を同じ板ワーカー内で行い、公開版だけをHTTPへ渡す。
func (repo *Repository) legacyDAT(w http.ResponseWriter, r *http.Request, board publicBoard) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 4 || parts[2] != "dat" {
		threadError(w, r, 404, "スレッドが見つかりません。")
		return
	}
	raw := strings.TrimSuffix(parts[3], ".dat")
	key, e := strconv.ParseUint(raw, 10, 64)
	if e != nil || key == 0 || strconv.FormatUint(key, 10) != raw {
		threadError(w, r, 404, "スレッドが見つかりません。")
		return
	}
	b, e := repo.postingOwner(board.ID)
	if e != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	now := b.clock()
	snapshot, status := b.publicSnapshot(key, domain.Time(now.UnixNano()))
	if status != 200 {
		threadError(w, r, status, "スレッドを表示できません。")
		return
	}
	tag := fmt.Sprintf("%s-%d-%d-%d", board.ID, key, snapshot.Generation, snapshot.Revision)
	representation := compat.Representation{DAT: snapshot.DAT, Compress: repo.feedCompression.Compress, ETagIdentity: `"` + tag + `-identity"`, ETagGzip: `"` + tag + compat.GzipETagSuffix + `"`, ETagZstd: `"` + tag + compat.ZstdETagSuffix + `"`, Modified: time.Unix(0, int64(snapshot.Modified)), Now: now, DateSafe: snapshot.DateSafe, DateExact: snapshot.DateExact, LegacyRangeDisabled: snapshot.LegacyRangeDisabled}
	writer, e := publicWriter(w, r, snapshot, b.clock)
	if e != nil {
		threadError(w, r, 410, "スレッドを表示できません。")
		return
	}
	defer writer.Close()
	compat.ServeDAT(writer, r, representation)
}

// legacySettings は現在受理可能な初期設定の公開キーを設計16の順で出力する。
func legacySettings(board boardValue) ([]byte, error) {
	s := board.Settings
	var body bytes.Buffer
	field := func(key string, value any) { fmt.Fprintf(&body, "%s=%v\n", key, value) }
	field("BBS_TITLE", board.Name)
	field("BBS_TITLE_ORIG", board.Name)
	field("BBS_NONAME_NAME", s.Input.Noname)
	field("BBS_SUBJECT_COUNT", s.Input.TitleBytes)
	field("BBS_NAME_COUNT", s.Input.NameBytes)
	field("BBS_MAIL_COUNT", s.Input.MailBytes)
	field("BBS_MESSAGE_COUNT", s.Input.BodyBytes)
	field("BBS_LINE_NUMBER", s.Input.BodyLines/2)
	switch s.Identity.IDMode {
	case "required":
		field("BBS_FORCE_ID", "checked")
	case "hidden":
		field("BBS_NO_ID", "checked")
	}
	if s.Identity.SlipMode != "none" {
		field("BBS_SLIP", s.Identity.SlipMode)
	}
	if s.Identity.extendCommandEnabled() {
		field("BBS_USE_VIPQ2", 2)
	}
	if s.Identity.RequireIP {
		field("BBS_DISP_IP", "siberia")
	}
	field("BBS_THREAD_NUMBER", s.Presentation.TopThreads)
	field("BBS_CONTENTS_NUMBER", s.Presentation.TopResponses)
	field("BBS_MAX_MENU_THREAD", s.Presentation.MenuThreads)
	field("BBS_DISP_MSEC", "checked")
	c := s.Presentation.Colors
	for _, v := range []struct{ key, value string }{
		{"BBS_TITLE_COLOR", c.Title}, {"BBS_BG_COLOR", c.Background}, {"BBS_MAKETHREAD_COLOR", c.Form}, {"BBS_MENU_COLOR", c.Menu}, {"BBS_THREAD_COLOR", c.Thread}, {"BBS_TEXT_COLOR", c.Text}, {"BBS_NAME_COLOR", c.Name}, {"BBS_SUBJECT_COLOR", c.Subject}, {"BBS_LINK_COLOR", c.Link}, {"BBS_ALINK_COLOR", c.ActiveLink}, {"BBS_VLINK_COLOR", c.VisitedLink},
	} {
		field(v.key, v.value)
	}
	return textcodec.Encode(body.String(), true)
}
