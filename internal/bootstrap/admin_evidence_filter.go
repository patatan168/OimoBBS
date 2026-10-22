// 提出案件の検索・状態・並び順をHTML/APIと署名カーソルで共用する。
package bootstrap

import (
	"cmp"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"oimobbs/internal/disclosure"
)

type evidenceListFilter struct{ Query, State, Sort, Kind string }

func evidenceListRoute(path string) bool {
	return path == "/evidence" || path == "/api/v1/evidence/cases"
}

// readEvidenceListFilter は重複・未知条件を拒否し、空の検索欄も受け付ける。
func readEvidenceListFilter(r *http.Request) (evidenceListFilter, error) {
	f := evidenceListFilter{Sort: "newest", Kind: "posts"}
	bad := &adminFailure{status: 400, code: "INVALID_LIST_QUERY"}
	if len(r.URL.RawQuery) > 4096 {
		return f, bad
	}
	v, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return f, bad
	}
	for name, values := range v {
		if !slices.Contains([]string{"q", "state", "sort", "kind", "limit", "cursor"}, name) || len(values) != 1 {
			return f, bad
		}
	}
	if kind := v.Get("kind"); kind != "" {
		f.Kind = kind
	}
	if !slices.Contains([]string{"posts", "other"}, f.Kind) {
		return f, bad
	}
	f.Query, f.State = strings.TrimSpace(v.Get("q")), v.Get("state")
	if !utf8.ValidString(f.Query) || utf8.RuneCountInString(f.Query) > 128 || len(strings.Fields(f.Query)) > 8 {
		return f, bad
	}
	if !slices.Contains([]string{"", "draft", "preparing", "active", "partial", "releasing", "closed"}, f.State) {
		return f, bad
	}
	if sort := v.Get("sort"); sort != "" {
		f.Sort = sort
	}
	if !slices.Contains([]string{"newest", "oldest", "until"}, f.Sort) {
		return f, bad
	}
	return f, nil
}

func (f evidenceListFilter) Active() bool {
	return f.Query != "" || f.State != "" || f.Sort != "newest"
}
func (f evidenceListFilter) OrderLabel() string {
	return map[string]string{"newest": "作成日時の新しい順", "oldest": "作成日時の古い順", "until": "保全期限が近い順"}[f.Sort]
}

// Values は既定値を省き、同じ条件のカーソル署名と次ページURLをそろえる。
func (f evidenceListFilter) Values() url.Values {
	v := url.Values{}
	if f.Kind == "other" {
		v.Set("kind", "other")
	}
	if f.Query != "" {
		v.Set("q", f.Query)
	}
	if f.State != "" {
		v.Set("state", f.State)
	}
	if f.Sort != "newest" {
		v.Set("sort", f.Sort)
	}
	return v
}

// NextLink は検索・状態・並び順を次ページでも維持する。
func (f evidenceListFilter) NextLink(path string, window adminListWindow) string {
	if window.Next == "" {
		return ""
	}
	v := f.Values()
	v.Set("cursor", window.Next)
	return path + "?" + v.Encode()
}

// matchesEvidenceCase は案件の管理情報だけを検索し、保存した投稿本文を走査しない。
func (r *Repository) matchesEvidenceCase(c disclosure.Case, f evidenceListFilter) bool {
	other := c.Rejected != nil || c.HTTP != nil && c.HTTP.Unbound
	if f.Kind == "other" {
		if !other && c.State != "draft" {
			return false
		}
	} else if other {
		return false
	}
	if f.State != "" && c.State != f.State {
		return false
	}
	fields := []string{c.Number, c.Reason, c.Organization, c.Reference}
	if c.Scope.Thread != 0 {
		fields = append(fields, strconv.FormatUint(uint64(c.Scope.Thread), 10))
	}
	if board := r.posting[c.Scope.Board]; board != nil {
		fields = append(fields, board.publicName, board.slug)
	}
	return adminThreadMatches(strings.Join(fields, "\n"), f.Query)
}

// compare は同時刻の案件もIDで確定し、ページ間の重複・欠落を避ける。
func (f evidenceListFilter) compare(a, b disclosure.Case) int {
	if f.Sort == "until" {
		if n := cmp.Compare(a.Until, b.Until); n != 0 {
			return n
		}
	}
	n := cmp.Compare(a.Created, b.Created)
	if n == 0 {
		n = strings.Compare(a.ID.String(), b.ID.String())
	}
	if f.Sort == "oldest" {
		return n
	}
	return -n
}
