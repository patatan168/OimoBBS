// 圧縮snapshotの現在値を、過去操作の再生とは独立して検査する。
package domain

import (
	"bytes"
	"math"
	"net/url"
	"oimobbs/internal/textcodec"
	"slices"
	"strings"
	"time"
)

// ValidateSnapshot は現在の投稿とDAT集計・期限・削除表示を照合する。
// 過去の受理操作との対応やorigin seqの証明は保存層と証拠照合の責務。
func ValidateSnapshot(t *Thread) error {
	if t == nil || t.Revision == 0 || t.Policy.Validate() != nil || len(t.Posts) == 0 || len(t.Posts) > 65536 || len(t.Posts) != len(t.Lines) || uint32(len(t.Posts)) != t.After.PostCount || t.After.DATGeneration == 0 {
		return ErrOperation
	}
	if !slices.Contains([]string{"active", "stopped", "archived"}, t.After.State) || !slices.Contains([]string{"normal", "bottom"}, t.After.BumpKind) {
		return ErrOperation
	}
	if (t.After.State == "active") != (t.After.EndReason == nil) {
		return ErrOperation
	}
	if t.After.EndReason != nil && !slices.Contains([]string{"count", "bytes", "manual", "idle", "age", "prune"}, *t.After.EndReason) {
		return ErrOperation
	}
	created := time.Unix(0, int64(t.Created))
	exp := SixMonths(created)
	if !exp.After(created) || !exp.Equal(time.Unix(0, exp.UnixNano())) || Time(exp.UnixNano()) != t.Expires {
		return ErrOperation
	}
	if t.MoveTarget != "" {
		u, e := url.Parse(t.MoveTarget)
		if e != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(t.MoveTarget, "\r\n\x00") {
			return ErrOperation
		}
	}
	var users uint32
	var size uint64
	var last Time
	for i, p := range t.Posts {
		line := t.Lines[i]
		p.DATOffset = 0
		if p.Number != uint32(i+1) || validatePosts([]Post{p}, line) != nil {
			return ErrOperation
		}
		if p.Kind == "user" {
			users++
			last = p.Created
		}
		if uint64(len(line)) > math.MaxUint64-size {
			return ErrOperation
		}
		size += uint64(len(line))
		if p.Visibility != "visible" {
			if p.Name != "あぼーん" || p.Body != "あぼーん" || p.Mail != "" || p.Identity != (Identity{DateText: "あぼーん"}) || !t.After.LegacyRangeDisabled || t.After.DATGeneration < 2 {
				return ErrOperation
			}
			parts := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte("<>"))
			a, _ := textcodec.Encode("あぼーん", false)
			if !bytes.Equal(parts[0], a) || len(parts[1]) != 0 || !bytes.Equal(parts[2], a) || !bytes.Equal(parts[3], a) {
				return ErrOperation
			}
		}
	}
	if users == 0 || users != t.After.UserCount || last != t.After.LastUserAt || size != uint64(t.After.DATBytes) || t.Posts[0].Kind != "user" || t.Posts[0].Created != t.Created {
		return ErrOperation
	}
	return nil
}

// ValidateStoredPost はpack内の一行を検査する。offsetは呼出し側がブロック内で照合する。
func ValidateStoredPost(p Post, line []byte) error {
	p.DATOffset = 0
	return validatePosts([]Post{p}, line)
}
