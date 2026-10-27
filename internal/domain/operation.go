// WAL操作の厳密な型と、復旧時にも適用する状態遷移を定義する。
package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
	"reflect"
	"slices"
	"strings"
	"time"
)

var ErrOperation = errors.New("invalid thread operation")

// MaxStoredPostBytes はpackの外枠・JSON・DATを合わせた一レスの上限。
const MaxStoredPostBytes = 512 << 10

type Versions struct {
	Site   U64  `json:"site"`
	Board  U64  `json:"board"`
	Thread U64  `json:"thread"`
	Cap    *U64 `json:"cap"`
}
type Actor struct {
	Kind        string  `json:"kind"`
	ID          *ID     `json:"id"`
	Reason      string  `json:"reason_code"`
	Request     *Hash   `json:"request_hmac"`
	Idempotency *Hash   `json:"idempotency_hmac"`
	KeyID       *uint32 `json:"key_id"`
}
type After struct {
	State               string  `json:"state"`
	UserCount           uint32  `json:"user_count"`
	PostCount           uint32  `json:"post_count"`
	DATBytes            U64     `json:"dat_bytes"`
	DATGeneration       U64     `json:"dat_generation"`
	LegacyRangeDisabled bool    `json:"legacy_range_disabled"`
	LastUserAt          Time    `json:"last_user_at_ns"`
	BumpKind            string  `json:"bump_kind"`
	BumpValue           U64     `json:"bump_value"`
	EndReason           *string `json:"end_reason"`
}
type Dedup struct {
	Mode       string `json:"mode"`
	KeyID      uint32 `json:"key_id"`
	Subject    Hash   `json:"subject_hmac"`
	RequestID  *Hash  `json:"request_id_hmac"`
	Request    Hash   `json:"request_hmac"`
	Expires    Time   `json:"expires_at_ns"`
	PostNumber uint32 `json:"post_number"`
}
type Identity struct {
	Trip     string `json:"trip"`
	Cap      string `json:"cap"`
	ID       string `json:"id"`
	Slip     string `json:"slip"`
	PublicIP string `json:"public_ip"`
	Host     string `json:"host"`
	Region   string `json:"region"`
	Suffix   string `json:"suffix"`
	DateText string `json:"date_text"`
}
type RateKey struct {
	Rule    ID     `json:"rule_id"`
	KeyID   uint32 `json:"key_id"`
	Subject Hash   `json:"subject_hmac"`
	Cost    uint32 `json:"cost"`
}
type Private struct {
	SourceIP string    `json:"source_ip"`
	CapID    *ID       `json:"cap_id"`
	RateKeys []RateKey `json:"rate_keys"`
}
type Post struct {
	Number     uint32   `json:"number"`
	Kind       string   `json:"kind"`
	Visibility string   `json:"visibility"`
	Created    Time     `json:"created_at_ns"`
	Name       string   `json:"name"`
	Mail       string   `json:"mail"`
	Body       string   `json:"body"`
	Identity   Identity `json:"identity"`
	Private    *Private `json:"private"`
	DATOffset  uint32   `json:"dat_offset"`
	DATLength  uint32   `json:"dat_length"`
}
type Policy struct {
	CapOnly         bool     `json:"cap_only,omitempty"`
	Version         U64      `json:"version"`
	IDMode          string   `json:"id_mode"`
	SlipMode        string   `json:"slip_mode"`
	RequireID       bool     `json:"require_id"`
	RequireSlipHash bool     `json:"require_slip_hash"`
	RequirePublicIP bool     `json:"require_public_ip"`
	UserPostLimit   uint32   `json:"user_post_limit"`
	DATUserLimit    U64      `json:"dat_user_limit"`
	Commands        []string `json:"allowed_commands"`
	AutoNext        bool     `json:"auto_next"`
	Pinned          bool     `json:"pinned"`
}
type Operation struct {
	Type      string          `json:"type"`
	Revision  U64             `json:"revision"`
	Committed Time            `json:"committed_at_ns"`
	Versions  Versions        `json:"policy_versions"`
	Actor     Actor           `json:"actor"`
	After     After           `json:"after"`
	Dedup     *Dedup          `json:"dedup"`
	Payload   json.RawMessage `json:"payload"`
}
type Create struct {
	Title   string `json:"title"`
	Created Time   `json:"created_at_ns"`
	Expires Time   `json:"expires_at_ns"`
	Policy  Policy `json:"policy"`
	Posts   []Post `json:"posts"`
}
type Append struct {
	Posts []Post `json:"posts"`
}
type Redact struct {
	Posts     []Post `json:"posts"`
	HideTitle bool   `json:"hide_title"`
}
type Stop struct {
	Posts  []Post `json:"posts"`
	Reason string `json:"reason"`
}
type Archive struct {
	Reason string `json:"reason"`
}
type Move struct {
	Target string `json:"target"`
}
type Hide struct {
	DeletionID ID `json:"deletion_id"`
}
type UpdatePolicy struct {
	Policy Policy `json:"policy"`
}

// Thread は非公開データを含む保存状態。HTTP DTOとして使用しない。
type Thread struct {
	Revision         U64
	Title            string
	Created, Expires Time
	Policy           Policy
	After            After
	Posts            []Post
	Lines            [][]byte
	MoveTarget       string
}

// ParseOperation は種別に応じたpayloadの完全スキーマを検査する。
func ParseOperation(b []byte) (Operation, error) {
	var o Operation
	if e := strictjson.Decode(b, &o); e != nil {
		return o, e
	}
	var p any
	switch o.Type {
	case "create":
		p = &Create{}
	case "append":
		p = &Append{}
	case "redact":
		p = &Redact{}
	case "stop":
		p = &Stop{}
	case "archive":
		p = &Archive{}
	case "move_link":
		p = &Move{}
	case "hide":
		p = &Hide{}
	case "update_policy":
		p = &UpdatePolicy{}
	default:
		return o, ErrOperation
	}
	if e := strictjson.Decode(o.Payload, p); e != nil {
		return o, e
	}
	return o, nil
}

// ApplyEncoded は操作の外形とpayloadを厳密検査して候補へ適用する。
// 復号した操作も返し、同じ保存処理で再送記録のために再解析することを避ける。
// 失敗時に元状態は変更せず、返した候補は公開しない。
func ApplyEncoded(old *Thread, raw, dat []byte) (*Thread, Operation, error) {
	var op Operation
	if err := strictjson.Decode(raw, &op); err != nil {
		return nil, op, err
	}
	next, err := Apply(old, op, dat)
	return next, op, err
}

func (p Policy) Validate() error {
	if p.Version == 0 || !slices.Contains([]string{"required", "optional", "hidden"}, p.IDMode) || !slices.Contains([]string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"}, p.SlipMode) || p.UserPostLimit == 0 || p.UserPostLimit >= math.MaxUint32 || p.DATUserLimit == 0 || p.DATUserLimit > 8<<20 || p.AutoNext || p.Commands == nil {
		return ErrOperation
	}
	if p.IDMode == "hidden" && p.RequireID {
		return ErrOperation
	}
	seen := map[string]bool{}
	for _, c := range p.Commands {
		if seen[c] || !slices.Contains([]string{"extend", "id", "slip", "soko", "status", "chkbbx", "rebuild", "stop"}, c) {
			return ErrOperation
		}
		seen[c] = true
	}
	return nil
}

// Apply は全操作を候補状態で検算する。失敗時に元の状態を変更しない。
func Apply(old *Thread, o Operation, dat []byte) (*Thread, error) {
	if e := o.validateCommon(old); e != nil {
		return nil, e
	}
	n := &Thread{}
	if old != nil {
		*n = *old
		// 一操作の追記は最大3レス。clone直後のappendによる全履歴の再確保を避ける。
		extra := 0
		if o.Type == "append" || o.Type == "stop" {
			extra = 3
		}
		if extra == 0 {
			n.Posts = slices.Clone(old.Posts)
			n.Lines = slices.Clone(old.Lines)
		} else {
			n.Posts = make([]Post, len(old.Posts), len(old.Posts)+extra)
			copy(n.Posts, old.Posts)
			n.Lines = make([][]byte, len(old.Lines), len(old.Lines)+extra)
			copy(n.Lines, old.Lines)
		}
	}
	var posts []Post
	switch o.Type {
	case "create":
		var p Create
		if e := strictjson.Decode(o.Payload, &p); e != nil {
			return nil, e
		}
		if old != nil || p.Created != o.Committed || p.Policy.Version != 1 || p.Policy.Validate() != nil || p.Title == "" {
			return nil, ErrOperation
		}
		at := time.Unix(0, int64(p.Created))
		exp := SixMonths(at)
		if !exp.After(at) || !exp.Equal(time.Unix(0, exp.UnixNano())) || p.Expires != Time(exp.UnixNano()) {
			return nil, ErrOperation
		}
		n.Title = p.Title
		n.Created = p.Created
		n.Expires = p.Expires
		n.Policy = p.Policy
		n.After = After{State: "active", DATGeneration: 1, BumpKind: "normal"}
		posts = p.Posts
	case "append":
		var p Append
		if e := strictjson.Decode(o.Payload, &p); e != nil {
			return nil, e
		}
		if n.After.State != "active" {
			return nil, ErrOperation
		}
		posts = p.Posts
	case "stop":
		var p Stop
		if e := strictjson.Decode(o.Payload, &p); e != nil {
			return nil, e
		}
		if n.After.State != "active" || !slices.Contains([]string{"count", "bytes", "manual"}, p.Reason) || len(p.Posts) != 1 || p.Posts[0].Kind != "system" {
			return nil, ErrOperation
		}
		n.After.State = "stopped"
		n.After.EndReason = &p.Reason
		posts = p.Posts
	case "redact":
		var p Redact
		if e := strictjson.Decode(o.Payload, &p); e != nil {
			return nil, e
		}
		if e := replacePosts(n, p, dat); e != nil {
			return nil, e
		}
	case "archive":
		var p Archive
		if e := strictjson.Decode(o.Payload, &p); e != nil {
			return nil, e
		}
		if n.After.State != "active" && n.After.State != "stopped" || !slices.Contains([]string{"manual", "idle", "age", "prune", "count", "bytes"}, p.Reason) {
			return nil, ErrOperation
		}
		if n.After.State == "active" && (p.Reason == "count" || p.Reason == "bytes") {
			return nil, ErrOperation
		}
		if n.After.State == "stopped" && p.Reason != "manual" && (n.After.EndReason == nil || p.Reason != *n.After.EndReason) {
			return nil, ErrOperation
		}
		n.After.State = "archived"
		n.After.EndReason = &p.Reason
	case "move_link":
		var p Move
		if e := strictjson.Decode(o.Payload, &p); e != nil {
			return nil, e
		}
		u, e := url.Parse(p.Target)
		if e != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(p.Target, "\r\n\x00") {
			return nil, ErrOperation
		}
		n.MoveTarget = p.Target
	case "hide":
		var p Hide
		if e := strictjson.Decode(o.Payload, &p); e != nil {
			return nil, e
		}
		n.After.State = "hidden"
	case "update_policy":
		var p UpdatePolicy
		if e := strictjson.Decode(o.Payload, &p); e != nil {
			return nil, e
		}
		if n.Policy.Version == U64(math.MaxUint64) || p.Policy.Version != n.Policy.Version+1 || p.Policy.Validate() != nil || p.Policy.CapOnly != n.Policy.CapOnly {
			return nil, ErrOperation
		}
		n.Policy = p.Policy
	default:
		return nil, ErrOperation
	}
	if posts != nil {
		if e := appendPosts(n, o, posts, dat); e != nil {
			return nil, e
		}
	} else if o.Type != "redact" && len(dat) != 0 {
		return nil, ErrOperation
	}
	if !reflect.DeepEqual(n.After, o.After) {
		return nil, fmt.Errorf("%w: after mismatch", ErrOperation)
	}
	n.Revision = o.Revision
	return n, nil
}
func (o Operation) validateCommon(old *Thread) error {
	if o.Revision == 0 || o.Versions.Site == 0 || o.Versions.Board == 0 {
		return ErrOperation
	}
	if old == nil {
		if o.Type != "create" || o.Revision != 1 || o.Versions.Thread != 0 {
			return ErrOperation
		}
	} else {
		if old.Revision == U64(math.MaxUint64) || o.Revision != old.Revision+1 || o.Versions.Thread != old.Policy.Version || old.After.State == "hidden" || o.Type == "create" {
			return ErrOperation
		}
	}
	if err := o.Actor.Validate(); err != nil {
		return err
	}
	a := o.Actor
	user := o.Type == "create" || o.Type == "append"
	if user {
		if a.Kind != "anonymous" && a.Kind != "cap" || o.Dedup == nil {
			return ErrOperation
		}
		d := o.Dedup
		duration := int64(30 * time.Second)
		if d.Mode == "explicit" {
			duration = int64(24 * time.Hour)
			if d.RequestID == nil {
				return ErrOperation
			}
		} else if d.Mode != "implicit" || d.RequestID != nil {
			return ErrOperation
		}
		if d.KeyID == 0 || d.PostNumber == 0 || int64(o.Committed) > math.MaxInt64-duration || d.Expires != o.Committed+Time(duration) {
			return ErrOperation
		}
	} else {
		if o.Dedup != nil {
			return ErrOperation
		}
		if o.Type == "stop" || o.Type == "archive" {
			if a.Kind != "admin" && a.Kind != "system" && a.Kind != "cap" {
				return ErrOperation
			}
		} else if a.Kind != "admin" {
			return ErrOperation
		}
	}
	return nil
}
func reasonCode(s string) bool {
	if len(s) < 1 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func validatePosts(posts []Post, dat []byte) error {
	if len(posts) < 1 || len(posts) > 256 {
		return ErrOperation
	}
	offset := uint64(0)
	var prev uint32
	for _, p := range posts {
		if p.Number <= prev || uint64(p.DATOffset) != offset || p.DATLength == 0 || uint64(p.DATLength) > uint64(len(dat))-offset {
			return ErrOperation
		}
		encoded, err := json.Marshal(p)
		if err != nil || uint64(len(encoded))+uint64(p.DATLength)+32 > MaxStoredPostBytes {
			return ErrOperation
		}
		prev = p.Number
		line := dat[offset : offset+uint64(p.DATLength)]
		offset += uint64(p.DATLength)
		if !validDATLine(line) {
			return ErrOperation
		}
		if !slices.Contains([]string{"visible", "aboon", "transparent"}, p.Visibility) {
			return ErrOperation
		}
		switch p.Kind {
		case "user":
			if p.Private == nil || p.Private.RateKeys == nil || len(p.Private.RateKeys) > 16 {
				return ErrOperation
			}
			ip, e := netip.ParseAddr(p.Private.SourceIP)
			if e != nil || ip.Zone() != "" || ip.Unmap().String() != p.Private.SourceIP {
				return ErrOperation
			}
			for _, r := range p.Private.RateKeys {
				if r.Rule == (ID{}) || r.KeyID == 0 || r.Cost == 0 {
					return ErrOperation
				}
			}
		case "system":
			if p.Private != nil {
				return ErrOperation
			}
		default:
			return ErrOperation
		}
	}
	if offset != uint64(len(dat)) {
		return ErrOperation
	}
	return nil
}
func appendPosts(n *Thread, o Operation, posts []Post, dat []byte) error {
	if e := validatePosts(posts, dat); e != nil {
		return e
	}
	user := o.Type == "create" || o.Type == "append"
	if len(posts) > 3 || !user && len(posts) > 2 || user && posts[0].Kind != "user" {
		return ErrOperation
	}
	for i, p := range posts {
		if n.After.PostCount == math.MaxUint32 || p.Number != n.After.PostCount+1 || p.Visibility != "visible" || p.Created != o.Committed {
			return ErrOperation
		}
		if i > 0 && p.Kind != "system" {
			return ErrOperation
		}
		if p.Kind == "user" {
			if n.Policy.CapOnly && o.Actor.Kind != "cap" {
				return ErrOperation
			}
			if o.Actor.Kind == "cap" {
				if o.Versions.Cap == nil || *o.Versions.Cap == 0 || p.Private.CapID == nil || *p.Private.CapID != *o.Actor.ID || p.Identity.Cap == "" || p.Identity.ID != "CAP_USER" || p.Identity.Suffix != "" {
					return ErrOperation
				}
			} else if o.Versions.Cap != nil || p.Private.CapID != nil || p.Identity.Cap != "" {
				return ErrOperation
			}
			if n.After.UserCount >= n.Policy.UserPostLimit {
				return ErrOperation
			}
			n.After.UserCount++
			n.After.LastUserAt = o.Committed
			if o.Dedup.PostNumber != p.Number {
				return ErrOperation
			}
		} else if p.DATLength > 4096 {
			return ErrOperation
		}
		line := bytes.Clone(dat[p.DATOffset : uint64(p.DATOffset)+uint64(p.DATLength)])
		n.Posts = append(n.Posts, p)
		n.Lines = append(n.Lines, line)
		n.After.PostCount++
		if uint64(n.After.DATBytes) > math.MaxUint64-uint64(len(line)) {
			return ErrOperation
		}
		n.After.DATBytes += U64(len(line))
	}
	if user {
		if o.After.BumpKind != "normal" && o.After.BumpKind != "bottom" {
			return ErrOperation
		}
		n.After.BumpKind = o.After.BumpKind
		n.After.BumpValue = o.After.BumpValue
		if n.After.UserCount == n.Policy.UserPostLimit {
			n.After.State = "stopped"
			reason := "count"
			n.After.EndReason = &reason
		} else if len(posts) != 1 {
			return ErrOperation
		}
		used := n.After.DATBytes
		for _, system := range posts[1:] {
			used -= U64(system.DATLength)
		}
		if used > n.Policy.DATUserLimit {
			return ErrOperation
		}
	}
	return nil
}
func replacePosts(n *Thread, p Redact, dat []byte) error {
	if e := validatePosts(p.Posts, dat); e != nil {
		return e
	}
	if n.After.DATGeneration == U64(math.MaxUint64) || p.HideTitle && p.Posts[0].Number != 1 {
		return ErrOperation
	}
	changed := false
	for _, post := range p.Posts {
		if post.Number > n.After.PostCount {
			return ErrOperation
		}
		i := int(post.Number) - 1
		old := n.Posts[i]
		if old.Kind != post.Kind || old.Created != post.Created || !reflect.DeepEqual(old.Private, post.Private) {
			return ErrOperation
		}
		if post.Visibility == "visible" {
			if !p.HideTitle || post.Number != 1 || post.Name != old.Name || post.Body != old.Body || post.Mail != old.Mail || post.Identity != old.Identity || post.Visibility != old.Visibility {
				return ErrOperation
			}
		} else {
			if post.Name != "あぼーん" || post.Body != "あぼーん" || post.Mail != "" || post.Identity != (Identity{DateText: "あぼーん"}) {
				return ErrOperation
			}
		}
		line := bytes.Clone(dat[post.DATOffset : uint64(post.DATOffset)+uint64(post.DATLength)])
		if err := validateReplacementLine(n.Lines[i], line, post, p.HideTitle); err != nil {
			return err
		}
		changed = changed || !bytes.Equal(line, n.Lines[i]) || post.Visibility != old.Visibility
		n.After.DATBytes = n.After.DATBytes - U64(len(n.Lines[i])) + U64(len(line))
		n.Posts[i] = post
		n.Lines[i] = line
	}
	if !changed {
		return ErrOperation
	}
	if p.HideTitle {
		n.Title = ""
	}
	n.After.DATGeneration++
	n.After.LegacyRangeDisabled = true
	return nil
}

// Validate は操作者の種別と監査HMACの必須条件を検証する。
func (a Actor) Validate() error {
	if !reasonCode(a.Reason) {
		return ErrOperation
	}
	switch a.Kind {
	case "anonymous", "system":
		if a.ID != nil {
			return ErrOperation
		}
	case "cap", "admin":
		if a.ID == nil {
			return ErrOperation
		}
	default:
		return ErrOperation
	}
	if a.Kind == "admin" {
		if a.Request == nil || a.Idempotency == nil || a.KeyID == nil || *a.KeyID == 0 {
			return ErrOperation
		}
	} else if a.Request != nil || a.Idempotency != nil || a.KeyID != nil {
		return ErrOperation
	}
	return nil
}

// validateReplacementLine は削除行に旧本文を混入させず、タイトルだけの変更を分ける。
func validateReplacementLine(old, next []byte, post Post, hideTitle bool) error {
	before := bytes.Split(bytes.TrimSuffix(old, []byte("\n")), []byte("<>"))
	after := bytes.Split(bytes.TrimSuffix(next, []byte("\n")), []byte("<>"))
	if len(before) != 5 || len(after) != 5 {
		return ErrOperation
	}
	if post.Visibility == "visible" {
		if len(after[4]) != 0 {
			return ErrOperation
		}
		for i := 0; i < 4; i++ {
			if !bytes.Equal(before[i], after[i]) {
				return ErrOperation
			}
		}
		return nil
	}
	aboon, _ := textcodec.Encode("あぼーん", false)
	if !bytes.Equal(after[0], aboon) || len(after[1]) != 0 || !bytes.Equal(after[2], aboon) || !bytes.Equal(after[3], aboon) {
		return ErrOperation
	}
	title := []byte{}
	if post.Number == 1 {
		title = before[4]
		if hideTitle {
			title = aboon
		}
	}
	if !bytes.Equal(after[4], title) {
		return ErrOperation
	}
	return nil
}
