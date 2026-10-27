// 最新スレッド状態から匿名通常投稿と公開DATを構築し、domain.Applyで検算する。
package postinput

import (
	"math"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/textcodec"
	"strings"
	"time"
)

// EndResponse は終了時に追加するシステムレスの表示内容。
type EndResponse struct{ Name, Mail, Body string }

// Limits は板の実効入力上限と表示条件。EndResponses=nilのみ従来の終了レスを使う。
type Limits struct {
	EndResponses                        []EndResponse
	Name, Mail, Title, Body, Lines      uint32
	Noname, EndMessage                  string
	NameRequired, ForceNoname, HideMail bool
}

// BuildContext は板ワーカーが確定する値。入力フォームに上書きさせない。
type BuildContext struct {
	AnonymousID           domain.ID
	DisplayCommands       *[]string
	AllowStrengthen       bool
	SlipNetKey, SlipUAKey domain.Hash
	Network               identity.NetworkClass
	UserAgent             string
	Cap                   *Cap
	RateKeys              []domain.RateKey
	Board                 domain.ID
	SourceIP              string
	Now                   time.Time
	PublicKey             domain.Hash
	Policy                domain.Policy
	Versions              domain.Versions
	Bump                  domain.U64
	Dedup                 domain.Dedup
	Limits                Limits
}

// Cap は上位の認証済み資格。生秘密を持たず、公開表示・非公開ID・版を固定する。
type Cap struct {
	ID       domain.ID
	Name     string
	Revision domain.U64
}

// Build は単一利用者投稿（件数上限では終了systemを含む）を一つのframeにする。
func Build(old *domain.Thread, input Input, c BuildContext) ([]byte, error) {
	prepared, err := BuildPrepared(old, input, c)
	if err != nil {
		return nil, err
	}
	return prepared.Raw, nil
}

// Prepared は同じ構築呼出しで検算したframe・操作・次状態。呼出元へ所有権を渡す。
// 元状態のsliceを変更せず、保存前にframeの完全検証も引き続き行う。
type Prepared struct {
	Raw       []byte
	Frame     store.Frame
	Operation domain.Operation
	Next      *domain.Thread
}

// BuildPrepared は一度のdomain検算結果を構築済みframeと共に返し、破棄・再検算を避ける。
// oldは不変で、返すNextとRawの公開・保存は上位層の耐久境界が成立した後に行う。
func BuildPrepared(old *domain.Thread, input Input, c BuildContext) (*Prepared, error) {
	now := domain.Time(c.Now.UnixNano())
	if c.Board == (domain.ID{}) || now > domain.Time(math.MaxInt64-86400*1e9) {
		return nil, ErrInput
	}
	policy := c.Policy
	if old != nil {
		if old.After.State != "active" || now >= old.Expires || old.Revision == domain.U64(math.MaxUint64) {
			return nil, ErrInput
		}
		policy = old.Policy
	}
	if input.CapOnly {
		if old != nil {
			return nil, ErrInput
		}
		policy.CapOnly = true
	}
	if policy.CapOnly && c.Cap == nil {
		return nil, ErrInput
	}
	if e := CheckDisplayCommands(input.Controls, c.DisplayCommands); e != nil {
		return nil, e
	}
	displayPolicy, e := DisplayPolicy(policy, input.Controls, c.AllowStrengthen)
	if e != nil {
		return nil, e
	}
	if input.Controls != nil && input.Controls.Thread {
		if old != nil {
			return nil, ErrInput
		}
		policy = displayPolicy
	}
	if policy.AutoNext || policy.Pinned {
		return nil, ErrUnsupported
	}
	if old == nil && strings.TrimSpace(input.Title) == "" || old != nil && input.Title != "" {
		return nil, ErrInput
	}
	if e := validateInput(input, c.Limits); e != nil {
		return nil, e
	}
	name := input.Name
	if name == "" || c.Limits.ForceNoname {
		name = c.Limits.Noname
	}
	mail := input.Mail
	if c.Limits.HideMail {
		mail = ""
	}
	post := domain.Post{Number: 1, Kind: "user", Visibility: "visible", Created: now, Name: name, Mail: mail, Body: input.Body, Identity: domain.Identity{Trip: input.Trip, DateText: compat.DateText(c.Now)}, Private: &domain.Private{SourceIP: c.SourceIP, RateKeys: append([]domain.RateKey{}, c.RateKeys...)}}
	if old != nil {
		post.Number = old.After.PostCount + 1
	}
	if c.Cap == nil {
		if e := setDisplay(&post, input, displayPolicy, c); e != nil {
			return nil, e
		}
	}
	if c.Cap != nil {
		if c.Cap.ID == (domain.ID{}) || c.Cap.Revision == 0 || c.Cap.Name == "" {
			return nil, ErrInput
		}
		post.Identity.Cap = c.Cap.Name
		post.Identity.ID, post.Identity.Suffix = "CAP_USER", ""
		id := c.Cap.ID
		post.Private.CapID = &id
	}
	dat, e := compat.DAT(post, input.Title)
	if e != nil {
		return nil, e
	}
	if len(strings.SplitN(string(dat), "<>", 2)[0]) > int(c.Limits.Name) {
		return nil, ErrInput
	}
	post.DATLength = uint32(len(dat))
	d := c.Dedup
	d.PostNumber = post.Number
	op := domain.Operation{Type: "create", Revision: 1, Committed: now, Versions: c.Versions, Actor: domain.Actor{Kind: "anonymous", Reason: "post"}, Dedup: &d, After: domain.After{State: "active", DATGeneration: 1, BumpKind: "normal"}}
	if c.Cap != nil {
		id, rev := c.Cap.ID, c.Cap.Revision
		op.Actor.Kind, op.Actor.ID = "cap", &id
		op.Versions.Cap = &rev
	}
	if old != nil {
		op.Type = "append"
		op.Revision = old.Revision + 1
		op.Versions.Thread = old.Policy.Version
		op.After = old.After
	}
	if op.After.UserCount >= policy.UserPostLimit || uint64(op.After.DATBytes)+uint64(len(dat)) > uint64(policy.DATUserLimit) {
		return nil, ErrInput
	}
	op.After.PostCount++
	op.After.UserCount++
	op.After.DATBytes += domain.U64(len(dat))
	op.After.LastUserAt = now
	if old == nil || !strings.Contains(strings.ToLower(input.Mail), "sage") {
		op.After.BumpKind = "normal"
		op.After.BumpValue = c.Bump
	}
	posts := []domain.Post{post}
	if len(c.Limits.EndResponses) > 2 {
		return nil, ErrInput
	}
	if op.After.UserCount == policy.UserPostLimit {
		endings := c.Limits.EndResponses
		if endings == nil {
			endings = []EndResponse{{Name: "OimoBBS", Body: c.Limits.EndMessage}}
		}
		for _, item := range endings {
			ending := domain.Post{Number: op.After.PostCount + 1, Kind: "system", Visibility: "visible", Created: now, Name: item.Name, Mail: item.Mail, Body: item.Body, Identity: domain.Identity{DateText: compat.DateText(c.Now)}, DATOffset: uint32(len(dat))}
			line, e := compat.DAT(ending, "")
			if e != nil || len(line) > 4096 {
				return nil, ErrInput
			}
			ending.DATLength = uint32(len(line))
			posts = append(posts, ending)
			dat = append(dat, line...)
			op.After.PostCount++
			op.After.DATBytes += domain.U64(len(line))
		}
		op.After.State = "stopped"
		reason := "count"
		op.After.EndReason = &reason
	}
	if old == nil {
		op.Payload, e = domain.MarshalCreate(domain.Create{Title: input.Title, Created: now, Expires: domain.Time(domain.SixMonths(c.Now).UnixNano()), Policy: policy, Posts: posts})
	} else {
		op.Payload, e = domain.MarshalAppend(domain.Append{Posts: posts})
	}
	if e != nil {
		return nil, e
	}
	next, e := domain.Apply(old, op, dat)
	if e != nil {
		return nil, e
	}
	raw, e := domain.MarshalOperation(op)
	if e != nil {
		return nil, e
	}
	frame := store.Frame{FirstSeq: uint64(op.Revision), Records: []store.Record{{ID: domain.NewID(), JSON: raw, DAT: dat}}}
	encoded, err := store.EncodeFrame(frame)
	if err != nil {
		return nil, err
	}
	return &Prepared{encoded, frame, op, next}, nil
}
func validateInput(in Input, limits Limits) error {
	if limits.Name == 0 || limits.Body == 0 || limits.Title == 0 || limits.Lines == 0 || limits.Noname == "" || limits.NameRequired && (in.Name == "" || limits.ForceNoname) {
		return ErrInput
	}
	if strings.TrimSpace(in.Body) == "" || strings.Count(in.Body, "\n")+1 > int(limits.Lines) {
		return ErrInput
	}
	for _, field := range []struct {
		value string
		limit uint32
		body  bool
	}{{in.Name, limits.Name, false}, {in.Mail, limits.Mail, false}, {in.Title, limits.Title, false}, {in.Body, limits.Body, true}} {
		normalized, e := compat.Normalize(field.value, field.body, false)
		if e != nil || normalized != field.value {
			return ErrInput
		}
		data, e := textcodec.Encode(field.value, true)
		if e != nil || len(data) > int(field.limit) {
			return ErrInput
		}
	}
	return nil
}
