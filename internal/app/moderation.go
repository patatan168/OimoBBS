// 管理変更の候補生成と署名証拠付き確定を、投稿と同じ所有列で処理する。
package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// RedactionRange は番号を保つ削除区間。Modeはaboon/transparent、合計256レスまで。
type RedactionRange struct {
	First uint32 `json:"first"`
	Last  uint32 `json:"last"`
	Mode  string `json:"mode"`
}

// ModerationInput は認可済み管理操作。外部HTTP入力へActor/Versionsを直接委ねない。
type ModerationInput struct {
	ID, DeletionID domain.ID
	Type           string
	Ranges         []RedactionRange
	HideTitle      bool
	Expected       domain.U64
	Actor          domain.Actor
	Versions       domain.Versions
	Now            domain.Time
}

// ModerationState は管理候補生成に必要な本文なしの状態。所有列内でだけ呼ぶ。
func (p *PostingLog) ModerationState() (domain.U64, domain.Time, error) {
	if p.stopped || p.expired || p.thread == nil {
		return 0, 0, ErrEvidenceGap
	}
	return p.thread.State().Revision, p.thread.State().Expires, nil
}

// PrepareModeration は旧状態を変更せずredact/hide候補を検算する。
func (p *PostingLog) PrepareModeration(input ModerationInput) ([]byte, error) {
	if p.stopped || p.expired || p.thread == nil || input.ID == (domain.ID{}) || input.DeletionID == (domain.ID{}) || input.Actor.Kind != "admin" {
		return nil, ErrEvidenceGap
	}
	state := p.thread.State()
	if state.Revision != input.Expected || input.Now >= state.Expires {
		return nil, domain.ErrOperation
	}
	after := state.After
	var payload any
	var dat []byte
	switch input.Type {
	case "hide":
		if len(input.Ranges) != 0 || input.HideTitle {
			return nil, domain.ErrOperation
		}
		after.State = "hidden"
		payload = domain.Hide{DeletionID: input.DeletionID}
	case "redact":
		posts, e := moderationPosts(state, input.Ranges, input.HideTitle)
		if e != nil {
			return nil, e
		}
		for i := range posts {
			line, e := moderationDAT(posts[i], state.Lines[posts[i].Number-1], input.HideTitle)
			if e != nil {
				return nil, e
			}
			posts[i].DATOffset = uint32(len(dat))
			posts[i].DATLength = uint32(len(line))
			after.DATBytes = after.DATBytes - domain.U64(len(state.Lines[posts[i].Number-1])) + domain.U64(len(line))
			dat = append(dat, line...)
		}
		after.DATGeneration++
		after.LegacyRangeDisabled = true
		payload = domain.Redact{Posts: posts, HideTitle: input.HideTitle}
	default:
		return nil, domain.ErrOperation
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return nil, e
	}
	versions := input.Versions
	versions.Thread = state.Policy.Version
	op := domain.Operation{Type: input.Type, Revision: state.Revision + 1, Committed: input.Now, Versions: versions, Actor: input.Actor, After: after, Payload: raw}
	raw, e = json.Marshal(op)
	if e != nil {
		return nil, e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Revision), Records: []store.Record{{ID: input.ID, JSON: raw, DAT: dat}}})
	if e != nil {
		return nil, e
	}
	if _, e = store.ValidateThreadFrame(state, frame); e != nil {
		return nil, e
	}
	return frame, nil
}

func moderationPosts(state *domain.Thread, ranges []RedactionRange, hideTitle bool) ([]domain.Post, error) {
	posts := []domain.Post{}
	var previous uint32
	for _, r := range ranges {
		if r.First == 0 || r.Last < r.First || r.Last > state.After.PostCount || r.First <= previous || (r.Mode != "aboon" && r.Mode != "transparent") || uint64(len(posts))+uint64(r.Last-r.First)+1 > 256 {
			return nil, domain.ErrOperation
		}
		previous = r.Last
		for n := r.First; n <= r.Last; n++ {
			post := state.Posts[n-1]
			post.Name = "あぼーん"
			post.Body = "あぼーん"
			post.Mail = ""
			post.Identity = domain.Identity{DateText: "あぼーん"}
			post.Visibility = r.Mode
			posts = append(posts, post)
		}
	}
	if hideTitle && (len(posts) == 0 || posts[0].Number != 1) {
		posts = append([]domain.Post{state.Posts[0]}, posts...)
	}
	if len(posts) == 0 || len(posts) > 256 {
		return nil, domain.ErrOperation
	}
	return posts, nil
}

// ApplyModeration は管理frame専用の署名proposal/decisionを保存し、確定後にだけ公開する。
// HTTP投稿captureを捏造せず、ActorのHMACと対象操作を証明へ束縛する。
func (p *PostingLog) ApplyModeration(ctx context.Context, frame []byte, now domain.Time) PostingResult {
	f, op, e := administrativeFrame(frame)
	if e != nil {
		return PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: e}}
	}
	capture, e := json.Marshal(administrativeCapture{Schema: 1, Actor: op.Actor})
	if e != nil {
		return PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: e}}
	}
	return p.commitFrame(ctx, frame, capture, now, f, op, true)
}

type administrativeCapture struct {
	Schema uint32       `json:"schema"`
	Actor  domain.Actor `json:"actor"`
}

func administrativeFrame(raw []byte) (store.Frame, domain.Operation, error) {
	f, n, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil || n != int64(len(raw)) || len(f.Records) != 1 {
		return f, domain.Operation{}, store.ErrCorrupt
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e == nil && (op.Actor.Kind != "admin" || op.Actor.Validate() != nil || op.Dedup != nil || op.Type == "create" || op.Type == "append" || uint64(op.Revision) != f.FirstSeq) {
		e = errors.New("invalid administrative frame")
	}
	return f, op, e
}

// BlockPublic は先行intentの所有者が公開と投稿の入口を閉じる。所有列内で呼ぶ。
func (p *PostingLog) BlockPublic(blocked bool) {
	if p.expired && !blocked {
		return
	}
	p.blockPublication(blocked)
	if !blocked {
		p.publish()
	}
}

// AdministrativeDigest は台帳が束縛した管理proposalのframeハッシュを返す。
// 現在値の復旧照合後、コピー掃除の対象証明として所有列内で使用する。
func (p *PostingLog) AdministrativeDigest(id domain.ID) (domain.Hash, bool) {
	entry, ok := p.proposals[id]
	return entry.payload.FrameSHA, ok && entry.event.Kind == "thread_admin_proposal"
}

// ModerationApplied は固定操作が指定位置へ耐久保存されたことを確認する。
// 同じIDが別のframeへ再利用されていた場合は成功と見なさない。
func (p *PostingLog) ModerationApplied(id domain.ID, revision domain.U64, deletion domain.ID) bool {
	if p.thread == nil && p.reclaimed == nil {
		return false
	}
	for _, r := range p.records() {
		if r.ID != id || r.Seq != revision {
			continue
		}
		entry, ok := p.proposals[id]
		if !ok || entry.event.Kind != "thread_admin_proposal" || r.FrameSHA != entry.payload.FrameSHA {
			return false
		}
		raw, e := base64.StdEncoding.Strict().DecodeString(entry.payload.Frame)
		if e != nil {
			return false
		}
		_, op, e := administrativeFrame(raw)
		if e != nil {
			return false
		}
		if op.Type == "hide" {
			var v domain.Hide
			return json.Unmarshal(op.Payload, &v) == nil && v.DeletionID == deletion
		}
		return op.Type == "redact"
	}
	return false
}

// PublicStatus は公開GETの状態を所有列内で判定する。削除反映中は503、hide/expireは410。
func (p *PostingLog) PublicStatus(now domain.Time) int {
	if p.PublicExpired(now) {
		return 410
	}
	if p.thread != nil && p.thread.State().After.State == "hidden" {
		return 410
	}
	if p.publicBlocked || p.stopped {
		return 503
	}
	if p.snapshot == nil {
		return 404
	}
	return 200
}

// moderationDAT は確定済みタイトルのbyteを保ち、削除行のタイトル規則だけを適用する。
// 再エスケープによって旧タイトルを変えず、visibleのタイトルのみ削除は空欄とする。
func moderationDAT(post domain.Post, old []byte, hideTitle bool) ([]byte, error) {
	line, e := compat.DAT(post, "")
	if e != nil {
		return nil, e
	}
	before := bytes.Split(bytes.TrimSuffix(old, []byte("\n")), []byte("<>"))
	after := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte("<>"))
	if len(before) != 5 || len(after) != 5 {
		return nil, domain.ErrOperation
	}
	if post.Number == 1 {
		after[4] = before[4]
		if hideTitle {
			if post.Visibility == "visible" {
				copy(after[:4], before[:4])
				after[4] = nil
			} else {
				after[4] = after[3]
			}
		}
	}
	return append(bytes.Join(after, []byte("<>")), '\n'), nil
}

// AdministrativeOperationIDs は先行intentの照合用に管理proposalの固定IDだけを返す。
// 未反映のproposalも含め、所有者が台帳なしで公開再開することを拒否できるようにする。
func (p *PostingLog) AdministrativeOperationIDs() []domain.ID {
	ids := []domain.ID{}
	for id, entry := range p.proposals {
		if entry.event.Kind == "thread_admin_proposal" {
			ids = append(ids, id)
		}
	}
	return ids
}
