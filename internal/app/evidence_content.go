// 受理原本の選択contentへ確定DATと公開項目だけを投影する。
package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// publicEvidencePost は公開部の許可リスト。Privateや受理枠を含めない。
type publicEvidencePost struct {
	Number     uint32          `json:"number"`
	Kind       string          `json:"kind"`
	Visibility string          `json:"visibility"`
	Created    domain.Time     `json:"created_at_ns"`
	Name       string          `json:"name"`
	Mail       string          `json:"mail"`
	Body       string          `json:"body"`
	Identity   domain.Identity `json:"identity"`
}

// projectAcceptedContent は秘密除去済み入力と、同じ受理操作の公開部を区別して返す。
// frameの対応が不一致なら、部分的な本文を返さずエラーにする。
func projectAcceptedContent(p postingProposal, inputRaw json.RawMessage) (map[string]any, error) {
	var input struct {
		Name  string `json:"name"`
		Mail  string `json:"mail"`
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	if e := json.Unmarshal(inputRaw, &input); e != nil {
		return nil, e
	}
	f, op, e := acceptedEvidenceFrame(p)
	if e != nil {
		return nil, e
	}
	posts, title, e := acceptedPublicPosts(op)
	if e != nil {
		return nil, e
	}
	public := make([]publicEvidencePost, 0, len(posts))
	for _, post := range posts {
		public = append(public, publicEvidencePost{post.Number, post.Kind, post.Visibility, post.Created, post.Name, post.Mail, post.Body, post.Identity})
	}
	var titleMissing *string
	if title == nil {
		reason := "not_in_append_operation"
		titleMissing = &reason
	}
	return map[string]any{"name": input.Name, "mail": input.Mail, "title": input.Title, "body": input.Body, "body_sha256": domain.Hash(sha256.Sum256([]byte(input.Body))), "public_title": title, "public_title_missing_reason": titleMissing, "public_posts": public, "dat_base64": base64.StdEncoding.EncodeToString(f.Records[0].DAT), "dat_sha256": domain.Hash(sha256.Sum256(f.Records[0].DAT))}, nil
}

// acceptedEvidenceFrame は選択出力の元frameを読み、proposalの固定対応を照合する。
func acceptedEvidenceFrame(p postingProposal) (store.Frame, domain.Operation, error) {
	frame, e := base64.StdEncoding.Strict().DecodeString(p.Frame)
	if e != nil {
		return store.Frame{}, domain.Operation{}, e
	}
	f, op, e := postingFrame(frame)
	if e != nil || sha256.Sum256(frame) != p.FrameSHA || f.Records[0].ID != p.OperationID || op.Revision != p.ThreadSeq || op.Committed != p.Committed {
		return store.Frame{}, domain.Operation{}, ErrEvidenceGap
	}
	return f, op, nil
}

// acceptedPublicPosts は確定操作の公開投稿と、作成操作で保存された件名を取り出す。
// 返信操作に件名は保存されないため、現在の公開スレッドから補完しない。
func acceptedPublicPosts(op domain.Operation) ([]domain.Post, *string, error) {
	if op.Type == "create" {
		var create domain.Create
		e := strictjson.Decode(op.Payload, &create)
		return create.Posts, &create.Title, e
	}
	var appendPost domain.Append
	e := strictjson.Decode(op.Payload, &appendPost)
	return appendPost.Posts, nil, e
}
