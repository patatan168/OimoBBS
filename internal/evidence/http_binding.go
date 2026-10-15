// HTTP観測成分と投稿正本の板・接続元・操作種別を結合する。
package evidence

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"strconv"
	"time"
)

// PostingHTTPObservation はHTTP観測成分なら完全検証して返す。他のcaptureスキーマはnil。
// 戻り値nilは別スキーマの検証完了を意味しない。呼出元の検証器も必ず適用する。
func PostingHTTPObservation(raw []byte) (*HTTPObservation, error) {
	var marker struct {
		Schema      string          `json:"schema"`
		Observation json.RawMessage `json:"observation"`
	}
	if e := json.Unmarshal(raw, &marker); e != nil {
		return nil, e
	}
	if marker.Schema == "form-post-v5" {
		raw = marker.Observation
	} else if marker.Schema != "http-observation-v1" {
		return nil, nil
	}
	if e := ValidateHTTPObservation(raw); e != nil {
		return nil, e
	}
	var observation HTTPObservation
	if e := strictjson.Decode(raw, &observation); e != nil {
		return nil, e
	}
	return &observation, nil
}

// ValidatePosting は観測情報の別投稿への取違えを拒否する。本文の秘密除去の代替ではない。
func (v HTTPObservation) ValidatePosting(owner domain.ID, day uint64, op domain.Operation) error {
	receivedDay, e := strconv.ParseUint(time.Unix(0, int64(v.Received)).UTC().Format("20060102"), 10, 64)
	if e != nil || receivedDay != day || v.BoardID != owner || v.Route == "web_create" && op.Type != "create" || v.Route == "web_reply" && op.Type != "append" {
		return ErrHTTPObservation
	}
	var posts []domain.Post
	switch op.Type {
	case "create":
		var value domain.Create
		if e := strictjson.Decode(op.Payload, &value); e != nil {
			return e
		}
		posts = value.Posts
	case "append":
		var value domain.Append
		if e := strictjson.Decode(op.Payload, &value); e != nil {
			return e
		}
		posts = value.Posts
	default:
		return ErrHTTPObservation
	}
	user := false
	for _, post := range posts {
		if post.Kind != "user" {
			continue
		}
		user = true
		if post.Private == nil || post.Private.SourceIP != v.Resolved.IP {
			return ErrHTTPObservation
		}
	}
	if !user {
		return ErrHTTPObservation
	}
	return nil
}
