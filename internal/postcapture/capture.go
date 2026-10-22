// Package postcapture は匿名通常投稿の入力・接続・主体と保存frameを結合する。
// 現行form-post-v8だけを受け付け、過去の投稿保存形式を読み替えない。
package postcapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"strings"
)

const Schema = "form-post-v8"

// CapEvidence は署名付き受理記録へ束縛する資格版。秘密/hashは含めない。
type CapEvidence struct {
	ID       domain.ID  `json:"id"`
	Revision domain.U64 `json:"revision"`
	Name     string     `json:"display_name"`
	KeyID    uint32     `json:"key_id"`
}

var ErrCapture = errors.New("posting capture mismatch")

// Display は入力から公開名・mailを確定した表示条件。認可の代用にはしない。
type Display struct {
	Noname      string `json:"noname"`
	ForceNoname bool   `json:"force_noname"`
	HideMail    bool   `json:"hide_mail"`
}

// TokenEvidence は検証済みCookieの用途別HMACと追加の受理枠。署名値・ID原文を含めない。
type TokenEvidence struct {
	Subject domain.Hash    `json:"subject_hmac"`
	Rate    domain.RateKey `json:"rate_key"`
}

// Capture は再利用可能なCookieやID原文を含めない。
type Capture struct {
	Token           *TokenEvidence           `json:"token"`
	Cap             *CapEvidence             `json:"cap"`
	Overrides       []domain.ID              `json:"overrides"`
	Schema          string                   `json:"schema"`
	Completeness    string                   `json:"completeness"`
	Observation     evidence.HTTPObservation `json:"observation"`
	Input           postinput.Input          `json:"input"`
	Target          domain.U64               `json:"target_key"`
	TokenValidation string                   `json:"token_validation"`
	SubjectSource   string                   `json:"subject_source"`
	Dedup           domain.Dedup             `json:"dedup"`
	Versions        domain.Versions          `json:"policy_versions"`
	Display         Display                  `json:"display"`
	Committed       domain.Time              `json:"committed_at_ns"`
	BodySHA         domain.Hash              `json:"body_sha256"`
	DATSHA          domain.Hash              `json:"dat_sha256"`
	FrameSHA        domain.Hash              `json:"frame_sha256"`
	TextCodec       string                   `json:"text_codec_version"`
	Renderer        string                   `json:"renderer_profile"`
}

// New は実際の候補frameからhashと版を取得し、入力との照合後だけ保存JSONを返す。
func New(observation evidence.HTTPObservation, input postinput.Input, target uint64, display Display, frame []byte) ([]byte, error) {
	return newCapture(observation, input, target, display, frame, nil)
}

// NewWithCap は認証済み資格をframeと同時に検証し、秘密なしのv3記録を作る。
func NewWithCap(observation evidence.HTTPObservation, input postinput.Input, target uint64, display Display, frame []byte, cap CapEvidence) ([]byte, error) {
	return newCapture(observation, input, target, display, frame, &cap)
}

func newCapture(observation evidence.HTTPObservation, input postinput.Input, target uint64, display Display, frame []byte, cap *CapEvidence) ([]byte, error) {
	f, op, e := readFrame(frame)
	if e != nil {
		return nil, e
	}
	c := Capture{Schema: Schema, Cap: cap, Overrides: []domain.ID{}, Completeness: "partial", Observation: observation, Input: input, Target: domain.U64(target), TokenValidation: "not_checked", SubjectSource: "ip", Dedup: *op.Dedup, Versions: op.Versions, Display: display, Committed: op.Committed, BodySHA: sha256.Sum256([]byte(input.Body)), DATSHA: sha256.Sum256(f.Records[0].DAT), FrameSHA: sha256.Sum256(frame), TextCodec: "sjis-compat-v1", Renderer: "dat-v1"}
	if cap != nil {
		c.Renderer = "dat-cap-v2"
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, e
	}
	validated, e := decode(raw)
	if e != nil {
		return nil, e
	}
	if e = validateFrame(validated, f, op, frame, target); e != nil {
		return nil, e
	}
	return raw, nil
}

// Validate は現行form成分と従来HTTP観測成分だけを厳密検証する。未知版は拒否する。
func Validate(raw []byte) error {
	schema, e := schemaOf(raw)
	if e != nil {
		return e
	}
	if schema == "http-observation-v4" {
		return evidence.ValidateHTTPObservation(raw)
	}
	if schema != Schema {
		return ErrCapture
	}
	_, e = decode(raw)
	return e
}
func schemaOf(raw []byte) (string, error) {
	var marker struct {
		Schema string `json:"schema"`
	}
	e := json.Unmarshal(raw, &marker)
	return marker.Schema, e
}

type decodedCapture struct{ Capture }

func decode(raw []byte) (decodedCapture, error) {
	var c decodedCapture
	if len(raw) > 512<<10 {
		return c, ErrCapture
	}
	if err := strictjson.Decode(raw, &c.Capture); err != nil {
		return c, err
	}
	return validateCapture(c)
}

// validateCapture は完全型で復号済みの値の業務制約を検査する。呼出しをまたいで保持しない。
func validateCapture(c decodedCapture) (decodedCapture, error) {
	if c.Schema != Schema || c.Completeness != "partial" || c.SubjectSource != "ip" || c.TextCodec != "sjis-compat-v1" || (c.Renderer != "dat-v1" && (c.Renderer != "dat-cap-v2" || c.Cap == nil)) || (c.Observation.Route != "bbs_post" && c.Observation.Route != "web_create" && c.Observation.Route != "web_reply") {
		return c, ErrCapture
	}
	if c.Overrides == nil || len(c.Overrides) > 0 && !validOverrides(c.Overrides) {
		return c, ErrCapture
	}
	if c.Cap != nil && (c.Cap.ID == (domain.ID{}) || c.Cap.Revision != 1 || c.Cap.KeyID != 9 || c.Cap.Name == "") {
		return c, ErrCapture
	}
	switch c.TokenValidation {
	case "valid":
		if c.Token == nil || c.Token.Subject == (domain.Hash{}) || c.Token.Rate.Rule == (domain.ID{}) || c.Token.Rate.Subject == (domain.Hash{}) || c.Token.Rate.KeyID != 7 || c.Token.Rate.Cost != 1 {
			return c, ErrCapture
		}
	case "not_checked", "absent", "invalid":
		if c.Token != nil {
			return c, ErrCapture
		}
	default:
		return c, ErrCapture
	}
	if e := evidence.ValidateHTTPObservationValue(c.Observation); e != nil {
		return c, e
	}
	for _, v := range []struct {
		s    string
		body bool
	}{{c.Input.Name, false}, {c.Input.Mail, false}, {c.Input.Title, false}, {c.Input.Body, true}, {c.Display.Noname, false}} {
		normalized, e := compat.Normalize(v.s, v.body, false)
		if e != nil || normalized != v.s {
			return c, ErrCapture
		}
	}
	if c.Observation.Route == "web_create" && c.Target != 0 || c.Observation.Route == "web_reply" && c.Target == 0 {
		return c, ErrCapture
	}
	if c.Input.CapOnly && (c.Target != 0 || c.Cap == nil) {
		return c, ErrCapture
	}
	if strings.TrimSpace(c.Input.Body) == "" || c.Target == 0 && strings.TrimSpace(c.Input.Title) == "" || c.Target != 0 && c.Input.Title != "" || strings.ContainsAny(c.Input.Name, "◆★●") || strings.Contains(strings.ToLower(c.Input.Mail), "#cap:") || c.Display.Noname == "" {
		return c, ErrCapture
	}
	if c.BodySHA != sha256.Sum256([]byte(c.Input.Body)) || c.Dedup.KeyID != 8 || c.Dedup.PostNumber == 0 || c.Versions.Site == 0 || c.Versions.Board == 0 || c.Committed <= 0 || c.Input.Credential == (domain.Hash{}) {
		return c, ErrCapture
	}
	if !reflect.DeepEqual(c.Input.RequestID, c.Dedup.RequestID) || c.Dedup.Mode != "implicit" && c.Dedup.Mode != "explicit" || (c.Input.RequestID != nil) != (c.Dedup.Mode == "explicit") {
		return c, ErrCapture
	}
	duration := domain.Time(30 * 1e9)
	if c.Dedup.Mode == "explicit" {
		duration = 86400 * 1e9
	}
	if c.Dedup.Expires <= c.Committed || c.Dedup.Expires-c.Committed != duration {
		return c, ErrCapture
	}
	return c, nil
}

// ValidateKey は保存済み用途鍵でIP主体・要求HMACを再計算する。旧観測成分は対象外。
func ValidateKey(raw []byte, key domain.Hash) error {
	_, err := ValidateKeyAndMetadata(raw, key)
	return err
}

// ValidateFrame は保存前と復旧時の両方で入力・確定Post・DAT・frameの対応を検証する。
// 別スキーマは呼出元の専用validatorへ任せる。返信は確定スレッドキーも一致が必要。
func ValidateFrame(raw, frame []byte, threadKey uint64) error {
	schema, e := schemaOf(raw)
	if e != nil {
		return e
	}
	if schema != Schema {
		return nil
	}
	c, e := decode(raw)
	if e != nil {
		return e
	}
	f, op, e := readFrame(frame)
	if e != nil {
		return e
	}
	return validateFrame(c, f, op, frame, threadKey)
}

// validateFrame は検査済みcaptureと復号済みframeを照合する。新規構築時の再復号を省く。
func validateFrame(c decodedCapture, f store.Frame, op domain.Operation, frame []byte, threadKey uint64) error {
	if c.FrameSHA != sha256.Sum256(frame) || c.DATSHA != sha256.Sum256(f.Records[0].DAT) || c.Committed != op.Committed || !reflect.DeepEqual(c.Versions, op.Versions) || !reflect.DeepEqual(c.Dedup, *op.Dedup) {
		return ErrCapture
	}
	if op.Type == "create" {
		var created domain.Create
		if e := strictjson.Decode(op.Payload, &created); e != nil || created.Policy.CapOnly != c.Input.CapOnly {
			return ErrCapture
		}
	}
	posts, title, e := operationPosts(op)
	if e != nil {
		return e
	}
	if op.Type == "create" && c.Target != 0 || op.Type == "append" && (c.Target == 0 || uint64(c.Target) != threadKey) || title != c.Input.Title {
		return ErrCapture
	}
	if len(posts) < 1 || len(posts) > 3 || posts[0].Kind != "user" {
		return ErrCapture
	}
	for _, ending := range posts[1:] {
		if ending.Kind != "system" || ending.Private != nil {
			return ErrCapture
		}
	}
	p := posts[0]
	name, mail := c.Input.Name, c.Input.Mail
	if name == "" || c.Display.ForceNoname {
		name = c.Display.Noname
	}
	if c.Display.HideMail {
		mail = ""
	}
	if p.Name != name || p.Mail != mail || p.Body != c.Input.Body || p.Identity.Trip != c.Input.Trip || p.Number != c.Dedup.PostNumber || p.Private == nil || p.Private.SourceIP != c.Observation.Resolved.IP {
		return ErrCapture
	}
	if c.Cap == nil {
		if op.Actor.Kind != "anonymous" || op.Versions.Cap != nil || p.Identity.Cap != "" || p.Private.CapID != nil {
			return ErrCapture
		}
	} else if op.Actor.Kind != "cap" || op.Actor.ID == nil || *op.Actor.ID != c.Cap.ID || op.Versions.Cap == nil || *op.Versions.Cap != c.Cap.Revision || p.Private.CapID == nil || *p.Private.CapID != c.Cap.ID || p.Identity.Cap != c.Cap.Name || p.Identity.ID != "CAP_USER" || p.Identity.Suffix != "" {
		return ErrCapture
	}
	if c.TokenValidation != "not_checked" || len(c.Overrides) > 0 {
		if c.Token == nil && len(p.Private.RateKeys) != 3+len(c.Overrides) {
			return ErrCapture
		}
		if c.Token != nil {
			if len(p.Private.RateKeys) != 4+len(c.Overrides) {
				return ErrCapture
			}
			found := 0
			for _, key := range p.Private.RateKeys {
				if key == c.Token.Rate {
					found++
				}
			}
			if found != 1 {
				return ErrCapture
			}
		}
	}
	for _, id := range c.Overrides {
		found := 0
		for _, key := range p.Private.RateKeys {
			if key.Rule == id && key.KeyID == 7 && key.Cost == 1 && key.Subject != (domain.Hash{}) {
				found++
			}
		}
		if found != 1 || c.Token != nil && c.Token.Rate.Rule == id {
			return ErrCapture
		}
	}
	var dat []byte
	for i, p := range posts {
		t := ""
		if i == 0 {
			t = title
		}
		render := compat.DAT
		if c.Renderer == "dat-v1" {
			render = compat.LegacyDAT
		}
		line, e := render(p, t)
		if e != nil {
			return e
		}
		if uint32(len(dat)) != p.DATOffset || uint32(len(line)) != p.DATLength {
			return ErrCapture
		}
		dat = append(dat, line...)
	}
	if !bytes.Equal(dat, f.Records[0].DAT) {
		return ErrCapture
	}
	return nil
}
func readFrame(frame []byte) (store.Frame, domain.Operation, error) {
	f, n, e := store.ReadFrame(bytes.NewReader(frame))
	if e != nil || n != int64(len(frame)) || len(f.Records) != 1 {
		return f, domain.Operation{}, ErrCapture
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		return f, op, e
	}
	if op.Dedup == nil || op.Type != "create" && op.Type != "append" || op.Actor.Kind != "anonymous" && op.Actor.Kind != "cap" {
		return f, op, ErrCapture
	}
	return f, op, nil
}
func operationPosts(op domain.Operation) ([]domain.Post, string, error) {
	if op.Type == "create" {
		var v domain.Create
		e := strictjson.Decode(op.Payload, &v)
		return v.Posts, v.Title, e
	}
	var v domain.Append
	e := strictjson.Decode(op.Payload, &v)
	return v.Posts, "", e
}

// WithAnonymous は検証済みの主体HMACと追加枠だけをcaptureへ結合する。
func WithAnonymous(raw, frame []byte, target uint64, status string, token *TokenEvidence) ([]byte, error) {
	c, e := decode(raw)
	if e != nil {
		return nil, e
	}
	c.TokenValidation = status
	c.Token = token
	out, e := json.Marshal(c.Capture)
	if e != nil {
		return nil, e
	}
	// 変更するのはstatusと固定長の証明値だけ。元の完全型・Unicode検査結果を使い、
	// 更新後の業務制約・符号化サイズ・frameとの対応は改めて検査する。
	if len(out) > 512<<10 {
		return nil, ErrCapture
	}
	c, e = validateCapture(c)
	if e != nil {
		return nil, e
	}
	f, op, e := readFrame(frame)
	if e != nil {
		return nil, e
	}
	if e = validateFrame(c, f, op, frame, target); e != nil {
		return nil, e
	}
	return out, nil
}

// TokenMetadata は検証済みcaptureから復旧に必要な秘密を含まない成分だけをコピーする。
func TokenMetadata(raw []byte) (string, string, *TokenEvidence, error) {
	var v struct {
		Schema string         `json:"schema"`
		Status string         `json:"token_validation"`
		Token  *TokenEvidence `json:"token"`
	}
	e := json.Unmarshal(raw, &v)
	return v.Schema, v.Status, v.Token, e
}

// CapMetadata は検証済み資格と確定時刻だけを複製する。資格の認可は所有者側で別途照合する。
func CapMetadata(raw []byte) (*CapEvidence, domain.Time, bool, error) {
	schema, e := schemaOf(raw)
	if e != nil || schema != Schema {
		return nil, 0, false, e
	}
	c, e := decode(raw)
	return c.Cap, c.Committed, c.Target == 0, e
}
