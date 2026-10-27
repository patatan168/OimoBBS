// Package postinput は匿名通常投稿の秘密除去・正規化・再送要求のHMACを生成する。
package postinput

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"regexp"
	"strconv"
	"strings"
)

var ErrInput = errors.New("invalid posting input")
var ErrUnsupported = errors.New("posting feature not supported")
var nameReference = regexp.MustCompile(`^&#(?:[0-9]+|[xX][0-9a-fA-F]+);`)
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// Input は秘密除去済み通常入力。生フォーム・trip/cap秘密・利用者request IDは持たない。
type Input struct {
	CapOnly    bool         `json:"cap_only,omitempty"`
	Controls   *Controls    `json:"controls"`
	Name       string       `json:"name"`
	Trip       string       `json:"trip"`
	Mail       string       `json:"mail"`
	Title      string       `json:"title"`
	Body       string       `json:"body"`
	Credential domain.Hash  `json:"credential_hmac"`
	RequestID  *domain.Hash `json:"request_id_hmac"`
}

// Prepare は生#で秘密を分離してから表示文字を正規化する。未対応制御は保存せず拒否する。
func Prepare(fields map[string]string, create bool, key domain.Hash) (Input, error) {
	var input Input
	if flag := fields["oimo_cap_only"]; flag != "" {
		if !create || flag != "1" {
			return input, ErrInput
		}
		input.CapOnly = true
	}
	name, secret := splitName(fields["FROM"])
	if strings.Contains(strings.ToLower(fields["mail"]), "#cap:") {
		return input, ErrUnsupported
	}
	rawBody := strings.ReplaceAll(strings.ReplaceAll(fields["MESSAGE"], "\r\n", "\n"), "\r", "\n")
	if rawBody == "!status:" || rawBody == "!chkBBx:" || rawBody == "!rebuild:" {
		return input, ErrUnsupported
	}
	var e error
	name, rawBody, input.Controls, e = parseControls(name, rawBody, create)
	if e != nil {
		return Input{}, e
	}
	if input.Trip, e = identity.Trip(secret); e != nil {
		return Input{}, ErrInput
	}
	input.Credential = identity.MAC(key[:], "oimo/post-credential/v1", []byte(secret))
	if input.Controls != nil {
		raw, _ := json.Marshal(input.Controls)
		input.Credential = identity.MAC(key[:], "oimo/post-controls/v1", input.Credential[:], raw)
	}
	if input.Name, e = compat.Normalize(name, false, true); e != nil {
		return Input{}, ErrInput
	}
	input.Name = strings.NewReplacer("◆", "◇", "★", "☆", "●", "○").Replace(input.Name)
	if input.Mail, e = compat.Normalize(fields["mail"], false, false); e != nil {
		return Input{}, ErrInput
	}
	if input.Title, e = compat.Normalize(fields["subject"], false, true); e != nil {
		return Input{}, ErrInput
	}
	if input.Body, e = compat.Normalize(rawBody, true, true); e != nil {
		return Input{}, ErrInput
	}
	if strings.TrimSpace(input.Body) == "" || create && strings.TrimSpace(input.Title) == "" || !create && input.Title != "" {
		return Input{}, ErrInput
	}
	if requestID := fields["oimo_request_id"]; requestID != "" {
		if !requestIDPattern.MatchString(requestID) {
			return Input{}, ErrInput
		}
		id := identity.MAC(key[:], "oimo/request-id/v1", []byte(requestID))
		input.RequestID = &id
	}
	return input, nil
}

// Dedup はIP主体を板へ束縛し、意味を持つ入力だけから要求HMACを生成する。
// 匿名tokenを採用する経路は未接続で、未検証Cookieから主体を生成してはならない。
func (in Input) Dedup(key domain.Hash, board domain.ID, target uint64, canonicalIP []byte, now domain.Time) domain.Dedup {
	subject := identity.MAC(key[:], "oimo/subject-ip/v1", board[:], canonicalIP)
	operation := "append"
	if target == 0 {
		operation = "create"
	}
	request := identity.MAC(key[:], "oimo/post-request/v1", []byte("operation"), []byte(operation), []byte("board"), board[:], []byte("key"), []byte(strconv.FormatUint(target, 10)), []byte("name"), []byte(in.Name), []byte("trip"), []byte(in.Trip), []byte("mail"), []byte(in.Mail), []byte("title"), []byte(in.Title), []byte("body"), []byte(in.Body), []byte("credential_hmac"), in.Credential[:])
	if in.Controls != nil {
		raw, _ := json.Marshal(in.Controls)
		request = identity.MAC(key[:], "oimo/post-request-controls/v1", request[:], raw)
	}
	if in.CapOnly {
		request = identity.MAC(key[:], "oimo/post-cap-only/v1", request[:])
	}
	d := domain.Dedup{Mode: "implicit", KeyID: 8, Subject: subject, Request: request, Expires: now + 30*1e9, PostNumber: 1}
	if in.RequestID != nil {
		id := *in.RequestID
		d.Mode = "explicit"
		d.RequestID = &id
		d.Expires = now + 86400*1e9
	}
	return d
}

// splitName は数値参照の構文内にある#を区切りとせず、最初の生#だけで分ける。
// 参照を復号しないので、参照から秘密や制御命令が発生しない。
func splitName(raw string) (string, string) {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '&' {
			if ref := nameReference.FindString(raw[i:]); ref != "" {
				i += len(ref) - 1
				continue
			}
		}
		if raw[i] == '#' {
			return raw[:i], raw[i+1:]
		}
	}
	return raw, ""
}
