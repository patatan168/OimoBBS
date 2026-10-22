// キャップ管理HTTPの日付をRFC3339Nanoへ変換する。保存形式と旧入力の再送HMACは維持する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

type capHTTPView struct {
	AdminCap
	ExpiresAt string `json:"expires_at"`
}

func capHTTPValue(cap AdminCap) capHTTPView {
	if cap.Expires == 0 {
		return capHTTPView{AdminCap: cap}
	}
	return capHTTPView{AdminCap: cap, ExpiresAt: time.Unix(0, int64(cap.Expires)).UTC().Format(time.RFC3339Nano)}
}
func capHTTPValues(caps []AdminCap) []capHTTPView {
	values := make([]capHTTPView, len(caps))
	for i, cap := range caps {
		values[i] = capHTTPValue(cap)
	}
	return values
}

// UnmarshalJSON は新しいexpires_atと従来expires_at_nsを排他的に受け付ける。
func (input *capInput) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	type prior capInput
	if value, present := fields["expires_at"]; present {
		if _, legacy := fields["expires_at_ns"]; legacy {
			return store.ErrCorrupt
		}
		var text string
		if string(value) == "null" || json.Unmarshal(value, &text) != nil {
			return store.ErrCorrupt
		}
		if text == "" {
			text = "1970-01-01T00:00:00Z"
		}
		at, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || at.UnixNano() < 0 || !time.Unix(0, at.UnixNano()).Equal(at) {
			return store.ErrCorrupt
		}
		delete(fields, "expires_at")
		fields["expires_at_ns"], _ = json.Marshal(domain.Time(at.UnixNano()))
		raw, _ = json.Marshal(fields)
	}
	if _, present := fields["expires_at_ns"]; !present {
		fields["expires_at_ns"] = json.RawMessage(`"0"`)
		raw, _ = json.Marshal(fields)
	}
	var result prior
	if err := strictjson.Decode(raw, &result); err != nil {
		return err
	}
	*input = capInput(result)
	return nil
}
