// 一度限り・短寿命のパスキーチャレンジをブラウザと管理者の世代へ結び付ける。
package bootstrap

import (
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"oimobbs/internal/domain"
)

type passkeyCeremony struct {
	Kind, Binding, Name string
	Account             administrator
	Revision            domain.U64
	Session             webauthn.SessionData
	Expires             time.Time
}
type passkeyCeremonies struct {
	mu      sync.Mutex
	pending map[string]passkeyCeremony
}

// put は期限切れを回収し、未完了要求を最大1024件に制限する。
func (p *passkeyCeremonies) put(v passkeyCeremony, now time.Time) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		p.pending = map[string]passkeyCeremony{}
	}
	for key, flow := range p.pending {
		if !now.Before(flow.Expires) {
			delete(p.pending, key)
		}
	}
	if len(p.pending) >= 1024 {
		return "", &adminFailure{status: 503, code: "PASSKEY_CAPACITY"}
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(token)
	v.Expires = now.Add(2 * time.Minute)
	p.pending[key] = v
	return key, nil
}

// take は失敗を含めて一度だけ消費し、別用途や別ブラウザからの転用を拒否する。
func (p *passkeyCeremonies) take(key, kind, binding string, now time.Time) (passkeyCeremony, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.pending[key]
	delete(p.pending, key)
	return v, ok && now.Before(v.Expires) && v.Kind == kind && v.Binding == binding
}
func (h *adminHandler) webAuthn() (*webauthn.WebAuthn, error) {
	origin, err := url.Parse(h.origin)
	if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPDisplayName: "OimoBBS管理", RPID: origin.Hostname(), RPOrigins: []string{h.origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired, ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired()},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute},
		},
	})
}
