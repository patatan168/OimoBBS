// OTP登録の共有鍵を暗号化したうえで短寿命・一度限り・セッション束縛で保持する。
package bootstrap

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
)

type otpEnrollment struct {
	Secret               sealedOTP
	Binding              string
	Admin                domain.ID
	Generation, Revision domain.U64
	Expires              time.Time
}
type otpEnrollments struct {
	mu      sync.Mutex
	pending map[string]*otpEnrollment
}

// put は期限切れを消去し、登録待ちを最大128件へ制限する。
func (p *otpEnrollments) put(v *otpEnrollment, now time.Time) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		p.pending = map[string]*otpEnrollment{}
	}
	for k, prior := range p.pending {
		if !now.Before(prior.Expires) {
			clear(prior.Secret[:])
			delete(p.pending, k)
		}
	}
	if len(p.pending) >= 128 {
		return "", adminauth.ErrBusy
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

// take は失敗も含め一度だけ消費し、期限・ブラウザ違いでは暗号文も消去する。
func (p *otpEnrollments) take(token, binding string, now time.Time) (*otpEnrollment, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.pending[token]
	delete(p.pending, token)
	if !ok {
		return nil, false
	}
	if !now.Before(v.Expires) || v.Binding != binding {
		clear(v.Secret[:])
		return nil, false
	}
	return v, true
}

// peek はQRの再表示用に暗号文だけを複製する。別セッションの要求では内容を返さない。
func (p *otpEnrollments) peek(token, binding string, now time.Time) (*otpEnrollment, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.pending[token]
	if !ok {
		return nil, false
	}
	if !now.Before(v.Expires) {
		clear(v.Secret)
		delete(p.pending, token)
		return nil, false
	}
	if v.Binding != binding {
		return nil, false
	}
	copy := *v
	copy.Secret = append(sealedOTP{}, v.Secret...)
	return &copy, true
}
