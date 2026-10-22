// セッション・使用済みログイントークン・試行枠を有限メモリに保持し、再起動で失効させる。
package adminauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"oimobbs/internal/domain"
	"sync"
	"time"
)

// ReauthenticationValidity は重要操作に使う再認証の有効期間を示す。
const ReauthenticationValidity = 10 * time.Minute

var ErrSession = errors.New("administrator session required")
var ErrBusy = errors.New("administrator authentication busy")

type Limited struct{ RetryAfter uint64 }

func (*Limited) Error() string { return "administrator login rate exceeded" }

// Session は認証済みID/世代と非公開のCSRF鍵を保持する。JSONへ変換しない。
type Session struct {
	Admin                 domain.ID
	Generation            domain.U64
	created, last         time.Time
	reauthenticated       time.Time
	reauthenticatedStrong bool
	csrf                  [32]byte
	handle                [32]byte
}
type nonce struct{ expires time.Time }

// Manager は所有Repositoryで一つだけ生成する。導出計算をmutex内で実行しない。
type Manager struct {
	mu             sync.Mutex
	sessions       map[[32]byte]Session
	nonces         map[[32]byte]nonce
	loginUses      []time.Time
	attempts       map[[32]byte][]time.Time
	key            [32]byte
	slots, workers chan struct{}
	dummy          Password
}

// New はdummyの導出結果とプロセス専用鍵を生成する。
func New() (*Manager, error) {
	m := &Manager{sessions: map[[32]byte]Session{}, nonces: map[[32]byte]nonce{}, attempts: map[[32]byte][]time.Time{}, slots: make(chan struct{}, 18), workers: make(chan struct{}, 2)}
	if _, e := rand.Read(m.key[:]); e != nil {
		return nil, e
	}
	secret, e := randomSecret()
	if e != nil {
		return nil, e
	}
	m.dummy, e = NewPassword(secret)
	return m, e
}
func randomSecret() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func secretHash(raw string) ([32]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != raw {
		return [32]byte{}, ErrSession
	}
	return sha256.Sum256(b), nil
}
func mac(key []byte, route, raw string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(route))
	h.Write([]byte{0})
	h.Write([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func (m *Manager) prune(now time.Time) {
	for h, s := range m.sessions {
		if !sessionAlive(s, now) {
			delete(m.sessions, h)
		}
	}
	for h, n := range m.nonces {
		if !now.Before(n.expires) {
			delete(m.nonces, h)
		}
	}
	for h, a := range m.attempts {
		if len(a) == 0 || !now.Before(a[len(a)-1].Add(time.Minute)) {
			delete(m.attempts, h)
		}
	}
}
func sessionAlive(s Session, now time.Time) bool {
	return !now.Before(s.created) && now.Before(s.last.Add(30*time.Minute)) && now.Before(s.created.Add(8*time.Hour))
}

// AttemptPassword は接続元別のrolling 1分/5件を消費する。
// 未認証者による他人の締め出しを避けるため、アカウント共通の停止は設けない。
func (m *Manager) AttemptPassword(ip string, now time.Time) error {
	return m.attempt([][32]byte{sha256.Sum256([]byte("ip:" + ip))}, now)
}

// AttemptPasskey は署名認証の開始を接続元別に制限する。パスワード試行枠や他の接続元の枠は消費しない。
func (m *Manager) AttemptPasskey(ip string, now time.Time) error {
	return m.attempt([][32]byte{sha256.Sum256([]byte("passkey-ip:" + ip))}, now)
}

// AttemptOTPPassword はOTP認証のパスワード照合前に接続元だけを制限する。
func (m *Manager) AttemptOTPPassword(ip string, now time.Time) error {
	return m.attempt([][32]byte{sha256.Sum256([]byte("otp-password-ip:" + ip))}, now)
}

// AttemptOTP はパスワードまたは登録用の再認証が確認済みの場合だけ、コードの接続元・アカウント枠を消費する。
func (m *Manager) AttemptOTP(ip, login string, now time.Time) error {
	return m.attempt([][32]byte{sha256.Sum256([]byte("otp-ip:" + ip)), sha256.Sum256([]byte("otp-login:" + login))}, now)
}

// AttemptSecuritySetting は再認証済みの設定変更を接続元別に制限し、ログイン用の枠を消費しない。
func (m *Manager) AttemptSecuritySetting(ip string, now time.Time) error {
	return m.attempt([][32]byte{sha256.Sum256([]byte("security-ip:" + ip))}, now)
}

// attempt は同じ名前空間の試行枠をまとめて検査し、全枠に余裕がある場合だけ消費する。
func (m *Manager) attempt(keys [][32]byte, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune(now)
	return m.attemptLocked(keys, now, 5)
}

// attemptLocked は所有mutex内で検査・消費する。拒否時は新規の枠を記憶しない。
func (m *Manager) attemptLocked(keys [][32]byte, now time.Time, limit int) error {
	newKeys := 0
	wait := uint64(0)
	lists := make([][]time.Time, len(keys))
	for i, k := range keys {
		v, ok := m.attempts[k]
		if !ok {
			newKeys++
		}
		if len(v) > 0 && now.Before(v[len(v)-1]) {
			now = v[len(v)-1]
		}
		for len(v) > 0 && !now.Before(v[0].Add(time.Minute)) {
			v = v[1:]
		}
		if len(v) >= limit {
			d := v[0].Add(time.Minute).Sub(now)
			wait = max(wait, uint64((d+time.Second-1)/time.Second))
		}
		lists[i] = v
	}
	if wait > 0 {
		return &Limited{wait}
	}
	if len(m.attempts)+newKeys > 20000 {
		return ErrBusy
	}
	for i, k := range keys {
		m.attempts[k] = append(lists[i], now)
	}
	return nil
}

// Verify は2worker/待ち16へ導出を制限する。未知アカウントでも同じdummy計算を行う。
func (m *Manager) Verify(ctx context.Context, password *Password, secret string) (bool, error) {
	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	default:
		return false, ErrBusy
	}
	select {
	case m.workers <- struct{}{}:
		defer func() { <-m.workers }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	p := m.dummy
	if password != nil {
		p = *password
	}
	ok := p.Verify(secret)
	return ok && password != nil, nil
}

// Create はログイン成功ごとに新しいCookieを生成し、アカウント内の最終利用順に上限を保つ。保存はhashだけ。
func (m *Manager) Create(id domain.ID, generation domain.U64, now time.Time) (string, Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune(now)
	evict, replace := m.accountSessionVictim(id)
	if len(m.sessions) >= 10000 && !replace {
		return "", Session{}, ErrBusy
	}
	raw, e := randomSecret()
	if e != nil {
		return "", Session{}, e
	}
	s := Session{Admin: id, Generation: generation, created: now, last: now}
	if _, e = rand.Read(s.csrf[:]); e != nil {
		return "", Session{}, e
	}
	h, _ := secretHash(raw)
	s.handle = h
	if replace {
		delete(m.sessions, evict)
	}
	m.sessions[h] = s
	return raw, s, nil
}

// Lookup は無操作/絶対期限を検査する。最新のアカウント世代・権限は呼出元でも照合する。
func (m *Manager) Lookup(raw string, now time.Time) (Session, error) {
	h, e := secretHash(raw)
	if e != nil {
		return Session{}, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[h]
	if !ok || !sessionAlive(s, now) {
		delete(m.sessions, h)
		return Session{}, ErrSession
	}
	if now.After(s.last) {
		s.last = now
	}
	m.sessions[h] = s
	return s, nil
}

// Check は処理待ち・送信待ちの後にも失効と期限を照合する。無操作期限は延長しない。
func (m *Manager) Check(expected Session, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[expected.handle]
	if !ok || !sessionAlive(s, now) || now.Before(s.last) || s.Admin != expected.Admin || s.Generation != expected.Generation || s.csrf != expected.csrf {
		return ErrSession
	}
	return nil
}

// Delete はlogout時にCookieをサーバー側でも失効させる。
func (m *Manager) Delete(raw string) {
	h, e := secretHash(raw)
	if e != nil {
		return
	}
	m.mu.Lock()
	delete(m.sessions, h)
	m.mu.Unlock()
}

// CSRF は操作経路へ束縛したform/API用トークンを返す。
func (s Session) CSRF(route string) string { return mac(s.csrf[:], route, "") }

// CheckCSRF はトークンを定時間比較する。
func (s Session) CheckCSRF(route, token string) bool {
	return hmac.Equal([]byte(s.CSRF(route)), []byte(token))
}

// Reauthenticated は明示した再認証から10分未満だけ高権限操作を許可する。時計後退は拒否する。
func (s Session) Reauthenticated(now time.Time) bool {
	return !s.reauthenticated.IsZero() && !now.Before(s.reauthenticated) && now.Before(s.reauthenticated.Add(ReauthenticationValidity))
}

// StrongReauthenticated はパスキーまたはOTPによる明示的な本人確認から10分未満を示す。
func (s Session) StrongReauthenticated(now time.Time) bool {
	return s.reauthenticatedStrong && s.Reauthenticated(now)
}

// MarkReauthenticated は照合済みの生存セッションを新Cookie・CSRFへ交換する。
// アカウント世代は呼出元が所有mutex内で再検査し、元の作成時刻に基づく絶対期限は延長しない。
func (m *Manager) MarkReauthenticated(raw string, expected Session, now time.Time) (string, Session, error) {
	return m.markReauthenticated(raw, expected, now, false)
}

// MarkStronglyReauthenticated はパスキー・OTPの照合済みセッションを新Cookie・CSRFへ交換する。
func (m *Manager) MarkStronglyReauthenticated(raw string, expected Session, now time.Time) (string, Session, error) {
	return m.markReauthenticated(raw, expected, now, true)
}

func (m *Manager) markReauthenticated(raw string, expected Session, now time.Time, strong bool) (string, Session, error) {
	h, e := secretHash(raw)
	if e != nil {
		return "", Session{}, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[h]
	if !ok || !sessionAlive(s, now) || now.Before(s.last) || s.Admin != expected.Admin || s.Generation != expected.Generation || s.csrf != expected.csrf {
		return "", Session{}, ErrSession
	}
	next, e := randomSecret()
	if e != nil {
		return "", Session{}, e
	}
	if _, e = rand.Read(s.csrf[:]); e != nil {
		return "", Session{}, e
	}
	s.reauthenticated, s.last = now, now
	s.reauthenticatedStrong = strong
	nextHash, _ := secretHash(next)
	delete(m.sessions, h)
	s.handle = nextHash
	m.sessions[nextHash] = s
	return next, s, nil
}

// DerivePassword は保存用の導出も同じ有限worker・待ち枠へ制限する。満杯なら待たずに拒否する。
func (m *Manager) DerivePassword(secret string) (Password, error) {
	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	default:
		return Password{}, ErrBusy
	}
	select {
	case m.workers <- struct{}{}:
		defer func() { <-m.workers }()
	default:
		return Password{}, ErrBusy
	}
	return NewPassword(secret)
}
