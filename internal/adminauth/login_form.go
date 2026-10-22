// 画面発行を無状態化し、署名・期限・一度限りの消費を有限の記憶領域で両立する。
package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

const loginFormValidity = 10 * time.Minute
const loginUsesPerSecond = 16
const loginUsesPerSourceMinute = 32

// LoginForm は発行時刻・192bit乱数を含むCookieとHMACを返す。発行をサーバーに記憶しない。
func (m *Manager) LoginForm(now time.Time) (string, string, error) {
	var value [32]byte
	binary.BigEndian.PutUint64(value[:8], uint64(now.UnixNano()))
	if _, err := rand.Read(value[8:]); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(value[:])
	return raw, mac(m.key[:], "login", raw), nil
}

func (m *Manager) validateLoginForm(raw, csrf string, now time.Time) ([32]byte, time.Time, error) {
	if len(raw) != 43 || len(csrf) != 43 {
		return [32]byte{}, time.Time{}, ErrSession
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(value) != 32 || base64.RawURLEncoding.EncodeToString(value) != raw || !hmac.Equal([]byte(csrf), []byte(mac(m.key[:], "login", raw))) {
		return [32]byte{}, time.Time{}, ErrSession
	}
	issued := time.Unix(0, int64(binary.BigEndian.Uint64(value[:8])))
	expires := issued.Add(loginFormValidity)
	if now.Before(issued) || !now.Before(expires) {
		return [32]byte{}, time.Time{}, ErrSession
	}
	return sha256.Sum256(value), expires, nil
}

// ConsumeLogin は一度だけ消費する。HTTP入口では接続元保護を含むConsumeLoginFromを使う。
func (m *Manager) ConsumeLogin(raw, csrf string, now time.Time) error {
	return m.consumeLogin(raw, csrf, "", now)
}

// ConsumeLoginFrom は署名検証後、接続元別の枠と使用済み記録を同じmutex内で消費する。
func (m *Manager) ConsumeLoginFrom(raw, csrf, ip string, now time.Time) error {
	if ip == "" {
		return ErrSession
	}
	return m.consumeLogin(raw, csrf, ip, now)
}

func (m *Manager) consumeLogin(raw, csrf, ip string, now time.Time) error {
	hash, expires, err := m.validateLoginForm(raw, csrf, now)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.loginUses) > 0 && now.Before(m.loginUses[len(m.loginUses)-1]) {
		now = m.loginUses[len(m.loginUses)-1]
	}
	if !now.Before(expires) {
		return ErrSession
	}
	m.prune(now)
	if _, used := m.nonces[hash]; used {
		return ErrSession
	}
	for len(m.loginUses) > 0 && !now.Before(m.loginUses[0].Add(time.Second)) {
		m.loginUses = m.loginUses[1:]
	}
	// 消費は16件/秒以下なので、10分の使用済み記録は最大9,600件。画面発行数には依存しない。
	if len(m.loginUses) >= loginUsesPerSecond {
		return &Limited{RetryAfter: 1}
	}
	if ip != "" {
		keys := [][32]byte{sha256.Sum256([]byte("login-form-ip:" + ip))}
		if err := m.attemptLocked(keys, now, loginUsesPerSourceMinute); err != nil {
			return err
		}
	}
	m.loginUses = append(m.loginUses, now)
	m.nonces[hash] = nonce{expires: expires}
	return nil
}
