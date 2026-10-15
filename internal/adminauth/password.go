// Package adminauth は管理者のパスワード照合と、プロセス内だけの認証状態を扱う。
package adminauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// 保存値から任意のCPU・メモリ量を指定させず、RFC 9106の第二推奨構成へ固定する。
const (
	passwordMemory  = 64 * 1024 // KiB。照合2workerで計算用メモリは合計128 MiB。
	passwordTime    = 3
	passwordThreads = 4
)

// Password は保存用の導出結果。公開DTOへ含めない。
type Password struct {
	Algorithm   string `json:"algorithm"`
	Version     uint32 `json:"version"`
	Iterations  uint32 `json:"iterations"`
	Memory      uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
	Salt        string `json:"salt_base64"`
	Digest      string `json:"digest_base64"`
}

var ErrPassword = errors.New("invalid administrator credential")

func passwordBytes(s string, n int) ([]byte, error) {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != n || base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrPassword
	}
	return b, nil
}

// Validate は固定アルゴリズム・作業量と正規base64を検証する。
func (p Password) Validate() error {
	if p.Algorithm != "argon2id" || p.Version != argon2.Version || p.Iterations != passwordTime || p.Memory != passwordMemory || p.Parallelism != passwordThreads {
		return ErrPassword
	}
	if _, e := passwordBytes(p.Salt, 16); e != nil {
		return e
	}
	_, e := passwordBytes(p.Digest, 32)
	return e
}

// NewPassword は15〜128文字の秘密から毎回別saltで保存形式を作る。
func NewPassword(secret string) (Password, error) {
	var p Password
	if !utf8.ValidString(secret) || len(secret) > 512 || strings.ContainsRune(secret, 0) || utf8.RuneCountInString(secret) < 15 || utf8.RuneCountInString(secret) > 128 {
		return p, ErrPassword
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return p, e
	}
	key := argon2.IDKey([]byte(secret), salt, passwordTime, passwordMemory, passwordThreads, 32)
	defer clear(key)
	return Password{Algorithm: "argon2id", Version: argon2.Version, Iterations: passwordTime, Memory: passwordMemory, Parallelism: passwordThreads, Salt: base64.StdEncoding.EncodeToString(salt), Digest: base64.StdEncoding.EncodeToString(key)}, nil
}

// Verify は定時間で導出結果を比較する。呼出元でworker数と試行回数を制限する。
func (p Password) Verify(secret string) bool {
	if p.Validate() != nil || !utf8.ValidString(secret) || len(secret) > 512 || strings.ContainsRune(secret, 0) {
		return false
	}
	salt, _ := passwordBytes(p.Salt, 16)
	want, _ := passwordBytes(p.Digest, 32)
	got := argon2.IDKey([]byte(secret), salt, p.Iterations, p.Memory, p.Parallelism, 32)
	defer clear(got)
	return subtle.ConstantTimeCompare(got, want) == 1
}
