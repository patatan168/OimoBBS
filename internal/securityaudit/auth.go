// Package securityaudit は認証結果だけを秘密なし・有界JSONでプロセス外へ記録する。
package securityaudit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Logger はプロセス専用鍵で接続元を仮名化する。入力秘密・Cookie・ログイン名を受け取らない。
type Logger struct {
	mu     sync.Mutex
	key    [32]byte
	log    *slog.Logger
	window time.Time
	counts map[string]uint64
}

// New は標準エラーや専用collectorへ書くloggerを作る。鍵は保存せず再起動で交換する。
func New(w io.Writer) (*Logger, error) {
	l := &Logger{log: slog.New(slog.NewJSONHandler(w, nil)), counts: make(map[string]uint64)}
	_, err := rand.Read(l.key[:])
	return l, err
}

// Record は許可済みの認証結果だけを記録する。同じ結果の過剰な記録は分単位で集約する。
// sourceはログへ直接出さずHMACへ変換する。accountは保存ID、未確定時は空を渡す。
func (l *Logger) Record(action, outcome, source, account string, now time.Time) {
	if l == nil || (action != "login" && action != "reauth" && action != "logout") {
		return
	}
	switch outcome {
	case "success", "failed", "limited", "busy", "rejected", "error":
	default:
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.window.IsZero() || !now.Before(l.window.Add(time.Minute)) {
		for key, count := range l.counts {
			if count > 100 {
				l.log.Warn("security_auth_summary", "result", key, "suppressed", count-100)
			}
		}
		clear(l.counts)
		l.window = now
	}
	k := action + ":" + outcome
	l.counts[k]++
	if l.counts[k] > 100 {
		return
	}
	h := hmac.New(sha256.New, l.key[:])
	h.Write([]byte(source))
	l.log.Info("security_auth", "action", action, "outcome", outcome, "source_id", hex.EncodeToString(h.Sum(nil)), "account_id", account)
}
