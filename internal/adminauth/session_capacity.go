// アカウント単位のセッション占有を抑え、他の管理者のログイン枠を残す。
package adminauth

import (
	"bytes"
	"oimobbs/internal/domain"
)

// accountSessionLimit は端末・ブラウザを併用できる緩い上限とする。
const accountSessionLimit = 32

// accountSessionVictim は所有mutex内で、自分の最終利用が最も古いセッションだけを選ぶ。
// 生成に成功するまで削除せず、同時刻は作成時刻・ハッシュ順で決定する。
func (m *Manager) accountSessionVictim(id domain.ID) ([32]byte, bool) {
	count := 0
	var oldest Session
	for _, s := range m.sessions {
		if s.Admin != id {
			continue
		}
		if count == 0 || sessionOlder(s, oldest) {
			oldest = s
		}
		count++
	}
	return oldest.handle, count >= accountSessionLimit
}

func sessionOlder(a, b Session) bool {
	if !a.last.Equal(b.last) {
		return a.last.Before(b.last)
	}
	if !a.created.Equal(b.created) {
		return a.created.Before(b.created)
	}
	return bytes.Compare(a.handle[:], b.handle[:]) < 0
}
