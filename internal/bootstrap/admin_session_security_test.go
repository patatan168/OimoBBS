// 受付時の認証結果を、ログアウト後の操作・非公開送信に使えないことを検査する。
package bootstrap

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/adminauth"
	"testing"
	"time"
)

func TestAdminQueuedSessionLogout(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	raw := client.cookies["oimo_admin"].Value
	s, err := repo.adminAuth.Lookup(raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	view, err := repo.adminOperations(s)
	if err != nil {
		t.Fatal(err)
	}
	revision := repo.site.State().Seq
	repo.adminAuth.Delete(raw)
	// 設定保存は公開状態やWALを変更する前に拒否する。
	_, err = repo.updateOperations(s, view.Settings, view.ETag(), "queued-session-security")
	if !errors.Is(err, adminauth.ErrSession) || repo.site.State().Seq != revision {
		t.Fatal("logged out request changed state", err)
	}
	// 送信ごとの共通認可も同じ失効判定を通す。
	w := httptest.NewRecorder()
	guard := &evidenceQueryWriter{ResponseWriter: w, check: func() error {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		_, e := repo.currentAdminSession(s)
		return e
	}}
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("private send not aborted")
			}
		}()
		_, _ = guard.Write([]byte("PRIVATE_QUEUED_BODY"))
	}()
	if w.Body.Len() != 0 {
		t.Fatal("private data transmitted after logout")
	}
}
