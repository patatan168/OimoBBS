// サイトと板の保存停止を、所有workerへ待機せず公開監視へ伝える。
package bootstrap

import (
	"io"
	"net/http"
	"oimobbs/internal/delivery"
	"strconv"
)

// HealthcheckPath は公開入口から保存停止を確認する固定URL。板名や停止理由は返さない。
const HealthcheckPath = "/.well-known/oimobbs-health"

// storageHealthy はサイト所有lockと板の公開済み状態だけを読む。保存やworkerへの投入は行わない。
// 混雑・意図的な閉鎖は停止とせず、保存不明のラッチと終了済みworkerを検知する。
func (repo *Repository) storageHealthy() bool {
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	if repo.available() != nil {
		return false
	}
	for _, b := range repo.posting {
		if b.listingStopped.Load() || b.worker == nil {
			return false
		}
		select {
		case <-b.worker.Done():
			return false
		default:
		}
	}
	return true
}

// healthcheckPage は保存状態をキャッシュ禁止の固定本文で返す。HEADにも同じ判定を適用する。
func (repo *Repository) healthcheckPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Content-Length", "0")
		delivery.RejectUnreadBody(w, r)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	status, body := http.StatusOK, "ok\n"
	if !repo.storageHealthy() {
		status, body = http.StatusServiceUnavailable, "unavailable\n"
	}
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}
