// 公開と管理の別listenerが同じ帯域枠へ予約することを検査する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRepositorySharedDelivery(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	public, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	admin, e := repo.AdminHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	scheduler := repo.egress
	for _, handler := range []http.Handler{public.Handler, admin.Handler} {
		before := repo.DeliveryStatus()
		request := httptest.NewRequest("HEAD", repo.cfg.Public.BaseURL+"/", nil)
		request.RemoteAddr = "127.0.0.1:1234"
		handler.ServeHTTP(httptest.NewRecorder(), request)
		after := repo.DeliveryStatus()
		if repo.egress != scheduler || after.Reserved <= before.Reserved || after.Active != 0 || after.Queued != 0 {
			t.Fatal("listener bypassed shared delivery", before, after)
		}
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
}
