// 架空サンプルは管理認証下で取得でき、実ログの権限を暗黙に追加しないことを検査する。
package bootstrap

import (
	"archive/zip"
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestAdminEvidenceSampleDownload(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	res, _ := client.request(http.MethodGet, "/evidence/sample.zip", "", nil)
	if res.StatusCode == 200 {
		t.Fatal("unauthenticated sample download")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := client.request(http.MethodGet, "/evidence/sample.zip", "", nil)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/zip" || !strings.Contains(res.Header.Get("Content-Disposition"), "evidence-sample.zip") {
		t.Fatal("sample download", res.StatusCode)
	}
	if _, e := zip.NewReader(bytes.NewReader([]byte(body)), int64(len(body))); e != nil {
		t.Fatal(e)
	}
	res, _ = client.request(http.MethodGet, "/api/v1/evidence/cases", "", nil)
	if res.StatusCode != 403 {
		t.Fatal("sample gave access to real logs")
	}
}
