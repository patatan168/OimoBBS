// 管理HTTPと保全ZIPの接続選択へclient/requestが保存値から出力されることを検査する。
package bootstrap

import (
	"encoding/json"
	"testing"
)

func assertAcceptedClientRequestQuery(t *testing.T, body string) {
	t.Helper()
	var response struct {
		Rows []struct {
			Client struct {
				IP     string `json:"resolved_ip"`
				Source string `json:"source"`
			} `json:"client"`
			Request struct {
				Method string  `json:"method"`
				Route  string  `json:"route"`
				Alias  *string `json:"board_alias_used"`
				Status string  `json:"header_capture_status"`
			} `json:"request"`
		} `json:"result"`
	}
	if e := json.Unmarshal([]byte(body), &response); e != nil {
		t.Fatal(e)
	}
	if len(response.Rows) != 1 {
		t.Fatal("client/request rows")
	}
	row := response.Rows[0]
	if row.Client.IP != "127.0.0.1" || row.Client.Source != "direct" {
		t.Fatal("saved resolved client omitted", body)
	}
	if row.Request.Method != "POST" || row.Request.Route != "bbs_post" {
		t.Fatal("saved method/route omitted", body)
	}
	if row.Request.Alias != nil || row.Request.Status != "captured" {
		t.Fatal("alias inferred or header status omitted", body)
	}
}
