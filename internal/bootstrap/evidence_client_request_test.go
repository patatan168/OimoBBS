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
			BoardKey *string `json:"board_key"`
			Client   struct {
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
	if row.Client.IP != "127.0.0.1" {
		t.Fatal("saved resolved client omitted", body)
	}
	if row.BoardKey == nil || *row.BoardKey != "logs" {
		t.Fatal("saved board alias omitted", body)
	}
	if row.Request.Alias != nil {
		t.Fatal("duplicate board key", body)
	}
	if row.Request.Method != "" || row.Request.Route != "" || row.Request.Status != "" {
		t.Fatal("internal request details exported", body)
	}
}
