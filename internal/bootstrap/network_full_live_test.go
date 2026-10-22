// 明示実行時だけ、全取得元の保存容量を検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"oimobbs/internal/strictjson"
	"os"
	"testing"
	"time"
)

func TestNetworkFullLiveSavedCapacity(t *testing.T) {
	if os.Getenv("OIMO_NETWORK_LIVE") != "1" {
		t.Skip("explicit live fetch")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	client := newNetworkClient()
	sources := defaultNetworkSources()
	rows, err := fetchNetworkRows(ctx, client, sources)
	if err != nil {
		t.Fatal(err)
	}
	access, err := fetchAccessData(ctx, client, sources)
	if err != nil {
		t.Fatal(err)
	}
	state := networkState{Version: 1, Config: defaultNetworkConfig(), Rows: rows, AccessData: access}
	state.Config.Sources = sources
	r, e := json.Marshal(state)
	if e != nil || len(r) > strictjson.MaxBytes-(128<<10) {
		t.Fatal("saved state capacity", len(r), e)
	}
	var restored networkState
	if err := strictjson.Decode(r, &restored); err != nil {
		t.Fatal("saved state roundtrip", err)
	}
	c, _ := json.Marshal(state.Config)
	a, _ := json.Marshal(access)
	p, _ := json.Marshal(state.Rows)
	t.Logf("state=%d marshal=%v config=%d access=%d rows=%d", len(r), e, len(c), len(a), len(p))
}
