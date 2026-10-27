// 固定枠を外す時刻、旧履歴の検査、利用者の投稿枠と保存版の維持を確認する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"reflect"
	"testing"
	"time"
)

func TestPostingResourceBoundary(t *testing.T) {
	at := time.Now()
	owner := domain.NewID()
	for _, current := range []bool{false, true} {
		policy := initialAdmission(at.Add(-time.Hour))
		policy.Defaults.Enabled = false
		a := &admission{policy: policy, limits: abuse.NewLimiter(10000), resourceFrom: domain.Time(at.UnixNano())}
		clock := at
		if !current {
			clock = at.Add(-time.Nanosecond)
		}
		for i := range 1000 {
			// /24を分け、サイト共通400件の瞬間枠だけを観測する。
			ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
			_, expected := a.charges(owner, ip, false)
			ticket, keys, _, err := a.reserve(owner, ip, false, func() time.Time { return clock })
			if !current && i == 400 {
				var limited *abuse.RateLimited
				if !errors.As(err, &limited) {
					t.Fatal("旧サイト枠が失われた", err)
				}
				break
			}
			if err != nil || !reflect.DeepEqual(keys, expected) {
				t.Fatal("固定枠または保存キー", current, i, err)
			}
			if err = a.limits.Commit(ticket); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 同一ネットワークの旧120件枠も境界前に残り、境界後は利用者の設定だけを消費する。
	for _, current := range []bool{false, true} {
		policy := initialAdmission(at.Add(-time.Hour))
		policy.Defaults.Enabled = false
		a := &admission{policy: policy, limits: abuse.NewLimiter(10000), resourceFrom: domain.Time(at.UnixNano())}
		clock := at
		if !current {
			clock = at.Add(-time.Nanosecond)
		}
		for i := range 200 {
			ticket, _, _, err := a.reserve(owner, netip.MustParseAddr("192.0.2.1"), false, func() time.Time { return clock })
			if !current && i == 120 {
				var limited *abuse.RateLimited
				if !errors.As(err, &limited) {
					t.Fatal("旧ネットワーク枠", err)
				}
				break
			}
			if err != nil {
				t.Fatal("ネットワーク固定枠", i, err)
			}
			if err = a.limits.Commit(ticket); err != nil {
				t.Fatal(err)
			}
		}
	}
	a := &admission{policy: initialAdmission(at), limits: abuse.NewLimiter(100), resourceFrom: domain.Time(at.UnixNano())}
	for i := range 4 {
		ticket, _, _, err := a.reserve(owner, netip.MustParseAddr("192.0.2.1"), false, func() time.Time { return at })
		if i == 3 {
			var limited *abuse.RateLimited
			if !errors.As(err, &limited) {
				t.Fatal("利用者の投稿間隔", err)
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = a.limits.Commit(ticket); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostingResourcePolicyPersistence(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	if _, err := repo.ValidationHTTPServer(); err != nil {
		t.Fatal(err)
	}
	var site siteState
	if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != max(postingResourcesReader, specialNetworkReader, dnsDisplayReader) {
		t.Fatal("reader境界", err, site.MinimumReader)
	}
	row := repo.site.State().Rows[postingResourcesCollection+":active"]
	var policy postingResourcePolicy
	if err := strictjson.Decode(row.Value, &policy); err != nil || policy.At <= 0 {
		t.Fatal(err)
	}
	// 二度目のサーバー構築では境界を書き直さない。
	if _, err := repo.ValidationHTTPServer(); err != nil {
		t.Fatal(err)
	}
	if repo.site.State().Rows[postingResourcesCollection+":active"].Revision != row.Revision {
		t.Fatal("境界が再保存された")
	}
	state := repo.site.State()
	state.Rows = maps.Clone(state.Rows)
	site.MinimumReader = postingResourcesReader - 1
	raw, _ := json.Marshal(site)
	changed := state.Rows["site:state"]
	changed.Value = raw
	state.Rows["site:state"] = changed
	if _, err := inspectSiteState(state, site.ID, cfg.Public.BaseURL); err == nil {
		t.Fatal("旧readerで受付境界を解釈した")
	}
	repo.Close()
	repo = nil
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("再起動", err)
	}
	var restored postingResourcePolicy
	if err = strictjson.Decode(repo.site.State().Rows[postingResourcesCollection+":active"].Value, &restored); err != nil || restored != policy {
		t.Fatal("保存境界", err, restored)
	}
	if validatePostingResources("active", row.Value, row.Value) == nil || validatePostingResources("active", nil, []byte(`{"enabled_at_ns":"0"}`)) == nil {
		t.Fatal("不正な境界更新")
	}
}
