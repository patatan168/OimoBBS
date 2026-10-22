// 投稿保護の設定変更が枠の迂回・消費量のリセット・通常枠超過を起こさないことを検査する。
package waf

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"oimobbs/internal/strictjson"
	"strings"
	"testing"
	"time"
)

func TestPostingSettingsStrictAndDefaults(t *testing.T) {
	value := DefaultTrafficSettings()
	raw, _ := json.Marshal(value)
	var decoded TrafficSettings
	if err := strictjson.Decode(raw, &decoded); err != nil || decoded != value {
		t.Fatal(decoded, err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "posting")
	old, _ := json.Marshal(fields)
	if err := strictjson.Decode(old, &decoded); err != nil || decoded != value {
		t.Fatal("既定の保護が変化した", decoded, err)
	}
	for _, posting := range []string{`null`, `{}`, `{"client_rate":10}`, strings.Replace(string(fieldsPosting(value)), `"client_rate":10`, `"client_rate":10,"client_rate":11`, 1)} {
		fields["posting"] = json.RawMessage(posting)
		bad, _ := json.Marshal(fields)
		if len(bad) == 0 { // 重複キーをMarshalに正規化させず、元objectへ直接挿入する。
			bad = []byte(strings.TrimSuffix(string(old), "}") + `,"posting":` + posting + `}`)
		}
		if err := strictjson.Decode(bad, &decoded); err == nil {
			t.Fatal("部分・重複・nullを受理した", posting)
		}
	}
	for _, mutate := range []func(*PostingSettings){
		func(s *PostingSettings) { s.ClientRate = 0 }, func(s *PostingSettings) { s.ClientBurst = 9 },
		func(s *PostingSettings) { s.GlobalRate = 9 }, func(s *PostingSettings) { s.GlobalBurst = 59 },
		func(s *PostingSettings) { s.ClientConcurrent = 0 }, func(s *PostingSettings) { s.GlobalConcurrent = 7 },
		func(s *PostingSettings) { s.GlobalConcurrent = 2049 }, func(s *PostingSettings) { s.GlobalRate = 100001 },
	} {
		next := value
		mutate(&next.Posting)
		if next.Valid() {
			t.Fatal("不正な投稿保護を受理した", next.Posting)
		}
	}
}

func TestConfiguredPostingGlobalRateAndConcurrency(t *testing.T) {
	now := time.Unix(1800000000, 0)
	s := DefaultTrafficSettings()
	s.Posting = PostingSettings{20, 40, 200, 400, 16, 64}
	g := &TrafficGuard{}
	g.Configure(s, now)
	for n := range 400 {
		if d := workAcquire(t, g, Posting, fmt.Sprintf("198.18.0.%d", n/40+1), now); d.Status != 0 {
			t.Fatal(n, d)
		}
	}
	if d := workAcquire(t, g, Posting, "203.0.113.1", now); d.Status != 503 {
		t.Fatal("全体の瞬間枠を超過した", d)
	}
	if d := workAcquire(t, g, Posting, "203.0.113.1", now.Add(5*time.Millisecond)); d.Status != 0 {
		t.Fatal("全体の新しい補充速度が反映されない", d)
	}
	g = &TrafficGuard{}
	g.Configure(s, now)
	var releases []func()
	for n := range 64 {
		release, d := g.AcquireOperation(netip.AddrFrom4([4]byte{198, 18, 0, byte(n + 1)}), Posting, now)
		if d.Status != 0 {
			t.Fatal("設定済みの投稿同時枠へ到達できない", n, d)
		}
		releases = append(releases, release)
	}
	if d := workAcquire(t, g, Posting, "203.0.113.1", now); d.Status != 503 {
		t.Fatal("投稿同時枠を超過した", d)
	}
	s.Posting.GlobalConcurrent = 32
	g.Configure(s, now)
	for _, release := range releases[:32] {
		release()
	}
	if d := workAcquire(t, g, Posting, "203.0.113.1", now); d.Status != 503 {
		t.Fatal("設定変更で実行数がリセットされた", d)
	}
	releases[32]()
	if d := workAcquire(t, g, Posting, "203.0.113.1", now); d.Status != 0 {
		t.Fatal("解放後も投稿枠が回復しない", d)
	}
	for _, release := range releases[33:] {
		release()
	}
}

func fieldsPosting(value TrafficSettings) []byte { raw, _ := json.Marshal(value.Posting); return raw }

func TestPostingSettingsChangesKeepConsumptionAndOuterLimits(t *testing.T) {
	g, now := trafficFixture()
	s := DefaultTrafficSettings()
	s.Posting = PostingSettings{20, 40, 200, 400, 16, 64}
	for range 30 {
		if d := workAcquire(t, g, Posting, "192.0.2.1", now); d.Status != 0 {
			t.Fatal(d)
		}
	}
	g.Configure(s, now)
	// 設定を広げても、消費済みの旧30件に新しい瞬間枠を補充しない。
	if d := workAcquire(t, g, Posting, "192.0.2.1", now); d.Status != 429 {
		t.Fatal("設定変更で枠が復活した", d)
	}
	if d := workAcquire(t, g, Posting, "192.0.2.1", now.Add(50*time.Millisecond)); d.Status != 0 {
		t.Fatal("新しい補充速度が反映されない", d)
	}
	// 外側の同時処理数より大きい投稿枠を保存しても、通常の同時枠を超えない。
	s.GlobalConcurrent = 40
	g.Configure(s, now.Add(time.Second))
	var releases []func()
	for n := 0; n < 40; n++ {
		ip := netip.AddrFrom4([4]byte{198, 18, 0, byte(n + 1)})
		release, d := g.AcquireOperation(ip, Posting, now.Add(time.Second))
		if d.Status != 0 {
			t.Fatal(n, d)
		}
		releases = append(releases, release)
	}
	if d := workAcquire(t, g, Posting, "203.0.113.1", now.Add(time.Second)); d.Status != 503 {
		t.Fatal("通常の同時枠を超過した", d)
	}
	for _, release := range releases {
		release()
	}
	if workLimits(s)[1] != workLimits(DefaultTrafficSettings())[1] || workLimits(s)[2] != workLimits(DefaultTrafficSettings())[2] {
		t.Fatal("照会・認証の固定保護が変化した")
	}
}
