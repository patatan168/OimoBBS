// 検証済み回線設定の共有でも、破損・書換え・不正な状態遷移を拒否することを確認する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestNetworkValidationCacheRejectsChangedBytes(t *testing.T) {
	var cache networkValidationCache
	v := networkState{Version: 1, Config: defaultNetworkConfig(), Rows: networkRows{}}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	first, err := cache.decode(raw)
	if err != nil || first.Version != 1 {
		t.Fatal(first.Version, err)
	}
	for _, invalid := range [][]byte{append(bytes.Clone(raw), []byte("{}")...), bytes.Replace(raw, []byte("{"), []byte(`{"unknown":true,`), 1), []byte(`{"version":1,"version":1}`), []byte(`null`), bytes.Repeat([]byte(" "), store.MaxNetworkValueJSON+1)} {
		if _, err := cache.decode(invalid); err == nil {
			t.Fatal("cached validation accepted invalid bytes")
		}
	}
	invalidState := v
	invalidState.Config.IntervalHours = 0
	changed, err := json.Marshal(invalidState)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(changed, raw) {
		t.Fatal("fixture did not change")
	}
	if _, err := cache.decode(changed); err == nil {
		t.Fatal("accepted changed invalid configuration")
	}
	// 呼出元が持つ入力byteの書換えを、キャッシュ内の一致判定や復号結果へ伝播させない。
	original := bytes.Clone(raw)
	for i := range raw {
		raw[i] = ' '
	}
	second, err := cache.decode(original)
	if err != nil || second.Config.IntervalHours != 24 {
		t.Fatal("input buffer changed cached state", err)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 8 {
				value, err := cache.decode(original)
				if err != nil || value.Version != 1 {
					t.Error("concurrent validation", err)
				}
			}
		})
	}
	workers.Wait()
}

func TestNetworkValidationCacheKeepsTransitionChecks(t *testing.T) {
	base := networkState{Version: 1, Config: defaultNetworkConfig(), Rows: networkRows{}}
	for _, mode := range []string{"version_jump", "configuration_without_version", "attempt_regression"} {
		t.Run(mode, func(t *testing.T) {
			previous, next := base, base
			switch mode {
			case "version_jump":
				next.Version = 3
			case "configuration_without_version":
				next.Config.IntervalHours = 48
			case "attempt_regression":
				previous.LastAttempt, next.LastAttempt = domain.Time(100), domain.Time(50)
				previous.AttemptVersion, next.AttemptVersion = 1, 1
				previous.Error, next.Error = "fetch_failed", "fetch_failed"
			}
			old, err := json.Marshal(previous)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			// それぞれの値を単独で完全検証した後も、組合せの不正は拒否する。
			if validateNetworkValue("active", nil, old) != nil || validateNetworkValue("active", nil, raw) != nil {
				t.Fatal("invalid standalone fixture")
			}
			if validateNetworkValue("active", old, raw) == nil {
				t.Fatal("accepted invalid transition after cached validation")
			}
		})
	}
	old, _ := json.Marshal(base)
	base.Version = 2
	base.Config.IntervalHours = 48
	next, _ := json.Marshal(base)
	if err := validateNetworkValue("active", old, next); err != nil {
		t.Fatal("valid configuration update rejected", err)
	}
	if err := validateNetworkValue("other", old, next); err == nil {
		t.Fatal("invalid key accepted")
	}
}
