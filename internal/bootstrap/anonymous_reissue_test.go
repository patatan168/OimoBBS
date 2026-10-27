// 発行回数の毎時回復・長い負債・厳格な保存型・回収時刻を検証する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
	"time"
)

func TestTokenReissueHourlyRecovery(t *testing.T) {
	origin := domain.Hash{1}
	start := domain.Time(1000 * int64(time.Second))
	value := tokenReissue{}
	for i := 1; i <= 20; i++ {
		var err error
		value, err = advanceTokenReissue(value, origin, start+domain.Time(i-1)*domain.Time(time.Second))
		if err != nil || value.Count != uint32(i) || value.Recovered != start {
			t.Fatal("increment", i, value, err)
		}
	}
	for _, tc := range []struct {
		offset    time.Duration
		count     uint32
		recovered time.Duration
	}{
		{time.Hour - time.Nanosecond, 21, 0},
		{time.Hour, 12, time.Hour},
		{2 * time.Hour, 3, 2 * time.Hour},
		{3 * time.Hour, 1, 3 * time.Hour},
	} {
		var err error
		value, err = advanceTokenReissue(value, origin, start+domain.Time(tc.offset))
		if err != nil || value.Count != tc.count || value.Recovered != start+domain.Time(tc.recovered) {
			t.Fatal("hour boundary", tc, value, err)
		}
	}
}

func TestTokenReissueShapeAndExpiry(t *testing.T) {
	origin := domain.Hash{1}
	start := domain.Time(time.Second)
	value, err := advanceTokenReissue(tokenReissue{}, origin, start)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(value)
	if err = validateAnonymousValue("token_reissue", origin.String(), nil, raw); err != nil {
		t.Fatal(err)
	}
	if err = validateAnonymousValue("token_reissue", domain.Hash{2}.String(), nil, raw); err == nil {
		t.Fatal("wrong key accepted")
	}
	next, err := advanceTokenReissue(value, origin, start+1)
	if err != nil {
		t.Fatal(err)
	}
	newRaw, _ := json.Marshal(next)
	if err = validateTokenReissue(origin.String(), raw, newRaw); err != nil {
		t.Fatal("valid transition", err)
	}
	next.Count = 4
	newRaw, _ = json.Marshal(next)
	if err = validateTokenReissue(origin.String(), raw, newRaw); err == nil {
		t.Fatal("invented increment accepted")
	}
	for i := 2; i <= 20; i++ {
		value, err = advanceTokenReissue(value, origin, start+domain.Time(i))
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, _ = json.Marshal(value)
	state := store.ControlState{Rows: map[string]store.ControlRow{"token_reissue:" + origin.String(): {Value: raw}}}
	if names, err := expiredControlNames(state, 1, start+domain.Time(61*time.Minute)); err != nil || len(names) != 0 {
		t.Fatal("unrecovered debt expired with issue history", names, err)
	}
	if names, err := expiredControlNames(state, 1, start+domain.Time(2*time.Hour)); err != nil || len(names) != 1 {
		t.Fatal("fully recovered counter retained", names, err)
	}
	value.Count = anonymousReissueCapacity
	value.Expires = value.Recovered + domain.Time(anonymousReissueCapacity/10)*domain.Time(time.Hour)
	if _, err = advanceTokenReissue(value, origin, value.Updated); !errors.Is(err, abuse.ErrRateCapacity) {
		t.Fatal("counter wrapped at capacity", err)
	}
}
