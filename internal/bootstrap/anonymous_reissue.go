// 匿名Cookieの新規発行をIP/ホスト単位で数え、段階待機と毎時10回分の回復を耐久保存する。
package bootstrap

import (
	"errors"
	"fmt"
	"net/netip"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strings"
	"time"
)

const anonymousReissueCapacity = 200000

type tokenReissue struct {
	Origin    domain.Hash `json:"origin_hmac"`
	Count     uint32      `json:"count"`
	Recovered domain.Time `json:"recovered_at_ns"`
	Updated   domain.Time `json:"updated_at_ns"`
	Expires   domain.Time `json:"expires_at_ns"`
}

// tokenReissueOrigin はIPと確認済みホストだけを用途別HMACへ変換する。未確認ホストは空欄で束ねる。
func (r *Repository) tokenReissueOrigin(ip netip.Addr) domain.Hash {
	return identity.MAC(r.admission.secret[:], "oimo/token-issue/ip-host/v1", []byte(ip.Unmap().String()), []byte(r.networkHosts.Hostname(ip)))
}

// anonymousOriginWait は任意Cookieモードで待機Cookieを捨てた再送にも、既存の期限を適用する。
// 正常Cookieは自身の署名期限を使う。回復済み・待機満了の起点を延長せず、要求だけでは加算しない。
func anonymousOriginWait(counter tokenReissue, now time.Time) error {
	if counter.Count < 10 {
		return nil
	}
	at := domain.Time(now.UnixNano())
	if at < counter.Updated {
		return abuse.ErrRateClock
	}
	hours := uint64(at-counter.Recovered) / uint64(time.Hour)
	if hours*10 >= uint64(counter.Count-9) {
		return nil
	}
	ready := time.Unix(int64(counter.Updated)/int64(time.Second)+int64(counter.Count-9)*600, 0)
	if !now.Before(ready) {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrAnonymousRecast, &abuse.RateLimited{RetryAfter: uint64((ready.Sub(now) + time.Second - 1) / time.Second)})
}

// advanceTokenReissue は固定した時間境界で10回分ずつ返し、新規発行の一回だけを加算する。
// 要求ごとに回復の起点を動かさず、連続発行中も毎時回復する。大きすぎる値は巻き戻さない。
func advanceTokenReissue(prior tokenReissue, origin domain.Hash, at domain.Time) (tokenReissue, error) {
	if origin == (domain.Hash{}) || at <= 0 || at < prior.Updated {
		return tokenReissue{}, abuse.ErrRateClock
	}
	count, recovered := prior.Count, prior.Recovered
	if count != 0 {
		hours := uint64(at-recovered) / uint64(time.Hour)
		count -= uint32(min(uint64(count), hours*10))
		recovered += domain.Time(hours * uint64(time.Hour))
	}
	if count == 0 {
		recovered = at
	}
	if count >= anonymousReissueCapacity {
		return tokenReissue{}, abuse.ErrRateCapacity
	}
	count++
	duration := domain.Time((uint64(count)+9)/10) * domain.Time(time.Hour)
	if recovered > domain.Time(1<<63-1)-duration {
		return tokenReissue{}, abuse.ErrRateClock
	}
	return tokenReissue{Origin: origin, Count: count, Recovered: recovered, Updated: at, Expires: recovered + duration}, nil
}

// nextTokenReissue は所有mutex内で一行を選び、発行後の値とCookieへ署名する待機期限を返す。
// 未回復の行を別の主体のために追い出さず、完全回復した行は既存の期限回収へ任せる。
func (r *Repository) nextTokenReissue(origin domain.Hash, at domain.Time) (tokenReissue, int64, error) {
	state := r.site.State()
	prior := tokenReissue{}
	if row, ok := state.Rows["token_reissue:"+origin.String()]; ok {
		if err := strictjson.Decode(row.Value, &prior); err != nil {
			return prior, 0, err
		}
	} else {
		rows := 0
		for name := range state.Rows {
			if strings.HasPrefix(name, "token_reissue:") {
				rows++
			}
		}
		if rows >= anonymousReissueCapacity {
			return prior, 0, abuse.ErrRateCapacity
		}
	}
	next, err := advanceTokenReissue(prior, origin, at)
	if err != nil {
		return next, 0, err
	}
	ready := int64(0)
	if next.Count >= 10 {
		ready = int64(at)/int64(time.Second) + int64(next.Count-9)*600
	}
	return next, ready, nil
}

// validateTokenReissue は保存・snapshot・復旧で同じ完全型、回復境界、加算を検査する。
func validateTokenReissue(key string, old, raw []byte) error {
	var value tokenReissue
	if err := strictjson.Decode(raw, &value); err != nil {
		return err
	}
	if value.Origin == (domain.Hash{}) || key != value.Origin.String() || value.Count < 1 || value.Count > anonymousReissueCapacity || value.Recovered <= 0 || value.Updated < value.Recovered || value.Updated-value.Recovered >= domain.Time(time.Hour) {
		return store.ErrCorrupt
	}
	duration := domain.Time((uint64(value.Count)+9)/10) * domain.Time(time.Hour)
	if value.Recovered > domain.Time(1<<63-1)-duration || value.Expires != value.Recovered+duration {
		return store.ErrCorrupt
	}
	if len(old) == 0 {
		return nil
	}
	var prior tokenReissue
	if err := strictjson.Decode(old, &prior); err != nil {
		return err
	}
	expected, err := advanceTokenReissue(prior, value.Origin, value.Updated)
	if err != nil || expected != value || prior.Origin != value.Origin {
		return errors.New("invalid anonymous reissue transition")
	}
	return nil
}
