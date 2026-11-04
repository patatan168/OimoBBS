// HTTP/3の起動設定と、UDP観測を保存する前のreader互換性境界。
package bootstrap

import (
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const http3Reader = 107

// UnmarshalJSON はHTTP/3の省略をfalseへ補い、他の必須項目を維持する。
func (c *PublicConfig) UnmarshalJSON(raw []byte) error {
	type wire PublicConfig
	var value wire
	if err := strictjson.DecodeDefaultBool(raw, &value, "http3", false); err != nil {
		return err
	}
	*c = PublicConfig(value)
	return nil
}

// EnableHTTP3 はUDP・HTTP/3の観測値を保存する前に旧readerでの起動を止める。
// UDP待受を確保した起動だけで呼び、既定のHTTP/2起動には変更を加えない。
func (r *Repository) EnableHTTP3() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return err
	}
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	if site.MinimumReader >= http3Reader {
		return nil
	}
	site.MinimumReader = http3Reader
	if err := appendControl(r.site, "http3_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{site.ID.String()}); err != nil {
		r.stopped = true
		return err
	}
	return nil
}
