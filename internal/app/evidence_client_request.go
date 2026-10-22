// 選択済み接続観測をclient/requestへ投影し、申告値を解決済み接続元へ昇格させない。
package app

import (
	"oimobbs/internal/evidence"
	"slices"
)

// projectAcceptedClient は保存済み解決結果と未検証の転送ヘッダを分けて返す。
// 生ヘッダから経路を再解釈せず、保存されていないreported_chainは不明とする。
func projectAcceptedClient(obs *evidence.HTTPObservation) map[string]any {
	if obs == nil {
		return nil
	}
	missing := []evidence.MissingField{{Field: "reported_chain", Reason: "not_recorded_in_capture"}}
	for _, field := range obs.MissingFields {
		if slices.Contains([]string{"proxy_profile_id", "proxy_config_revision", "origin_endpoint", "reverse_dns"}, field.Field) {
			missing = append(missing, field)
		}
	}
	return map[string]any{"reverse_dns": obs.ReverseDNS, "resolved_ip": obs.Resolved.IP, "resolved_port": obs.Resolved.Port, "source": obs.ClientSource, "proxy_profile_id": obs.ProxyProfileID, "proxy_config_revision": obs.ProxyConfigRevision, "verified_proxy_chain": obs.VerifiedProxyChain, "reported_chain": nil, "reported_headers": obs.ReportedHeaders, "reported_headers_verified": false, "origin_endpoint": obs.OriginEndpoint, "missing_fields": missing}
}

// projectAcceptedHTTPRequest は許可リストの元表現・観測量・取得状態を維持する。
// 未保存の板aliasは現在のaliasやcanonical hostから補完しない。
func projectAcceptedHTTPRequest(obs *evidence.HTTPObservation) map[string]any {
	if obs == nil {
		return nil
	}
	var alias any
	missing := []evidence.MissingField{}
	if obs.BoardAliasUsed != nil {
		alias = *obs.BoardAliasUsed
	} else {
		missing = append(missing, evidence.MissingField{Field: "board_alias_used", Reason: "not_recorded_in_capture"})
	}
	return map[string]any{"canonical_host": obs.CanonicalHost, "board_alias_used": alias, "missing_fields": missing}

}
