// Cookie由来の照合用IDだけを提出し、再利用可能なCookieや内部資格情報を除く。
package app

import "encoding/json"

// projectAcceptedCookie は投稿時に検証・保存された匿名Cookieの用途別HMACを返す。
// 現在のCookieや設定から補完しない。同じIDでも投稿者本人の一致は保証しない。
func projectAcceptedCookie(capture map[string]json.RawMessage) (map[string]any, error) {
	identity, err := projectPrincipalIdentity(capture)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": identity["anon_subject_hmac"], "status": identity["token_validation"]}, nil
}
