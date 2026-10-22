// 解析して板へ照合する投稿キーを原本へ固定する。現在の板設定から過去値を補完しない。
package evidence

// WithBoardAlias はフォームから受け取った板キーを観測の独立コピーへ保存する。
// 投稿先の所有板との一致は呼出元が確認する。URL全体や秘密queryは受け取らない。
func (v HTTPObservation) WithBoardAlias(alias string) (HTTPObservation, error) {
	v.BoardAliasUsed = &alias
	if err := ValidateHTTPObservationValue(v); err != nil {
		return HTTPObservation{}, err
	}
	return v, nil
}

func validObservedBoardAlias(alias *string) bool {
	if alias == nil {
		return true
	}
	v := *alias
	if len(v) == 0 || len(v) > 32 || v[0] < 'a' || v[0] > 'z' || v == "test" || v == "web" || v == "admin" {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
