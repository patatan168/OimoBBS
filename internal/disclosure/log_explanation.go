// 提出物の署名済み説明文へ、ログ確認範囲と未確認状態を結合する。
package disclosure

import "fmt"

// SetLogExplanation は呼出元の排他下でログ確認状況の取得元を設定する。
// callbackは本人情報を含めず、対象scopeだけの確認結果を返す。変更は生成済みZIPへ遡及しない。
func (s *Store) SetLogExplanation(explain func(Scope) (string, error)) {
	s.logExplanation = explain
}

// explainLogs は確認元がない場合も未確認を明示し、説明が取れなければ提出物を完成させない。
func (s *Store) explainLogs(scope Scope) ([]byte, error) {
	text := "ログの確認状況：未確認。選択した記録の存在は対象期間全体の欠落ゼロを証明しません。"
	if s.logExplanation != nil {
		var e error
		text, e = s.logExplanation(scope)
		if e != nil {
			return nil, e
		}
	}
	if len(text) == 0 || len(text) > 16<<10 {
		return nil, ErrLimit
	}
	return []byte(fmt.Sprintf("\nログの確認範囲と欠落\n%s\n既知の選択対象の欠落はmanifest.jsonのmissing_record_idsに明記します。未確認期間を記録なしや欠落ゼロとして扱わないでください。\n", text)), nil
}
