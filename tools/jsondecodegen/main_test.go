// 保存型のフィールド追加や独自復号器の変更で生成結果が古くならないことを確認する。
package main

import "testing"

func TestGeneratedDecodersCurrent(t *testing.T) {
	if err := generateAll("../..", true); err != nil {
		t.Fatal(err)
	}
}
