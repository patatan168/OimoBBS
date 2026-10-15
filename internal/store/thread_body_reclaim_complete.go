// 本文回収の再開用整合検査と、回収完了後の物理不在検査を区別する。
package store

import (
	"context"
	"os"
)

// CheckBodyReclamationComplete は署名対象の残存fileがないことと、元ディレクトリの不在を検査する。
// CheckReclaimedBodyは再開可能な残存を許すため、原本回収の前提確認にはこちらを使う。
// 所有者の排他内で実行し、pathの再作成を検査から後続回収まで防ぐ。
func CheckBodyReclamationComplete(ctx context.Context, dir string, files []BodySourceFile) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := CheckReclaimedBody(ctx, dir, files); e != nil {
		return e
	}
	_, e := os.Lstat(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	return ErrIncomplete
}
