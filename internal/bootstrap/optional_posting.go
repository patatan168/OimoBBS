// 実投稿の確定裁定を非必須HTTP観測へ結び、受理操作IDを推測しない。
package bootstrap

import (
	"context"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// annotateOptionalResult は必須保存結果を優先し、確認・拒否・保存不明を区別する。
func annotateOptionalResult(ctx context.Context, board domain.ID, result LegacyFormResult) {
	outcome := "rejected"
	var operation *domain.ID
	switch {
	case result.Status == store.Durable:
		outcome = "accepted"
		if result.Duplicate {
			outcome = "duplicate"
		}
		if result.OperationID != (domain.ID{}) {
			id := result.OperationID
			operation = &id
		}
	case result.Confirmation != nil:
		outcome = "confirmation"
	case result.Status == store.Unknown:
		outcome = "uncertain"
	}
	_ = evidence.AnnotateOptionalPosting(ctx, board, operation, outcome)
}
