// 板追加の投稿方式を初期設定・再送確認・保存内容HMACへ接続する。
package bootstrap

import (
	"context"
	"reflect"

	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

// initialBoardSettings は公開開始時から適用する通常板またはCAP専用板の設定を返す。
func initialBoardSettings(policy string) boardSettings {
	s := defaultBoardSettings()
	if policy == "cap_only" {
		s.Posting.Create, s.Posting.Reply = policy, policy
	}
	return s
}

// validInitialBoardSettings は板追加で指定可能な二種類の完全な初期設定だけを許す。
func validInitialBoardSettings(s boardSettings) bool {
	return (s.Posting.Create == "anyone" || s.Posting.Create == "cap_only") && reflect.DeepEqual(s, initialBoardSettings(s.Posting.Create))
}

// checkBoardCreationPolicy は既存板の投稿方式を変更せず、異なる方式での追加を拒否する。
// 呼出元がsiteロックを持ち、稼働板の設定は板ワーカー内で読む。
func (r *Repository) checkBoardCreationPolicy(ctx context.Context, id domain.ID, policy string) error {
	check := func() (any, error) {
		var v boardValue
		if err := strictjson.Decode(r.boards[id].State().Rows["board:state"].Value, &v); err != nil {
			return nil, err
		}
		if v.Settings.Posting.Create != policy || v.Settings.Posting.Reply != policy {
			return nil, &adminFailure{status: 409, code: "BOARD_POLICY_EXISTS"}
		}
		return nil, nil
	}
	if b := r.posting[id]; b != nil {
		_, err := b.worker.Submit(ctx, check)
		return err
	}
	_, err := check()
	return err
}
