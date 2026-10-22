// CAPコマンドの非公開intentと完了状態を保存し、再送の対象集合を固定する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const capCommandsReader = 79
const maxCapBanMinutes = 100 * 365 * 24 * 60

type capCommandReceipt struct {
	Key     domain.Hash `json:"request_key_hmac"`
	Request domain.Hash `json:"request_hmac"`
	Cap     domain.ID   `json:"cap_id"`
	Board   domain.ID   `json:"board_id"`
	Thread  domain.U64  `json:"thread_key"`
	Post    uint32      `json:"post_number"`
	Kind    string      `json:"kind"`
	Minutes uint32      `json:"duration_minutes"`
	Rules   []domain.ID `json:"rule_ids"`
	Done    bool        `json:"done"`
	Created domain.Time `json:"created_at_ns"`
	Expires domain.Time `json:"expires_at_ns"`
}

// validateCapCommandReceipt は旧field省略・未知field・状態の後戻りを許さない。
func validateCapCommandReceipt(key string, old, next json.RawMessage) error {
	var v capCommandReceipt
	if strictjson.Decode(next, &v) != nil || key != v.Key.String() || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.Cap == (domain.ID{}) || v.Board == (domain.ID{}) || v.Thread == 0 || v.Post == 0 || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || (v.Expires != v.Created+86400e9 && v.Expires != v.Created+30e9) || v.Rules == nil || len(v.Rules) > 1000 {
		return store.ErrCorrupt
	}
	if v.Kind != "ban" && v.Kind != "unban" && v.Kind != "delete" && v.Kind != "stop" {
		return store.ErrCorrupt
	}
	if v.Kind == "ban" {
		if v.Minutes == 0 || v.Minutes > maxCapBanMinutes && v.Minutes != permanentDenyMinutes {
			return store.ErrCorrupt
		}
	} else if v.Minutes != 0 {
		return store.ErrCorrupt
	}
	if v.Kind != "unban" && len(v.Rules) != 0 {
		return store.ErrCorrupt
	}
	for i, id := range v.Rules {
		if id == (domain.ID{}) || i > 0 && v.Rules[i-1].String() >= id.String() {
			return store.ErrCorrupt
		}
	}
	if len(old) == 0 {
		if v.Done {
			return store.ErrCorrupt
		}
		return nil
	}
	var prior capCommandReceipt
	if strictjson.Decode(old, &prior) != nil {
		return store.ErrCorrupt
	}
	if prior.Expires <= v.Created {
		if v.Done {
			return store.ErrCorrupt
		}
		return nil
	}
	if prior.Done || !v.Done {
		return store.ErrCorrupt
	}
	prior.Done = true
	if !reflect.DeepEqual(prior, v) {
		return store.ErrCorrupt
	}
	return nil
}

// saveCapCommandReceipt は本文・Cookie・接続元を含めず、操作と結果を管理監査へ同期する。
func (b *postingBoard) saveCapCommandReceipt(v capCommandReceipt) error {
	reason := "cap_command_" + v.Kind
	if v.Done {
		reason += "_applied"
	}
	kid := uint32(8)
	actor := domain.Actor{Kind: "admin", ID: &v.Cap, Reason: reason, Request: &v.Request, Idempotency: &v.Key, KeyID: &kid}
	change := mutation("cap_command", v.Key.String(), v, nil)
	change.ExpectedRevision = b.control.State().Rows["cap_command:"+v.Key.String()].Revision
	frame, err := controlFrame(b.control.State(), domain.NewID(), domain.Time(b.clock().UnixNano()), reason, []store.Mutation{change}, []string{fmt.Sprint(v.Thread), fmt.Sprint(v.Post)}, actor)
	if err != nil {
		return err
	}
	if b.control.Append(frame).Status != store.Durable {
		b.stopped = true
		return ErrPostingUnavailable
	}
	return nil
}

func capCommandRules(b *postingBoard, subject domain.Hash) []domain.ID {
	ids := []domain.ID{}
	for _, entry := range b.sortedDenials() {
		if entry.Enabled && entry.Reason == "manual" && entry.Effect.Type == "deny" && len(entry.Conditions) == 1 && entry.Conditions[0].Field == "token" && entry.Conditions[0].Operator == "exact" && entry.Conditions[0].Value == subject.String() {
			ids = append(ids, entry.ID)
		}
	}
	slices.SortFunc(ids, func(a, b domain.ID) int {
		if a.String() < b.String() {
			return -1
		}
		if a == b {
			return 0
		}
		return 1
	})
	return ids
}

// snapshotCapCommandReceipt は完了済み現在値を検査し、WALの初回intent制約を維持する。
func snapshotCapCommandReceipt(key string, raw json.RawMessage) error {
	var v capCommandReceipt
	if strictjson.Decode(raw, &v) != nil {
		return store.ErrCorrupt
	}
	if !v.Done {
		return validateCapCommandReceipt(key, nil, raw)
	}
	v.Done = false
	prior, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := validateCapCommandReceipt(key, nil, prior); err != nil {
		return err
	}
	return validateCapCommandReceipt(key, prior, raw)
}

// capCommandOperationKey は短命の暗黙再送が満了した後の新しい操作を区別する。
func capCommandOperationKey(b *postingBoard, v capCommandReceipt) domain.Hash {
	return identity.MAC(b.dedupKey[:], "oimo/cap-command-operation/v1", v.Key[:], []byte(fmt.Sprint(v.Created)))
}
