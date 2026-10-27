// 回線分類の保存だけを2MiBまで許可し、通常操作と入力JSONの上限を維持する。
package store

import (
	"encoding/json"
	"oimobbs/internal/strictjson"
)

// MaxNetworkOperationJSON は回線分類とサイト状態だけを含む制御操作の上限。
const MaxNetworkOperationJSON = 2 << 20

// MaxNetworkValueJSON は制御操作の包みと管理receiptに128KiBの余白を残す。
const MaxNetworkValueJSON = MaxNetworkOperationJSON - (128 << 10)

// decodeStoredControlOperation は拡張サイズの場合、サイト設定・回線分類と、その小さな管理再送記録だけを許可する。
func decodeStoredControlOperation(raw []byte) (ControlOperation, error) {
	var op ControlOperation
	if err := strictjson.DecodeLimit(raw, &op, MaxNetworkOperationJSON); err != nil {
		return op, err
	}
	if len(raw) <= MaxOperationJSON {
		return op, nil
	}
	found := false
	for _, m := range op.Mutations {
		switch {
		case m.Collection == "network" && m.Key == "active":
			found = true
		case m.Collection == "admin_receipt" && validExtendedNetworkReceipt(op, m):
		case m.Collection == "site" && m.Key == "state":
			if len(m.Value) > strictjson.MaxBytes {
				return op, ErrCorrupt
			}
		default:
			return op, ErrCorrupt
		}
	}
	if !found {
		return op, ErrCorrupt
	}
	return op, nil
}

// validateStoredControlValue は所有列に関係なく、分類のactive行だけに余裕を与える。
func validateStoredControlValue(collection, key string, raw json.RawMessage) error {
	if collection == "network" && key == "active" {
		return strictjson.ValidateLimit(raw, MaxNetworkValueJSON)
	}
	return strictjson.Validate(raw)
}

// validExtendedNetworkReceipt は回線設定の再送記録だけを小さな付随行として許可する。
// 完全型と認可情報の照合は通常どおりcollection validatorで行う。
func validExtendedNetworkReceipt(op ControlOperation, m Mutation) bool {
	if len(m.Value) > 4<<10 || op.Result.Code != "network_config" || op.Actor.Kind != "admin" || op.Actor.Reason != "network_config" {
		return false
	}
	var tag struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(m.Value, &tag) == nil && tag.Type == "network_change"
}
