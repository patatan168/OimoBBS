// 独占する未公開状態へ、有界候補の全検査後に制御WALを反映する。
package store

// applyControlReplay は復旧が独占する状態だけを更新する。公開済みStateには使わない。
// 解析済み操作の全mutationを検査し、失敗時は元のmap/seqを変更しない。
func applyControlReplay(old ControlState, kind uint16, frame Frame, validate ValueValidator) (ControlState, error) {
	if validate == nil || len(frame.Records) != 1 || len(frame.Records[0].DAT) != 0 || len(controlCollections[kind]) == 0 {
		return old, ErrCorrupt
	}
	op, e := decodeControlOperation(frame)
	if e != nil {
		return old, e
	}
	if len(op.Mutations) < 1 || len(op.Mutations) > 256 {
		return old, ErrCorrupt
	}
	candidate, e := applyControlOperation(controlReplaySubset(old, op.Mutations), kind, frame.FirstSeq, op, validate, false)
	if e != nil {
		return old, e
	}
	return mergeControlReplay(old, candidate, op.Mutations), nil
}

// controlReplaySubset は当該操作群が参照する行だけを候補へ渡す。
// 一操作は最大256行、一括追記は最大MaxCommitFrames操作で呼出側が制限する。
// CAS/期限削除の検査は各mutationの旧行を参照するため、未対象行を複製する必要がない。
func controlReplaySubset(old ControlState, mutations []Mutation) ControlState {
	subset := ControlState{Seq: old.Seq, Rows: make(map[string]ControlRow, len(mutations))}
	for _, m := range mutations {
		key := m.Collection + ":" + m.Key
		if row, found := old.Rows[key]; found {
			subset.Rows[key] = row
		}
	}
	return subset
}

// mergeControlReplay は全検査済み候補だけを独占する未公開mapへ反映する。
// 通常追記ではSync完了後に使い、公開済みmapは呼出側で先に複製する。
func mergeControlReplay(old, candidate ControlState, mutations []Mutation) ControlState {
	if old.Rows == nil {
		old.Rows = make(map[string]ControlRow, len(candidate.Rows))
	}
	for _, m := range mutations {
		key := m.Collection + ":" + m.Key
		if row, found := candidate.Rows[key]; found {
			old.Rows[key] = row
		} else {
			delete(old.Rows, key)
		}
	}
	old.Seq = candidate.Seq
	return old
}
