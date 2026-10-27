// 大きい分類行のWAL・snapshot復元と、他collectionへの拡張流用の拒否を検証する。
package store

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"testing"
)

func TestNetworkControlExtendedLimit(t *testing.T) {
	var id domain.ID
	id[0] = 1
	value, _ := json.Marshal(map[string]string{"data": string(bytes.Repeat([]byte("a"), MaxOperationJSON+1024))})
	op := ControlOperation{Schema: 1, Seq: 1, ExpectedSeq: 0, Committed: 1, Actor: domain.Actor{Kind: "system", Reason: "network_refresh"}, Mutations: []Mutation{{Collection: "network", Key: "active", Value: value}}, Result: ControlResult{Code: "network_refresh", Targets: []string{}}}
	validator := func(collection, key string, old, next json.RawMessage) error {
		return validateStoredControlValue(collection, key, next)
	}
	raw, _ := json.Marshal(op)
	frame := Frame{FirstSeq: 1, Records: []Record{{ID: id, JSON: raw}}}
	encoded, err := EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := ReadFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	state, err := ApplyControl(ControlState{Rows: map[string]ControlRow{}}, 1, decoded, validator)
	if err != nil {
		t.Fatal(err)
	}
	h := Header{Kind: 1, Owner: id, Generation: 1, BaseSeq: 1}
	snapshot, err := EncodeControlSnapshot(h, state, 6, validator)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeControlSnapshot(snapshot, h, validator)
	if err != nil || !bytes.Equal(restored.Rows["network:active"].Value, value) {
		t.Fatal(err)
	}
	for _, collection := range []string{"site", "report", "job"} {
		op.Mutations[0].Collection = collection
		raw, _ = json.Marshal(op)
		frame.Records[0].JSON = raw
		if _, err := EncodeFrame(frame); err == nil {
			t.Fatal("通常操作へ流用した", collection)
		}
	}

	op.Mutations[0].Collection = "network"
	op.Result.Code = "network_config"
	var request domain.Hash
	request[0] = 1
	keyID := uint32(8)
	op.Actor = domain.Actor{Kind: "admin", ID: &id, Reason: "network_config", Request: &request, Idempotency: &request, KeyID: &keyID}
	receipt := Mutation{Collection: "admin_receipt", Key: request.String(), Value: json.RawMessage(`{"type":"network_change"}`)}
	op.Mutations = append(op.Mutations, receipt)
	raw, _ = json.Marshal(op)
	frame.Records[0].JSON = raw
	if _, err := EncodeFrame(frame); err != nil {
		t.Fatal("分類設定の小さい再送記録を拒否した", err)
	}
	op.Mutations[1].Value = json.RawMessage(`{"type":"other"}`)
	raw, _ = json.Marshal(op)
	frame.Records[0].JSON = raw
	if _, err := EncodeFrame(frame); err == nil {
		t.Fatal("別操作の再送記録へ拡張を流用した")
	}
	op.Mutations[1].Value, _ = json.Marshal(map[string]string{"type": "network_change", "padding": string(bytes.Repeat([]byte("a"), 4<<10))})
	raw, _ = json.Marshal(op)
	frame.Records[0].JSON = raw
	if _, err := EncodeFrame(frame); err == nil {
		t.Fatal("小さい付随行の上限を超えた")
	}
	if strictjson.Validate(value) == nil {
		t.Fatal("通常JSON上限を変えた")
	}
	tooLarge, _ := json.Marshal(map[string]string{"data": string(bytes.Repeat([]byte("a"), MaxNetworkValueJSON))})
	if validateStoredControlValue("network", "active", tooLarge) == nil {
		t.Fatal("分類行の上限も超えた")
	}
}
