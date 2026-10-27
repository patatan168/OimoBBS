// 案件試験のcontent原本へ、公開部と非公開部が異なる実WALフレームを与える。
package disclosure

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
)

func caseFixtureFrame(t *testing.T, id domain.ID, at domain.Time) []byte {
	t.Helper()
	dat := []byte("public-name<>sage<>date<>PUBLIC_BODY<>public-title\n")
	posts := []domain.Post{{Number: 1, Kind: "user", Visibility: "visible", Created: at, Name: "public-name", Mail: "sage", Body: "PUBLIC_BODY", Private: &domain.Private{SourceIP: "PRIVATE_CONNECTION_SECRET", RateKeys: []domain.RateKey{}}, DATLength: uint32(len(dat))}}
	payload, e := json.Marshal(domain.Create{Title: "public-title", Policy: domain.Policy{Commands: []string{}}, Posts: posts})
	if e != nil {
		t.Fatal(e)
	}
	op, e := json.Marshal(domain.Operation{Type: "create", Revision: 1, Committed: at, Dedup: &domain.Dedup{PostNumber: 1}, Payload: payload})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = domain.ParseOperation(op); e != nil {
		t.Fatal("fixture operation", e)
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: 1, Records: []store.Record{{ID: id, JSON: op, DAT: dat}}})
	if e != nil {
		t.Fatal(e)
	}
	return frame
}
