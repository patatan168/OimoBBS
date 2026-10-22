// 保存済みintentと不一致のcontrolを修復名目で上書きしないことを検証する。
package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/domain"
)

func TestCompleteControlCreationRefusesDifferentIntent(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial", true: "complete"}[complete], func(t *testing.T) {
			parent := privateTemp(t)
			dir := filepath.Join(parent, "control")
			h := Header{Kind: 2, Owner: domain.NewID(), Generation: 1}
			validate := func(c, k string, old, next json.RawMessage) error { return nil }
			op := ControlOperation{Schema: 1, Seq: 1, Actor: domain.Actor{Kind: "system", Reason: "bootstrap"}, Mutations: []Mutation{{Collection: "key_watermark", Key: "thread", Value: json.RawMessage(`{"last_reserved_key":"0"}`)}}, Result: ControlResult{Code: "created", Targets: []string{}}}
			raw, err := json.Marshal(op)
			if err != nil {
				t.Fatal(err)
			}
			recordID := domain.NewID()
			frame, err := EncodeFrame(Frame{FirstSeq: 1, Records: []Record{{ID: recordID, JSON: raw}}})
			if err != nil {
				t.Fatal(err)
			}
			log, err := CreateControl(dir, h, frame, validate)
			if err != nil {
				t.Fatal(err)
			}
			if err = log.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "control-000001.wal")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !complete {
				if err = os.Remove(filepath.Join(dir, "control.current")); err != nil {
					t.Fatal(err)
				}
			}
			op.Mutations[0].Value = json.RawMessage(`{"last_reserved_key":"1"}`)
			raw, _ = json.Marshal(op)
			different, _ := EncodeFrame(Frame{FirstSeq: 1, Records: []Record{{ID: recordID, JSON: raw}}})
			if got, err := CompleteControlCreation(dir, h, different, validate); err == nil {
				got.Close()
				t.Fatal("different intent accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("existing evidence modified")
			}
		})
	}
}
