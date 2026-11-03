// 長い返信群でも元状態を隔離し、不正な末尾を保存前に拒否することを検査する。
package store

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"os"
	"reflect"
	"testing"
)

func TestThreadCandidateGroupIsolation(t *testing.T) {
	for _, mode := range []string{"group", "individual"} {
		for _, invalid := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/valid", true: "/invalid"}[invalid], func(t *testing.T) {
				g, batches, create := newThreadGroupTest(t)
				log := batches[0].Log
				for number := uint32(2); number <= 100; number++ {
					if result := log.Append(packReply(t, create, number)); result.Status != Durable {
						t.Fatal(result)
					}
				}
				old := log.State()
				before, _ := json.Marshal(old)
				records := log.Records()
				body, err := os.ReadFile(log.file.Name())
				if err != nil {
					t.Fatal(err)
				}
				frames := make([][]byte, 64)
				for i := range frames {
					frames[i] = packReply(t, create, uint32(101+i))
				}
				if invalid {
					f, _, err := ReadFrame(bytes.NewReader(frames[63]))
					if err != nil {
						t.Fatal(err)
					}
					op, err := domain.ParseOperation(f.Records[0].JSON)
					if err != nil {
						t.Fatal(err)
					}
					op.After.DATBytes++
					f.Records[0].JSON, _ = domain.MarshalOperation(op)
					frames[63], err = EncodeFrame(f)
					if err != nil {
						t.Fatal(err)
					}
				}
				result := CommitResult{}
				if mode == "group" {
					result = g.Commit([]ThreadAppend{{log, frames}})
				} else {
					result = log.AppendBatch(frames)
				}
				after, _ := json.Marshal(old)
				if !bytes.Equal(before, after) {
					t.Fatal("元状態が変化した")
				}
				if invalid {
					if result.Status != NotWritten || result.Err == nil || log.State() != old || !reflect.DeepEqual(records, log.Records()) {
						t.Fatal("不正な群の部分反映", result)
					}
					stored, err := os.ReadFile(log.file.Name())
					if err != nil || !bytes.Equal(stored, body) || g.file != nil {
						t.Fatal("不正な群を書き込んだ", err)
					}
					return
				}
				if result.Status != Durable || log.State().After.PostCount != 164 {
					t.Fatal(result)
				}
				want := old
				for _, raw := range frames {
					f, _, err := ReadFrame(bytes.NewReader(raw))
					if err != nil {
						t.Fatal(err)
					}
					want, err = applyFrame(want, f)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(log.State(), want) {
					t.Fatal("逐次検算と不一致")
				}
				log.State().Posts[0].Body = "候補の独立性"
				after, _ = json.Marshal(old)
				if !bytes.Equal(before, after) {
					t.Fatal("候補が元履歴を共有した")
				}
			})
		}
	}
}
