// 構築時の検算結果を再利用しても、元frameの完全再検証と次状態が一致し旧状態を変更しない。
package postinput

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"reflect"
	"testing"
	"time"
)

func TestBuildPreparedMatchesCanonicalFrameAndState(t *testing.T) {
	for _, capEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "cap"}[capEnabled], func(t *testing.T) {
			c := buildContext()
			c.Policy.UserPostLimit = 50
			if capEnabled {
				c.Cap = &Cap{ID: domain.ID{10}, Name: "運営", Revision: 1}
			}
			var previous *domain.Thread
			for i := 0; i < 50; i++ {
				fields := map[string]string{"MESSAGE": "日本語 <投稿> 😀"}
				if i == 0 {
					fields["subject"] = "検算"
				}
				if i%2 == 1 {
					fields["mail"] = "sage"
				}
				input, err := Prepare(fields, i == 0, domain.Hash{3})
				if err != nil {
					t.Fatal(err)
				}
				target := uint64(123)
				if i == 0 {
					target = 0
				}
				c.Now = c.Now.Add(time.Second)
				c.Bump = domain.U64(i + 1)
				c.Dedup = input.Dedup(domain.Hash{3}, c.Board, target, []byte{4, 192, 0, 2, 1}, domain.Time(c.Now.UnixNano()))
				before, _ := json.Marshal(previous)
				result, err := BuildPrepared(previous, input, c)
				if err != nil {
					t.Fatal(i, err)
				}
				checked, err := store.ValidateThreadFrame(previous, result.Raw)
				if err != nil || !reflect.DeepEqual(checked, result.Next) {
					t.Fatal("canonical state differs", i, err)
				}
				encoded, err := store.EncodeFrame(result.Frame)
				if err != nil || !reflect.DeepEqual(encoded, result.Raw) {
					t.Fatal("canonical bytes differ", i, err)
				}
				parsed, err := domain.ParseOperation(result.Frame.Records[0].JSON)
				if err != nil || !reflect.DeepEqual(parsed, result.Operation) {
					t.Fatal("canonical operation differs", i, err)
				}
				after, _ := json.Marshal(previous)
				if string(before) != string(after) {
					t.Fatal("old state changed")
				}
				previous = result.Next
			}
		})
	}
}
