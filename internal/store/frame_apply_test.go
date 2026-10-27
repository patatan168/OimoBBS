// 厳密なframe検査と型付き適用を連続させた経路が、従来の拒否条件と索引を保つことを確認する。
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"oimobbs/internal/domain"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestFrameApplyRecordsMatchesReplay(t *testing.T) {
	_, create := fixtureCreate(t)
	var state *domain.Thread
	for _, raw := range [][]byte{create, packReply(t, create, 2), packReply(t, create, 3)} {
		frame, err := decodeFrameView(raw)
		if err != nil {
			t.Fatal(err)
		}
		want, err := replayFrameReference(state, frame)
		if err != nil {
			t.Fatal(err)
		}
		got, records, err := applyFrameRecords(state, frame, sha256.Sum256(raw))
		if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(records, frameRecords(frame)) {
			t.Fatalf("復旧結果と不一致: %v", err)
		}
		snapshot, _ := json.Marshal(got)
		clear(raw)
		actual, _ := json.Marshal(got)
		if !bytes.Equal(snapshot, actual) {
			t.Fatal("入力buffer変更が候補へ波及した")
		}
		state = got
	}
}

func TestFrameTypedPathsRejectInvalidJSON(t *testing.T) {
	for _, body := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `{"a":"\u0000"}`, `{"a":1} x`, `{"a":NaN}`, `{"schema":1,"unexpected":true}`} {
		t.Run(body, func(t *testing.T) {
			// 正しいCRCを持つ不正JSONを作り、破損検査だけで拒否していないことを確認する。
			placeholder := []byte("{}" + strings.Repeat(" ", len(body)-2))
			raw, err := EncodeFrame(Frame{1, []Record{{domain.NewID(), placeholder, nil}}})
			if err != nil {
				t.Fatal(err)
			}
			copy(raw[40:], body)
			n := int(le.Uint32(raw))
			le.PutUint32(raw[8+n:], checksum(raw[8:8+n]))
			frame, err := decodeFrameLayout(raw)
			if err != nil {
				t.Fatal("外形は正当", err)
			}
			if _, _, err = applyFrameRecords(nil, frame, sha256.Sum256(raw)); err == nil {
				t.Fatal("不正操作を受理")
			}
			if _, err = ValidateThreadFrame(nil, raw); err == nil {
				t.Fatal("不正候補を受理")
			}
			if decodeControlCandidate(raw).err == nil {
				t.Fatal("不正制御操作を受理")
			}
		})
	}
}

func FuzzFrameTypedApplyMatchesStrict(f *testing.F) {
	var fixture struct {
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	body, err := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if err != nil {
		f.Fatal(err)
	}
	if err = json.Unmarshal(body, &fixture); err != nil {
		f.Fatal(err)
	}
	dat, err := hex.DecodeString(fixture.DAT)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := EncodeFrame(Frame{1, []Record{{domain.NewID(), fixture.Operation, dat}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		frame, e := decodeFrameView(raw)
		var want *domain.Thread
		if e == nil {
			want, e = replayFrameReference(nil, frame)
		}
		layout, actual := decodeFrameLayout(raw)
		var got *domain.Thread
		if actual == nil {
			got, _, actual = applyFrameRecords(nil, layout, sha256.Sum256(raw))
		}
		if (e == nil) != (actual == nil) || e == nil && !reflect.DeepEqual(got, want) {
			t.Fatal("厳密検査と適用の受理条件が不一致", e, actual)
		}
	})
}

// replayFrameReference は変更前の「完全復号→連番照合→適用」を比較用に残す。
func replayFrameReference(old *domain.Thread, f Frame) (*domain.Thread, error) {
	candidate := old
	for i, r := range f.Records {
		op, err := domain.ParseOperation(r.JSON)
		if err != nil {
			return nil, err
		}
		if uint64(op.Revision) != f.FirstSeq+uint64(i) || len(f.Records) > 1 && op.Type != "append" {
			return nil, ErrCorrupt
		}
		candidate, err = domain.Apply(candidate, op, r.DAT)
		if err != nil {
			return nil, err
		}
	}
	return candidate, nil
}
