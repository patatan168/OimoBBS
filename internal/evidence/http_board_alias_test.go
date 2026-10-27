// 原本の板キーを値として固定し、不正なキーの保存を拒否する。
package evidence

import (
	"encoding/json"
	"testing"
)

func TestHTTPObservationBoardAlias(t *testing.T) {
	base := decodedObservationFixture(t)
	for _, alias := range []string{"news", "board_1", "a"} {
		v, err := base.WithBoardAlias(alias)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(v)
		if ValidateHTTPObservation(raw) != nil || v.BoardAliasUsed == nil || *v.BoardAliasUsed != alias {
			t.Fatal(string(raw))
		}
		if base.BoardAliasUsed != nil {
			t.Fatal("input observation mutated")
		}
	}
	for _, alias := range []string{"", "../news", "news?secret=x", "news\n", "NEWS", "test", "web", "admin"} {
		if _, err := base.WithBoardAlias(alias); err == nil {
			t.Fatal("invalid board alias accepted", alias)
		}
	}
}

func TestHTTPObservationRequiresCurrentAliasField(t *testing.T) {
	raw, err := json.Marshal(decodedObservationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "board_alias_used")
	raw, _ = json.Marshal(fields)
	if ValidateHTTPObservation(raw) == nil {
		t.Fatal("observation missing current field accepted")
	}
}
