// CAP専用スレッドの入力、保存条件、匿名投稿拒否を検査する。
package postinput

import (
	"bytes"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
)

func TestCapOnlyInputAndBuild(t *testing.T) {
	fields := map[string]string{"subject": "告知", "MESSAGE": "本文", "oimo_cap_only": "1"}
	in, err := Prepare(fields, true, domain.Hash{3})
	if err != nil || !in.CapOnly {
		t.Fatal(in, err)
	}
	c := buildContext()
	if _, err = Build(nil, in, c); err == nil {
		t.Fatal("anonymous restricted creation")
	}
	c.Cap = &Cap{ID: domain.ID{7}, Name: "運営", Revision: 1}
	old, _ := applyInput(t, nil, fields, c)
	if !old.Policy.CapOnly {
		t.Fatal("restriction not persisted")
	}
	c.Cap = nil
	reply, _ := Prepare(map[string]string{"MESSAGE": "返信"}, false, domain.Hash{3})
	if _, err = Build(old, reply, c); err == nil {
		t.Fatal("anonymous reply accepted")
	}
	c.Cap = &Cap{ID: domain.ID{8}, Name: "別のCAP", Revision: 1}
	next, _ := applyInput(t, old, map[string]string{"MESSAGE": "返信"}, c)
	if !next.Policy.CapOnly || next.After.UserCount != 2 || next.After.State != "stopped" {
		t.Fatal(next)
	}
	for _, raw := range []string{"0", "true", "2"} {
		fields["oimo_cap_only"] = raw
		if _, err := Prepare(fields, true, domain.Hash{3}); err == nil {
			t.Fatal("invalid flag", raw)
		}
	}
	fields["oimo_cap_only"] = "1"
	delete(fields, "subject")
	if _, err := Prepare(fields, false, domain.Hash{3}); err == nil {
		t.Fatal("reply changes restriction")
	}
}

func TestCapOnlyDedupBinding(t *testing.T) {
	fields := map[string]string{"subject": "告知", "MESSAGE": "本文"}
	plain, _ := Prepare(fields, true, domain.Hash{3})
	fields["oimo_cap_only"] = "1"
	restricted, _ := Prepare(fields, true, domain.Hash{3})
	a := plain.Dedup(domain.Hash{3}, domain.ID{1}, 0, []byte{4, 1, 2, 3, 4}, 1)
	b := restricted.Dedup(domain.Hash{3}, domain.ID{1}, 0, []byte{4, 1, 2, 3, 4}, 1)
	if a.Request == b.Request {
		t.Fatal("restriction not bound to confirmation/retry")
	}
}

// TestCapOnlyWALRejectsAnonymous は上位の投稿構築を迂回してもWAL検算で匿名追記を拒否する。
func TestCapOnlyWALRejectsAnonymous(t *testing.T) {
	c := buildContext()
	c.Cap = &Cap{ID: domain.ID{7}, Name: "運営", Revision: 1}
	old, _ := applyInput(t, nil, map[string]string{"subject": "題", "MESSAGE": "本文", "oimo_cap_only": "1"}, c)
	unrestricted := *old
	unrestricted.Policy.CapOnly = false
	c.Cap = nil
	in, err := Prepare(map[string]string{"MESSAGE": "匿名返信"}, false, domain.Hash{3})
	if err != nil {
		t.Fatal(err)
	}
	c.Dedup = in.Dedup(domain.Hash{3}, c.Board, 123, []byte{4, 192, 0, 2, 1}, domain.Time(c.Now.UnixNano()))
	frame, err := Build(&unrestricted, in, c)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := store.ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	op, err := domain.ParseOperation(f.Records[0].JSON)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := domain.Apply(old, op, f.Records[0].DAT); err == nil {
		t.Fatal("anonymous WAL bypass")
	}
}
