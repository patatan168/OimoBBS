package postinput

import (
	"bytes"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/textcodec"
	"strings"
	"testing"
	"time"
)

func buildContext() BuildContext {
	return BuildContext{AnonymousID: domain.ID{9}, Board: domain.ID{1}, SourceIP: "192.0.2.1", Now: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC), PublicKey: domain.Hash{2}, Bump: 1,
		Versions: domain.Versions{Site: 1, Board: 1}, Policy: domain.Policy{Version: 1, IDMode: "required", SlipMode: "none", UserPostLimit: 2, DATUserLimit: 524288, Commands: []string{}},
		Limits: Limits{Name: 96, Mail: 64, Title: 128, Body: 4096, Lines: 60, Noname: "名無しさん", EndMessage: "終了しました。"}}
}
func applyInput(t *testing.T, old *domain.Thread, fields map[string]string, c BuildContext) (*domain.Thread, string) {
	t.Helper()
	in, e := Prepare(fields, old == nil, domain.Hash{3})
	if e != nil {
		t.Fatal(e)
	}
	key := uint64(0)
	if old != nil {
		key = 123
	}
	c.Dedup = in.Dedup(domain.Hash{3}, c.Board, key, []byte{4, 192, 0, 2, 1}, domain.Time(c.Now.UnixNano()))
	raw, e := Build(old, in, c)
	if e != nil {
		t.Fatal(e)
	}
	f, _, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	next, e := domain.Apply(old, op, f.Records[0].DAT)
	if e != nil {
		t.Fatal(e)
	}
	dat, e := textcodec.Decode(f.Records[0].DAT)
	if e != nil {
		t.Fatal(e)
	}
	return next, dat
}
func TestBuildCreateAndLastSageReply(t *testing.T) {
	c := buildContext()
	old, dat := applyInput(t, nil, map[string]string{"subject": "日本語😀", "FROM": "名#secret", "MESSAGE": "<script>\r\n本文"}, c)
	if !strings.Contains(dat, "&lt;script&gt;<br>本文") || !strings.Contains(dat, "◆") || !strings.Contains(dat, "ID:") || strings.Contains(dat, "secret") || !strings.HasSuffix(dat, "日本語&#128512;\n") {
		t.Fatal(dat)
	}
	c.Now = c.Now.Add(time.Second)
	c.Bump = 2
	next, dat := applyInput(t, old, map[string]string{"mail": "sage", "MESSAGE": "返信"}, c)
	if next.After.State != "stopped" || next.After.PostCount != 3 || next.After.UserCount != 2 || next.After.BumpValue != 1 || strings.Count(dat, "\n") != 2 {
		t.Fatal(next.After, dat)
	}
	if !strings.Contains(dat, "終了しました。") || strings.Contains(dat, "日本語") {
		t.Fatal(dat)
	}
	in, _ := Prepare(map[string]string{"MESSAGE": "追記"}, false, domain.Hash{3})
	if _, e := Build(next, in, c); e == nil {
		t.Fatal("stopped thread accepted")
	}
}
func TestBuildLimitsAndAge(t *testing.T) {
	c := buildContext()
	c.Policy.UserPostLimit = 100
	old, _ := applyInput(t, nil, map[string]string{"subject": "題", "MESSAGE": "初回"}, c)
	c.Now = c.Now.Add(time.Second)
	c.Bump = 9
	next, _ := applyInput(t, old, map[string]string{"MESSAGE": "返信"}, c)
	if next.After.BumpValue != 9 {
		t.Fatal(next.After)
	}
	in, _ := Prepare(map[string]string{"subject": "題", "MESSAGE": "日本"}, true, domain.Hash{3})
	c.Dedup = in.Dedup(domain.Hash{3}, c.Board, 0, []byte{4, 192, 0, 2, 1}, domain.Time(c.Now.UnixNano()))
	for _, change := range []func(*BuildContext){func(c *BuildContext) { c.Limits.Body = 3 }, func(c *BuildContext) { c.Policy.DATUserLimit = 1 }, func(c *BuildContext) { c.Limits.NameRequired = true }} {
		bad := c
		change(&bad)
		if _, e := Build(nil, in, bad); e == nil {
			t.Fatal("invalid limits accepted")
		}
	}
}
func TestDedupMeaningfulInput(t *testing.T) {
	fields := map[string]string{"subject": "題", "MESSAGE": "本文", "FROM": "名#secret", "time": "1"}
	key := domain.Hash{3}
	board := domain.ID{1}
	a, _ := Prepare(fields, true, key)
	d := a.Dedup(key, board, 0, []byte{4, 127, 0, 0, 1}, 1)
	fields["time"] = "2"
	fields["csrf"] = "ignored"
	b, _ := Prepare(fields, true, key)
	other := b.Dedup(key, board, 0, []byte{4, 127, 0, 0, 1}, 2)
	if d.Request != other.Request || d.Subject != other.Subject {
		t.Fatal("transport fields affected dedup")
	}
	fields["FROM"] = "名#other-secret"
	b, _ = Prepare(fields, true, key)
	if b.Dedup(key, board, 0, []byte{4, 127, 0, 0, 1}, 2).Request == d.Request {
		t.Fatal("secret change not bound")
	}
	if a.Dedup(key, domain.ID{2}, 0, []byte{4, 127, 0, 0, 1}, 2).Subject == d.Subject {
		t.Fatal("subject not board bound")
	}
}

func TestBuildConfigurableEndingPosts(t *testing.T) {
	for _, endings := range [][]EndResponse{{}, {{Name: "終了係", Mail: "sage", Body: "終了\n<script>"}}, {{Name: "案内", Body: "終了"}, {Name: "運営", Mail: "notice", Body: "次スレへ"}}} {
		c := buildContext()
		c.Policy.UserPostLimit = 1
		c.Limits.EndResponses = endings
		thread, dat := applyInput(t, nil, map[string]string{"subject": "終了試験", "MESSAGE": "最後の投稿"}, c)
		if thread.After.State != "stopped" || thread.After.UserCount != 1 || thread.After.PostCount != uint32(1+len(endings)) || strings.Count(dat, "\n") != 1+len(endings) {
			t.Fatal(thread.After, dat)
		}
		for i, want := range endings {
			got := thread.Posts[i+1]
			if got.Number != uint32(i+2) || got.Name != want.Name || got.Mail != want.Mail || got.Body != want.Body || got.Private != nil {
				t.Fatal(got)
			}
		}
	}
}
