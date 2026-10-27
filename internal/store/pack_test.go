// pack全体の設計互換・境界・改変・DAT範囲読み出しを検証する。
package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/textcodec"
	"os"
	"strings"
	"testing"
)

func packFixture(t testing.TB) []byte {
	t.Helper()
	b, e := os.ReadFile("../../docs/design/fixtures/pack-zstd-layout.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Hex string `json:"pack_hex"`
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	p, e := hex.DecodeString(f.Hex)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPackFixtureRoundTrip(t *testing.T) {
	raw := packFixture(t)
	s, e := DecodePack(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.State.Posts) != 2 || len(s.Dedup) != 2 || len(s.Audit) != 2 {
		t.Fatal("counts")
	}
	dat := bytes.Join(s.State.Lines, nil)
	for _, level := range []uint8{0, 1, 6, 9} {
		encoded, e := EncodePack(s, level)
		if e != nil {
			t.Fatal(level, e)
		}
		restored, e := DecodePack(encoded)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(bytes.Join(restored.State.Lines, nil), dat) {
			t.Fatal("DAT changed")
		}
		for start := 0; start <= len(dat); start++ {
			for _, end := range []int{start, min(start+7, len(dat)), len(dat)} {
				got, e := ReadPackDAT(encoded, uint64(start), uint64(end))
				if e != nil || !bytes.Equal(got, dat[start:end]) {
					t.Fatal(start, end, e)
				}
			}
		}
	}
}
func TestPackFromWAL(t *testing.T) {
	owner, raw := fixtureCreate(t)
	f, _, e := ReadFrame(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	b := NewPackBuilder(nil)
	if e = b.Apply(f); e != nil {
		t.Fatal(e)
	}
	s := b.Snapshot(owner, 1, 2, b.snapshot.LastOperation)
	encoded, e := EncodePack(s, 6)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := DecodePack(encoded)
	if e != nil {
		t.Fatal(e)
	}
	if len(restored.Audit) != 1 || len(restored.Dedup) != 1 || restored.State.Revision != 1 {
		t.Fatal("missing source")
	}
}

// 外側のCRCだけを正しく更新し、内側の構造検証を迂回できないことを確かめる。
func repairPackChecksums(p []byte) {
	for i := 0; i < 5; i++ {
		x := p[96+24*i:]
		off, n := le.Uint64(x), le.Uint64(x[8:])
		if off <= uint64(len(p)) && n <= uint64(len(p))-off {
			le.PutUint32(x[16:], checksum(p[off:off+n]))
		}
	}
	le.PutUint32(p[252:], checksum(p[:252]))
}
func TestPackRejectsCorruption(t *testing.T) {
	source := packFixture(t)
	tests := map[string]func([]byte){
		"schema": func(p []byte) { p[8] = 2 }, "reserved": func(p []byte) { p[232] = 1 },
		"length":           func(p []byte) { le.PutUint64(p[216:], uint64(len(p))+1) },
		"section overflow": func(p []byte) { le.PutUint64(p[104:], ^uint64(0)) },
		"section gap":      func(p []byte) { le.PutUint64(p[120:], le.Uint64(p[120:])+1) },
		"post count":       func(p []byte) { le.PutUint32(p[80:], ^uint32(0)) },
		"block count":      func(p []byte) { le.PutUint32(p[84:], ^uint32(0)) },
		"index reserved":   func(p []byte) { o := le.Uint64(p[120:]); p[o+42] = 1; le.PutUint32(p[o+92:], checksum(p[o:o+92])) },
		"index offset": func(p []byte) {
			o := le.Uint64(p[120:])
			le.PutUint64(p[o+24:], ^uint64(0))
			le.PutUint32(p[o+92:], checksum(p[o:o+92]))
		},
		"index origin": func(p []byte) {
			o := le.Uint64(p[120:])
			le.PutUint64(p[o+72:], 0)
			le.PutUint32(p[o+92:], checksum(p[o:o+92]))
		},
		"dedup count": func(p []byte) {
			o := le.Uint64(p[144:])
			le.PutUint32(p[o+12:], ^uint32(0))
			le.PutUint32(p[o+28:], checksum(p[o:o+28]))
		},
		"dedup crc": func(p []byte) { o := le.Uint64(p[144:]); p[o+32+8] ^= 1 },
		"audit count": func(p []byte) {
			o := le.Uint64(p[168:])
			le.PutUint32(p[o+12:], ^uint32(0))
			le.PutUint32(p[o+28:], checksum(p[o:o+28]))
		},
		"body": func(p []byte) { p[len(p)-1] ^= 1 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p := bytes.Clone(source)
			change(p)
			repairPackChecksums(p)
			if _, e := DecodePack(p); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for i := 0; i < len(source); i++ {
		if _, e := DecodePack(source[:i]); e == nil {
			t.Fatalf("truncation %d", i)
		}
	}
	if _, e := DecodePack(append(bytes.Clone(source), 0)); e == nil {
		t.Fatal("trailing")
	}
	if _, e := ReadPackDAT(source, 2, 1); e == nil {
		t.Fatal("reversed range")
	}
}

func FuzzDecodePack(f *testing.F) {
	f.Add([]byte("OIMOPAK1"))
	b, e := os.ReadFile("../../docs/design/fixtures/pack-zstd-layout.json")
	if e != nil {
		f.Fatal(e)
	}
	var fixture struct {
		Hex string `json:"pack_hex"`
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		f.Fatal(e)
	}
	p, e := hex.DecodeString(fixture.Hex)
	if e != nil {
		f.Fatal(e)
	}
	f.Add(p)
	large, _ := largePackFixture(f)
	f.Add(large)
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > MaxPackFile {
			return
		}
		_, _ = DecodePack(p)
		if len(p) >= 256 {
			p = bytes.Clone(p)
			repairPackChecksums(p)
			_, _ = DecodePack(p)
		}
	})
}

func TestPackBlockBoundariesAndClockOrder(t *testing.T) {
	for _, size := range []int{packDATTarget - 1, packDATTarget, packDATTarget + 1, 200000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, e := DecodePack(packFixture(t))
			if e != nil {
				t.Fatal(e)
			}
			line := []byte("name<><>date<>" + strings.Repeat("x", size-16) + "<>\n")
			// 一レスが目標より長くても分断せず、JSON込み上限内なら保存できる。
			s.State.Posts[1].Body = strings.Repeat("x", size-16)
			s.State.Posts[1].DATLength = uint32(len(line))
			s.State.Lines[1] = line
			s.State.After.DATBytes = domain.U64(len(s.State.Lines[0]) + len(line))
			// user時刻の最大値ではなく、番号が最後のuser時刻を保持する。
			s.State.Posts[1].Created = s.State.Posts[0].Created - 1
			s.State.After.LastUserAt = s.State.Posts[1].Created
			s.Dedup = nil
			s.Audit = nil
			encoded, e := EncodePack(s, 6)
			if e != nil {
				t.Fatal(e)
			}
			_, _, blocks, e := parsePack(encoded)
			if e != nil || len(blocks) != 2 {
				t.Fatal("block split", len(blocks), e)
			}
			got, e := DecodePack(encoded)
			if e != nil || got.State.After.LastUserAt != s.State.After.LastUserAt {
				t.Fatal(e)
			}
			dat := bytes.Join(s.State.Lines, nil)
			start := uint64(len(s.State.Lines[0]) - 1)
			end := start + 3
			actual, e := ReadPackDAT(encoded, start, end)
			if e != nil || !bytes.Equal(actual, dat[start:end]) {
				t.Fatal(e)
			}
		})
	}
	s, e := DecodePack(packFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	s.State.Posts[1].Body = strings.Repeat("x", MaxPackRaw)
	if _, e = EncodePack(s, 6); e == nil {
		t.Fatal("oversize JSON accepted")
	}
}

func TestPackAuditAndDedupExpiry(t *testing.T) {
	owner, frame := fixtureCreate(t)
	f, _, e := ReadFrame(bytes.NewReader(frame))
	if e != nil {
		t.Fatal(e)
	}
	builder := NewPackBuilder(nil)
	if e = builder.Apply(f); e != nil {
		t.Fatal(e)
	}
	at := builder.snapshot.Dedup[0].Value.Expires
	for _, offset := range []domain.Time{-1, 0, 1} {
		s := builder.Snapshot(owner, 1, 2, at+offset)
		raw, e := EncodePack(s, 6)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := DecodePack(raw)
		if e != nil {
			t.Fatal(e)
		}
		want := 0
		if offset < 0 {
			want = 1
		}
		if len(decoded.Dedup) != want {
			t.Fatal("dedup boundary")
		}
	}
	at = builder.snapshot.Audit[0].Expires
	for _, offset := range []domain.Time{-1, 0, 1} {
		s := builder.Snapshot(owner, 1, 2, at+offset)
		raw, e := EncodePack(s, 6)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := DecodePack(raw)
		if e != nil {
			t.Fatal(e)
		}
		want := 0
		if offset < 0 {
			want = 1
		}
		if len(decoded.Audit) != want {
			t.Fatal("audit boundary")
		}
	}
}

func TestPackModerationOriginAndPolicy(t *testing.T) {
	owner, raw := fixtureCreate(t)
	frame, _, e := ReadFrame(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	b := NewPackBuilder(nil)
	if e = b.Apply(frame); e != nil {
		t.Fatal(e)
	}
	old := b.snapshot.State
	p := old.Posts[0]
	p.Visibility = "aboon"
	p.Name = "あぼーん"
	p.Mail = ""
	p.Body = "あぼーん"
	p.Identity = domain.Identity{DateText: "あぼーん"}
	line, e := textcodec.Encode("あぼーん<><>あぼーん<>あぼーん<>example\n", false)
	if e != nil {
		t.Fatal(e)
	}
	p.DATLength = uint32(len(line))
	after := old.After
	after.DATBytes = domain.U64(len(line))
	after.DATGeneration++
	after.LegacyRangeDisabled = true
	id, key, hash := domain.NewID(), uint32(1), domain.Hash{}
	actor := domain.Actor{Kind: "admin", ID: &id, Reason: "moderation", Request: &hash, Idempotency: &hash, KeyID: &key}
	payload, _ := json.Marshal(domain.Redact{Posts: []domain.Post{p}})
	op := domain.Operation{Type: "redact", Revision: 2, Committed: old.Created, Versions: domain.Versions{Site: 1, Board: 1, Thread: 1}, Actor: actor, After: after, Payload: payload}
	encoded, _ := json.Marshal(op)
	if e = b.Apply(Frame{2, []Record{{domain.NewID(), encoded, line}}}); e != nil {
		t.Fatal(e)
	}
	policy := old.Policy
	policy.Version++
	policy.UserPostLimit = 25
	op.Type = "update_policy"
	op.Revision = 3
	op.Payload, _ = json.Marshal(domain.UpdatePolicy{Policy: policy})
	encoded, _ = json.Marshal(op)
	if e = b.Apply(Frame{3, []Record{{domain.NewID(), encoded, nil}}}); e != nil {
		t.Fatal(e)
	}
	pack, e := EncodePack(b.Snapshot(owner, 1, 2, old.Created), 9)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := DecodePack(pack)
	if e != nil {
		t.Fatal(e)
	}
	if restored.Origins[0] != 1 || restored.State.Policy.UserPostLimit != 25 || restored.State.Posts[0].Body != "あぼーん" || restored.State.After.DATGeneration != 2 || len(restored.Audit) != 3 {
		t.Fatal("lost moderation state")
	}
	got, e := ReadPackDAT(pack, 1, uint64(len(line)-1))
	if e != nil || !bytes.Equal(got, line[1:len(line)-1]) {
		t.Fatal("redacted DAT range", e)
	}
}
