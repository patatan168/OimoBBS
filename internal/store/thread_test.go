// 実filesystem上で保存・復旧・破損隔離・symlink拒否を検査する。
package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"testing"
)

func fixtureCreate(t *testing.T) (domain.ID, []byte) {
	t.Helper()
	b, e := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Board     domain.ID       `json:"board_id_hex"`
		ID        domain.ID       `json:"operation_id_hex"`
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	dat, _ := hex.DecodeString(f.DAT)
	frame, e := EncodeFrame(Frame{1, []Record{{f.ID, f.Operation, dat}}})
	if e != nil {
		t.Fatal(e)
	}
	return f.Board, frame
}
func TestThreadDiskRecovery(t *testing.T) {
	owner, frame := fixtureCreate(t)
	dir := privateTemp(t)
	log, e := CreateThread(dir, owner, 1700000000, frame)
	if e != nil {
		t.Fatal(e)
	}
	if e = log.Close(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "1700000000", "delta-000001.wal")
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.Write([]byte{1, 2, 3})
	_ = f.Close()
	log, e = OpenThread(dir, owner, 1700000000)
	if e != nil {
		t.Fatal(e)
	}
	if log.State().After.PostCount != 1 {
		t.Fatal("count")
	}
	_ = log.Close()
	s, _ := os.Stat(path)
	if s.Size() != int64(64+len(frame)) {
		t.Fatal("tail not truncated")
	}
	f, _ = os.OpenFile(path, os.O_RDWR, 0)
	_, _ = f.WriteAt([]byte{0}, int64(64+len(frame)-1))
	_ = f.Close()
	if _, e = OpenThread(dir, owner, 1700000000); e == nil {
		t.Fatal("corrupt create accepted")
	}
}
func TestOrphanAndSymlink(t *testing.T) {
	owner, frame := fixtureCreate(t)
	dir := privateTemp(t)
	log, e := CreateThread(dir, owner, 1, frame)
	if e != nil {
		t.Fatal(e)
	}
	_ = log.Close()
	path := filepath.Join(dir, "1", "current.json")
	if e = os.Rename(path, path+".old"); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenThread(dir, owner, 1); e == nil {
		t.Fatal("orphan promoted")
	}
	if e = os.Symlink("current.json.old", path); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenThread(dir, owner, 1); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestUnacknowledgedAppendRecovery(t *testing.T) {
	owner, frame := fixtureCreate(t)
	dir := privateTemp(t)
	log, e := CreateThread(dir, owner, 1, frame)
	if e != nil {
		t.Fatal(e)
	}
	old := log.State()
	f, _, e := ReadFrame(bytes.NewReader(frame))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	var create domain.Create
	if e = json.Unmarshal(op.Payload, &create); e != nil {
		t.Fatal(e)
	}
	post := create.Posts[0]
	post.Number = 2
	op.Type = "append"
	op.Revision = 2
	op.Versions.Thread = 1
	op.After.PostCount = 2
	op.After.UserCount = 2
	op.After.DATBytes *= 2
	op.Dedup.PostNumber = 2
	op.Payload, _ = json.Marshal(domain.Append{Posts: []domain.Post{post}})
	raw, _ := json.Marshal(op)
	appendFrame, e := EncodeFrame(Frame{2, []Record{{domain.NewID(), raw, f.Records[0].DAT}}})
	if e != nil {
		t.Fatal(e)
	}
	if r := log.Append(appendFrame); r.Status != Durable {
		t.Fatal(r)
	}
	if old.After.PostCount != 1 {
		t.Fatal("old state mutated")
	}
	_ = log.Close()
	log, e = OpenThread(dir, owner, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	if log.State().After.PostCount != 2 || log.State().Revision != 2 {
		t.Fatal("complete append not recovered")
	}
	stat, _ := log.file.Stat()
	bad := bytes.Clone(appendFrame)
	bad[len(bad)-1] ^= 1
	if r := log.Append(bad); r.Status != NotWritten {
		t.Fatal(r)
	}
	after, _ := log.file.Stat()
	if after.Size() != stat.Size() {
		t.Fatal("rejected frame written")
	}
}

func privateTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
