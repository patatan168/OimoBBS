// 圧縮後のfileに余裕があっても、展開後の上限では追記せず、再起動で計数を復元する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestOptionalExpandedCapacityAndRestart(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	site := domain.NewID()
	s, err := OpenOptionalStore(root, site, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	now := time.Now().UTC()
	r := optionalFixture()
	r.Site = site
	r.Received = domain.Time(now.UnixNano())
	r.Finished = r.Received + 100
	r.Until = r.Received + domain.Time(OptionalRetention)
	if err = s.Write(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	day, _ := strconv.ParseUint(now.Format("20060102"), 10, 64)
	j := s.journals[day]
	wal := filepath.Join(root, strconv.FormatUint(day, 10), "control-000001.wal")
	before, err := os.ReadFile(wal)
	if err != nil {
		t.Fatal(err)
	}
	retained := j.retainedBytes
	j.retainedBytes = MaxOptionalDayBytes - 1
	r.ID = domain.NewID()
	if err = s.Write(t.Context(), r); err == nil {
		t.Fatal("compressed file bypassed expanded day capacity")
	}
	after, err := os.ReadFile(wal)
	if err != nil || !bytes.Equal(before, after) || len(j.entries) != 1 {
		t.Fatal("capacity rejection changed durable state", err)
	}
	j.retainedBytes = retained
	// 全日合計も、日別容量とは独立して検査する。
	s.journals[day+1] = &Journal{retainedBytes: MaxOptionalStoreBytes - retained}
	if err = s.Write(t.Context(), r); err == nil {
		t.Fatal("expanded total capacity bypassed")
	}
	delete(s.journals, day+1)
	if err = s.Write(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	want := j.retainedBytes
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenOptionalStore(root, site, key)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.journals[day].retainedBytes; got != want {
		t.Fatalf("restart retained=%d want=%d", got, want)
	}
}
