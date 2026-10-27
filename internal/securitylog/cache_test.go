// writer専用の単一bucket再利用について、保存失敗・外部変更・保持上限を検査する。
package securitylog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestBucketRowsReuseAndInvalidate(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	e := Event{At: now, Source: "similar", Reason: "reason", Body: "本文"}
	name := bucket(e)
	path := filepath.Join(dir, name+".json")
	rows := map[string]Row{}
	merge(rows, e)
	info, err := saveSnapshot(path, rows)
	if err != nil {
		t.Fatal(err)
	}
	var cache bucketRows
	cache.remember(name, rows, info)
	got, err := cache.load(dir, name)
	if err != nil || reflect.ValueOf(got).Pointer() != reflect.ValueOf(rows).Pointer() {
		t.Fatal("cache miss", err)
	}
	// 同じ長さ・日時でも、atomic置換による別inodeの保存を読み直す。
	replacement := map[string]Row{}
	merge(replacement, e)
	merge(replacement, e)
	if err := save(path, replacement); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	got, err = cache.load(dir, name)
	if err != nil || got[fingerprint(e)].Count != 2 {
		t.Fatal("replacement not observed", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	got, err = cache.load(dir, name)
	if err != nil || len(got) != 0 {
		t.Fatal("deleted bucket reused", err)
	}
}

func TestBucketRowsBoundsAndExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	e := Event{At: now, Source: "waf", Reason: "reason"}
	name := bucket(e)
	rows := map[string]Row{}
	merge(rows, e)
	info, err := saveSnapshot(filepath.Join(dir, name+".json"), rows)
	if err != nil {
		t.Fatal(err)
	}
	var cache bucketRows
	cache.remember(name, rows, info)
	cache.expire(now.Add(retention + 2*time.Hour))
	if cache.rows != nil {
		t.Fatal("expired bucket retained")
	}
	large := make(map[string]Row, maxSamples*2+1)
	for i := 0; i <= maxSamples*2; i++ {
		large[string(rune(i))] = Row{}
	}
	cache.remember(name, large, info)
	if cache.rows != nil {
		t.Fatal("unbounded rows cached")
	}
	f, err := os.Create(filepath.Join(dir, "oversized"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxBucketBytes + 1); err != nil {
		t.Fatal(err)
	}
	info, err = f.Stat()
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	cache.remember(name, rows, info)
	if cache.rows != nil {
		t.Fatal("oversized file cached")
	}
}

func TestBucketRowsDoesNotBypassReadPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failure requires non-root")
	}
	dir := t.TempDir()
	e := Event{At: time.Now().UTC(), Source: "waf", Reason: "path"}
	name := bucket(e)
	path := filepath.Join(dir, name+".json")
	rows := map[string]Row{}
	merge(rows, e)
	info, err := saveSnapshot(path, rows)
	if err != nil {
		t.Fatal(err)
	}
	var cache bucketRows
	cache.remember(name, rows, info)
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0600) })
	if _, err := cache.load(dir, name); !os.IsPermission(err) {
		t.Fatal("read failure hidden", err)
	}
	if cache.rows != nil {
		t.Fatal("unreadable file retained")
	}
}

func TestWriterCacheDiscardsUnsavedCounts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failure requires non-root")
	}
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700); l.Close() })
	e := Event{At: time.Now().UTC(), Source: "waf", Reason: "path"}
	l.Add(e)
	if err := l.flush(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	l.Add(e)
	if err := l.flush(); err == nil {
		t.Fatal("save failure not reported")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	l.Add(e)
	if err := l.Close(); err == nil {
		t.Fatal("save failure forgotten")
	}
	rows, err := load(filepath.Join(dir, bucket(e)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if rows[fingerprint(e)].Count != 2 {
		t.Fatal("unsaved count reused", rows)
	}
}

func TestWriterCacheMatchesReloadedBatches(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	now := time.Now().UTC().Truncate(time.Hour)
	model := map[string]map[string]Row{}
	for batch := 0; batch < 60; batch++ {
		changed := map[string]bool{}
		for index := 0; index < 16; index++ {
			i := batch*16 + index
			e := Event{At: now.Add(-time.Duration((batch/10)%3)*time.Hour + time.Duration(i%59)*time.Second), Source: "similar", Reason: fmt.Sprint(i % 2), Body: fmt.Sprintf("本文%d", i), Rejected: i%5 == 0, Dummy: i%7 == 0}
			if i%97 == 0 {
				e.Source = "invalid\xff"
				e.Body = "body\xff"
			}
			l.Add(e)
			name := bucket(e)
			if model[name] == nil {
				model[name] = map[string]Row{}
			}
			merge(model[name], e)
			changed[name] = true
		}
		if err := l.flush(); err != nil {
			t.Fatal(err)
		}
		// 従来writerが次batchの前に行っていたJSON再読込を期待値側で再現する。
		for name := range changed {
			raw, err := json.Marshal(model[name])
			if err != nil {
				t.Fatal(err)
			}
			var restored map[string]Row
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			model[name] = restored
			actual, err := load(filepath.Join(dir, name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, restored) {
				t.Fatalf("batch %d differs", batch)
			}
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWriterCacheReloadsCorruptionAndSaveFailure(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	e := Event{At: now, Source: "waf", Reason: "path"}
	path := filepath.Join(dir, bucket(e)+".json")
	l.Add(e)
	if err := l.flush(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	l.Add(e)
	if err := l.Close(); err == nil {
		t.Fatal("corruption masked by cache")
	}
	// 成功したbucketをdirectoryへ置換しても、次の保存失敗を隠さない。
	dir = t.TempDir()
	l, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, bucket(e)+".json")
	l.Add(e)
	if err := l.flush(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	l.Add(e)
	if err := l.Close(); err == nil {
		t.Fatal("save failure masked by cache")
	}
}

func BenchmarkSecurityLogWriter(b *testing.B) {
	// fsync呼出しを保ち、媒体待ちを除いて同じ256本文例の更新CPUを比較する。
	dir, err := os.MkdirTemp("/dev/shm", "oimo-securitylog-bench-")
	if err != nil {
		b.Skip("tmpfs unavailable:", err)
	}
	b.Cleanup(func() { os.RemoveAll(dir) })
	now := time.Now().UTC()
	rows := map[string]Row{}
	for i := 0; i < maxSamples; i++ {
		merge(rows, Event{At: now, Source: "similar", Reason: "類似本文", Body: string(rune(0x3040+i)) + "比較用の本文"})
	}
	if err := save(filepath.Join(dir, bucket(Event{At: now})+".json"), rows); err != nil {
		b.Fatal(err)
	}
	l, err := Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	e := Event{At: now, Source: "similar", Reason: "類似本文", Body: string(rune(0x3040)) + "比較用の本文"}
	l.Add(e)
	if err := l.flush(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		l.Add(e)
		if err := l.flush(); err != nil {
			b.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		b.Fatal(err)
	}
}
