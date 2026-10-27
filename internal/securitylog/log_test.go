// 検出集約の再起動保持、7日期限、保存済みダミーの非表示を確認する。
package securitylog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionRestartAndCounts(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Hour).Add(30 * time.Minute)
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []Event{
		{At: now, Source: "similar", Reason: "類似本文の連投", Body: "広告の本文"},
		{At: now.Add(time.Minute), Source: "similar", Reason: "類似本文の連投", Body: "広告の本文"},
		{At: now, Source: "similar", Reason: "類似本文の連投", Body: "広告の本文", Rejected: true},
		{At: now, Source: "similar", Reason: "類似本文の連投", Body: "広告の本文", Dummy: true},
		{At: now.Add(-8 * 24 * time.Hour), Source: "waf", Reason: "path", Rejected: true},
	} {
		l.Add(e)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	v, err := l.View(now.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Rows) != 2 || v.Groups != 2 || v.Detected != 2 || v.Rejected != 1 {
		t.Fatalf("%+v", v)
	}
	if len(v.Reasons) != 1 || v.Reasons[0].Detected != 2 || v.Reasons[0].Rejected != 1 {
		t.Fatalf("%+v", v.Reasons)
	}
}

func TestBoundedSamplesKeepCounts(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now()
	for i := range maxSamples + 20 {
		l.Add(Event{At: now, Source: "waf", Reason: "path", Path: string(rune(1000 + i)), Rejected: true})
	}
	v, err := l.View(now)
	if err != nil {
		t.Fatal(err)
	}
	if v.Rejected != maxSamples+20 || v.Limited != 20 {
		t.Fatalf("counts %d limited %d", v.Rejected, v.Limited)
	}
}

func TestFilteringFindAndSaveFailure(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	dummy := Event{At: now, Source: "similar", Reason: "確認用", Body: "表示しない過去の確認用ログ", Dummy: true}
	l.Add(dummy)
	l.Add(Event{At: now.Add(-time.Minute), Source: "similar", Reason: "類似本文", Body: "古い比較対象"})
	for i := range 70 {
		l.Add(Event{At: now, Source: "waf", Reason: "path", Path: fmt.Sprint(i), Rejected: true})
	}
	v, err := l.Filtered(now, Filter{Source: "similar"})
	if err != nil || len(v.Rows) != 1 {
		t.Fatal("filter before pagination", v, err)
	}
	row, err := l.Find(v.Rows[0].ID, now)
	if err != nil || row.Body != "古い比較対象" {
		t.Fatal("find", row, err)
	}
	if _, err = l.Find(bucket(dummy)+":"+fingerprint(dummy), now); !os.IsNotExist(err) {
		t.Fatal("historical dummy sample exposed", err)
	}
	if _, err = l.Find("../../etc/passwd", now); err == nil {
		t.Fatal("unsafe ID")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	// 時間別ファイルをdirectoryで塞ぐと、保存失敗を一覧とCloseへ返す。
	next := now.Add(time.Hour)
	if err = os.Mkdir(filepath.Join(dir, bucket(Event{At: next})+".json"), 0700); err != nil {
		t.Fatal(err)
	}
	l, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Add(Event{At: next, Source: "waf", Reason: "path"})
	v, err = l.View(next)
	if err != nil {
		t.Fatal(err)
	}
	if v.Error == "" {
		t.Fatal("save failure hidden")
	}
	if err = l.Close(); err == nil {
		t.Fatal("close failure hidden")
	}
}

func TestSaturatedQueueDoesNotBlockAndKeepsCounts(t *testing.T) {
	// writerを起動しない固定長待機列で、通常投稿の経路が保存待ちにならないことを再現する。
	l := &Log{dir: t.TempDir(), queue: make(chan message, 2), done: make(chan struct{}), overflow: map[string]Row{}}
	now := time.Now()
	for range 100 {
		l.Add(Event{At: now, Source: "similar", Reason: "類似本文", Body: "比較する本文"})
	}
	if len(l.queue) != 2 || len(l.overflow) != 1 {
		t.Fatal("bounded queue", len(l.queue), len(l.overflow))
	}
	go l.run()
	v, err := l.View(now)
	if err != nil || v.Detected != 100 || v.Limited != 98 {
		t.Fatal("overflow counts", v, err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
}
