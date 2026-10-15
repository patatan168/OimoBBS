// 独立回収鍵のCLI生成・巡回・定期起動と引数の排他を検査する。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/bootstrap"
)

func TestIndependentReplayCLI(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(parent, "cleanup.key")
	work := filepath.Join(parent, "work")
	if e := os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	var out, diag bytes.Buffer
	if e := run([]string{"backup", "init-replay-cleanup-key", "--output", key}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	if e := run([]string{"backup", "init-replay-cleanup-key", "--output", key}, &out, &diag); e == nil {
		t.Fatal("key overwritten")
	}
	out.Reset()
	if e := run([]string{"backup", "sweep-replay", "--work-parent", work, "--cleanup-key", key, "--apply"}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	var sweep bootstrap.ReplaySweepReport
	if e := json.Unmarshal(out.Bytes(), &sweep); e != nil || sweep.RestoreReady || len(sweep.Items) != 0 {
		t.Fatal(sweep, e)
	}
	sentinel := errors.New("stop writer")
	writer := &watchReportWriter{err: sentinel}
	if e := run([]string{"backup", "watch-replay", "--work-parent", work, "--cleanup-key", key}, writer, &diag); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	for _, args := range [][]string{
		{"backup", "sweep-replay", "--work-parent", work, "--cleanup-key", key, "--keys", parent},
		{"backup", "reclaim-replay", "--input", work, "--cleanup-key", key, "--keys", parent},
		{"backup", "watch-replay", "--work-parent", work, "--cleanup-key", key, "--keys", parent},
		{"backup", "init-replay-cleanup-key", "--output", key, "--config", "config.json"},
	} {
		if e := run(args, &out, &diag); e == nil {
			t.Fatal("invalid input accepted", args)
		}
	}
}
