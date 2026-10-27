// 原本回収のsnapshot候補だけを許し、無関係な世代/未知名を読み飛ばさない。
package bootstrap

import (
	"oimobbs/internal/store"
	"testing"
)

func TestPostingJournalDirectoryGenerationScope(t *testing.T) {
	m := store.ControlManifest{Generation: 2, Delta: store.Delta{File: "control-000002.wal"}, Snapshot: &store.ControlSnapshot{File: "control-000002.snap"}}
	for _, tc := range []struct {
		name   string
		intent bool
		want   bool
	}{
		{"control.current", false, true},
		{"control-000002.wal", false, true},
		{"control-000002.snap", false, true},
		{"control-000001.wal", false, false},
		{"control-000001.wal", true, true},
		{"control-000003.snap", true, true},
		{"control-000004.snap", true, false},
		{"control-000000.wal", true, false},
		{"control-99999999999999999999.wal", true, false},
		{"unknown", true, false},
		{"control-000001.wal.tmp", true, false},
	} {
		if got := knownPostingJournalFile(tc.name, m, tc.intent); got != tc.want {
			t.Errorf("%s intent=%v: %v", tc.name, tc.intent, got)
		}
	}
}
