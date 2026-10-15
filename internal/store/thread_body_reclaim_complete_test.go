// 途中回収/空ディレクトリ/取消を完了扱いせず、全消去後だけ完了を認める。
package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBodyReclamationCompleteRequiresDirectoryRemoval(t *testing.T) {
	owner, frame := fixtureCreate(t)
	parent := privateTemp(t)
	log, e := CreateThread(parent, owner, 1, frame)
	if e != nil {
		t.Fatal(e)
	}
	files, e := log.BodySourceFiles(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if e = log.Close(); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(parent, "1")
	if e = CheckBodyReclamationComplete(t.Context(), dir, files); !errors.Is(e, ErrIncomplete) {
		t.Fatal("remaining matching files accepted", e)
	}
	if e = RemoveReclaimedBody(t.Context(), dir, files, nil); e != nil {
		t.Fatal(e)
	}
	if e = CheckBodyReclamationComplete(t.Context(), dir, files); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = CheckBodyReclamationComplete(t.Context(), dir, files); !errors.Is(e, ErrIncomplete) {
		t.Fatal("empty recreated directory accepted", e)
	}
}

func TestBodyReclamationCompleteRejectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e := CheckBodyReclamationComplete(ctx, filepath.Join(privateTemp(t), "absent"), nil); !errors.Is(e, context.Canceled) {
		t.Fatal("absent path bypassed cancellation", e)
	}
}
