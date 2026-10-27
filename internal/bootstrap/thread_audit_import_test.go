// 大きな日別要約集合を有界frameへ分割し、部分Syncから重複なしに再開する。
package bootstrap

import (
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestThreadAuditImportPages(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "resume"}[crash], func(t *testing.T) {
			owner := domain.NewID()
			at := domain.Time(time.Now().UnixNano())
			day := time.Unix(0, int64(at)).UTC().Format("20060102")
			header, first, e := auditInitial(owner, "board", day)
			if e != nil {
				t.Fatal(e)
			}
			parent := t.TempDir()
			if e = os.Chmod(parent, 0700); e != nil {
				t.Fatal(e)
			}
			dir := filepath.Join(parent, "day")
			log, e := store.CreateControl(dir, header, first, auditValueValidator(owner, "board", day))
			if e != nil {
				t.Fatal(e)
			}
			rows := []threadAuditStored{}
			for i := range 300 {
				kind := "append"
				revision := domain.U64(1)
				if i == 0 {
					kind = "create"
					revision = 0
				}
				a := store.PackAudit{ID: domain.NewID(), Seq: domain.U64(i + 1), Type: kind, Committed: at, Expires: at + domain.Time(auditRetention), Actor: domain.Actor{Kind: "anonymous", Reason: "post"}, Versions: domain.Versions{Site: 1, Board: 1, Thread: revision}, Ranges: []store.PackRange{{First: uint32(i + 1), Last: uint32(i + 1)}}}
				rows = append(rows, threadAuditStored{a.ID, "thread_summary", owner, 1, a.Committed, a.Expires, a})
			}
			b := &postingBoard{checkpoint: func(string) {}}
			if crash {
				b.deletionCheckpoint = func(string) error { return errors.New("crash") }
			}
			e = b.importThreadAuditRows(log, rows)
			if (e != nil) != crash {
				t.Fatal(e)
			}
			if crash && len(log.State().Rows) != 129 {
				t.Fatal("unexpected page size", len(log.State().Rows))
			}
			if e = log.Close(); e != nil {
				t.Fatal(e)
			}
			log, e = store.OpenControl(dir, 4, owner, header.Key, auditValueValidator(owner, "board", day))
			if e != nil {
				t.Fatal(e)
			}
			defer log.Close()
			b.deletionCheckpoint = nil
			if e = b.importThreadAuditRows(log, rows); e != nil {
				t.Fatal("resume pages", e)
			}
			count := 0
			for name := range log.State().Rows {
				if strings.HasPrefix(name, "audit_entry:") {
					count++
				}
			}
			if count != 300 {
				t.Fatal("audit count", count)
			}
			before := log.State().Seq
			if e = b.importThreadAuditRows(log, rows); e != nil || before != log.State().Seq {
				t.Fatal("duplicate import", e)
			}
		})
	}
}
