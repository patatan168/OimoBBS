// 必須保全の先行intent/コピー分離と、元所有者待ち後の現在CAS再照合を実fileで確認する。
package disclosure

import (
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/app"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestPrepareHoldDefersCopyAcrossRestart(t *testing.T) {
	s, key, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	etag := c.ETag()
	c, e = s.PrepareHold(c.ID, actor, etag, "hold", "preserve", []app.AcceptedEvidence{record}, now)
	if e != nil || c.State != "preparing" || len(c.Items) != 1 || c.Items[0].State != "pending" {
		t.Fatal(c, e)
	}
	if _, e = os.Lstat(s.artifactDir(c.ID, "items")); !os.IsNotExist(e) {
		t.Fatal("intent created copy directory", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(s.root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again, e := s.PrepareHold(c.ID, actor, etag, "hold", "preserve", nil, now.Add(time.Second))
	if e != nil || !reflect.DeepEqual(c, again) {
		t.Fatal("fixed intent replay", e)
	}
	if _, e = s.PrepareHold(c.ID, actor, etag, "hold", "different", nil, now); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, etag, "hold", "preserve", []app.AcceptedEvidence{record}, now.Add(time.Second))
	if e != nil || c.State != "active" {
		t.Fatal(c, e)
	}
	again, e = s.PrepareHold(c.ID, actor, etag, "hold", "preserve", nil, now.Add(2*time.Second))
	if e != nil || again.Revision != c.Revision || again.State != "active" {
		t.Fatal("replay returned obsolete case", again, e)
	}
	rows, e := s.Records(c, now.Add(2*time.Second))
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
}

func TestRequiredCopyGuardBeforeEachSideEffect(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			s, _, input, actor, now, record := fixture(t)
			c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
			if e != nil {
				t.Fatal(e)
			}
			c, e = s.PrepareHold(c.ID, actor, c.ETag(), "hold", "preserve", []app.AcceptedEvidence{record}, now)
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			_, e = s.resumeHoldChecked(c, actor, []app.AcceptedEvidence{record}, now, func() error {
				calls++
				if calls == failAt {
					return io.ErrUnexpectedEOF
				}
				return nil
			})
			if !errors.Is(e, io.ErrUnexpectedEOF) || calls != failAt {
				t.Fatal(calls, e)
			}
			current, e := s.Get(c.ID)
			if e != nil || current.State != "preparing" || current.Revision != c.Revision {
				t.Fatal(current, e)
			}
			_, e = os.Lstat(s.itemPath(c.ID, record.RecordID))
			if failAt < 3 && !os.IsNotExist(e) {
				t.Fatal("copy written after failed source guard", e)
			}
			if failAt == 3 && e != nil {
				t.Fatal("completed copy missing", e)
			}
			c, e = s.resumeHoldChecked(current, actor, []app.AcceptedEvidence{record}, now, func() error { return nil })
			if e != nil || c.State != "active" {
				t.Fatal("guarded resume", c, e)
			}
		})
	}
}

func TestRequiredCopyGuardDetectsCaseCancellationDuringOwnerWait(t *testing.T) {
	for _, cancelAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(cancelAt), func(t *testing.T) {
			s, _, input, actor, now, record := fixture(t)
			c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
			if e != nil {
				t.Fatal(e)
			}
			c, e = s.PrepareHold(c.ID, actor, c.ETag(), "hold", "preserve", []app.AcceptedEvidence{record}, now)
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			_, e = s.resumeHoldChecked(c, actor, []app.AcceptedEvidence{record}, now, func() error {
				calls++
				if calls != cancelAt {
					return nil
				}
				_, err := s.Release(c.ID, actor, c.ETag(), "cancel", "cancel preservation", now)
				return err
			})
			if !errors.Is(e, ErrConflict) {
				t.Fatal("cancelled case completed", e)
			}
			current, e := s.Get(c.ID)
			if e != nil || current.State != "closed" {
				t.Fatal(current, e)
			}
			if _, e = os.Lstat(s.itemPath(c.ID, record.RecordID)); !os.IsNotExist(e) {
				t.Fatal("cancelled copy remained", e)
			}
		})
	}
}
