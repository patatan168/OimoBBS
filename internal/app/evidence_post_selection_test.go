// 未受理proposalと同じ番号の再投稿を区別し、署名済みacceptedだけを選択する。
package app

import (
	"bytes"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"testing"
)

func TestAcceptedPostSelectionAfterUnacceptedProposal(t *testing.T) {
	p, j, frame, now, _, _ := newPostingTest(t)
	capture := []byte(`{"fixture":true}`)
	p.checkpoint = func(stage string) error {
		if stage == "proposal" {
			return errors.New("simulated interruption")
		}
		return nil
	}
	if result := p.Post(t.Context(), frame, capture, now); result.Status != store.Unknown {
		t.Fatal(result)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, now)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	parsed, _, err := store.ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	parsed.Records[0].ID = domain.NewID()
	retry, err := store.EncodeFrame(parsed)
	if err != nil {
		t.Fatal(err)
	}
	result := next.Post(t.Context(), retry, capture, now)
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	rows, err := AcceptedRecordsForPost([]*evidence.Journal{j}, p.owner, domain.U64(p.key), 1, "post", now, 1)
	if err != nil || len(rows) != 1 || rows[0].Operation != result.OperationID {
		t.Fatal("unaccepted counted or wrong operation selected", err)
	}
	rows, err = AcceptedRecordsForPost([]*evidence.Journal{j}, p.owner, domain.U64(p.key), 1, "post", rows[0].Expires, 1)
	if err != nil || len(rows) != 0 {
		t.Fatal("expired record selected", err)
	}
}
