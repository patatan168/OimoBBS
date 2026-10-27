// 通常投稿の重複本文を解放しても、署名済み元byte・照会・取消・再起動を保つことを検査する。
package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"testing"
)

func TestPostingCompactProposalKeepsOriginalAndReopen(t *testing.T) {
	p, journal, create, now, root, key := newPostingTest(t)
	capture := []byte(`{"fixture":true}`)
	if r := p.Post(context.Background(), create, capture, now); r.Status != store.Durable {
		t.Fatal(r)
	}
	batch := &PostingBatch{}
	reply := batchReply(t, create, 2)
	if r := batch.Stage(context.Background(), p, reply, capture, now); r.Err != ErrPostingPrepared {
		t.Fatal(r)
	}
	if r := batch.Commit(); r.Status != store.Durable {
		t.Fatal(r)
	}
	check := func(p *PostingLog) {
		t.Helper()
		if p.Snapshot(now).PostCount != 2 {
			t.Fatal("公開内容が変化した")
		}
		for _, entry := range p.proposals {
			if !entry.compact || entry.payload.Frame != "" || entry.payload.Capture != nil || entry.event.Payload == "" {
				t.Fatal("本文を重複保持した")
			}
			original, err := entry.originalPayload()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := entry.decodeFrame()
			if err != nil {
				t.Fatal(err)
			}
			expected := create
			if entry.payload.ThreadSeq == 2 {
				expected = reply
			}
			if !bytes.Equal(raw, expected) || !bytes.Equal(original.Capture, capture) {
				t.Fatal("元frame/captureが変化した")
			}
			encoded, err := base64.StdEncoding.DecodeString(entry.event.Payload)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := json.Marshal(original)
			if err != nil || !bytes.Equal(actual, encoded) {
				t.Fatal("署名元payloadが変化した", err)
			}
			original.Capture[0] ^= 1
			restored, err := entry.originalPayload()
			if err != nil || !bytes.Equal(restored.Capture, capture) {
				t.Fatal("照会結果の変更が原本へ波及した", err)
			}
		}
	}
	check(p)
	owner, keyNumber := p.owner, p.key
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, key, PostingValidator(fixtureCapture))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	p, err = OpenPosting(filepath.Join(root, "threads"), owner, keyNumber, []*evidence.Journal{reopened}, reopened, now)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	check(p)
}

func TestPostingCompactProposalRejectsMismatchAndRetiredStaysEmpty(t *testing.T) {
	p, journal, create, now, _, _ := newPostingTest(t)
	if r := p.Post(context.Background(), create, []byte(`{"fixture":true}`), now); r.Status != store.Durable {
		t.Fatal(r)
	}
	var original proposalEntry
	for _, entry := range p.proposals {
		original = entry
		break
	}
	for _, mode := range []string{"frame", "capture", "metadata", "missing", "changed", "hash"} {
		t.Run(mode, func(t *testing.T) {
			entry := original
			switch mode {
			case "frame":
				entry.payload.Frame = "AA=="
			case "capture":
				entry.payload.Capture = []byte(`{}`)
			case "metadata":
				entry.payload.ThreadSeq++
			case "missing":
				entry.event.Payload = ""
			case "changed":
				entry.event.Payload = "!" + entry.event.Payload
			case "hash":
				entry.event.PayloadSHA = domain.Hash{}
			}
			if _, err := entry.originalPayload(); err != ErrEvidenceGap {
				t.Fatal("不一致原本を返した", err)
			}
		})
	}
	retired := proposalEntry{payload: original.payload, event: original.event}
	retired.event.Payload = ""
	restored, err := retired.originalPayload()
	if err != nil || restored.Frame != "" || restored.Capture != nil {
		t.Fatal("回収済み原本を補完した", err)
	}
	_ = journal
}
