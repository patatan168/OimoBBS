// 受理時の確定DATと公開項目の選択提出、秘密非混入と原本対応の拒否を検査する。
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
)

func acceptedContentFixture(t *testing.T) (AcceptedEvidence, []byte) {
	t.Helper()
	owner, frame, at := postingFixture(t)
	f, op, e := postingFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	p := postingProposal{Owner: owner, Day: 20231114, Seq: 1, ThreadKey: 1700000000, OperationID: f.Records[0].ID, ThreadSeq: op.Revision, FrameSHA: sha256.Sum256(frame), Committed: at, Retention: postRetention(at), Frame: base64.StdEncoding.EncodeToString(frame), Capture: json.RawMessage(`{"input":{"name":"submitted-name","mail":"sage","title":"submitted-title","body":"before-command","credential":"SECRET_CREDENTIAL"}}`)}
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	r := AcceptedEvidence{RecordID: domain.NewID(), Board: owner, Thread: p.ThreadKey, Operation: p.OperationID, Post: 1, Committed: at, Expires: p.Retention, Proposal: evidence.Entry{Payload: raw}}
	r.Proposal.Event.RecordID = r.RecordID
	setAcceptedFixtureDecision(t, &r)
	return r, f.Records[0].DAT
}

func setAcceptedFixtureDecision(t *testing.T, r *AcceptedEvidence) {
	t.Helper()
	var p postingProposal
	if e := json.Unmarshal(r.Proposal.Payload, &p); e != nil {
		t.Fatal(e)
	}
	d := postingDecision{Owner: p.Owner, Day: p.Day, Seq: p.Seq + 1, ThreadKey: p.ThreadKey, OperationID: p.OperationID, ThreadSeq: p.ThreadSeq, FrameSHA: p.FrameSHA, ProposalID: r.Proposal.Event.RecordID, ProposalSHA: r.Proposal.Event.EventSHA, Committed: p.Committed, Retention: p.Retention, Outcome: "accepted", Decided: p.Committed + 10}
	var e error
	r.Decision.Payload, e = json.Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
}

func TestAcceptedContentProjectsExactDATAndPublicPosts(t *testing.T) {
	r, dat := acceptedContentFixture(t)
	selected, e := r.Project([]string{"content"})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(selected["content"])
	if e != nil {
		t.Fatal(e)
	}
	var content struct {
		Body    string            `json:"body"`
		DAT     []byte            `json:"dat_base64"`
		BodySHA domain.Hash       `json:"body_sha256"`
		DATSHA  domain.Hash       `json:"dat_sha256"`
		Posts   []json.RawMessage `json:"public_posts"`
	}
	if e = json.Unmarshal(raw, &content); e != nil {
		t.Fatal(e)
	}
	if content.Body != "before-command" || !bytes.Equal(content.DAT, dat) || content.BodySHA != sha256.Sum256([]byte("before-command")) || content.DATSHA != sha256.Sum256(dat) || len(content.Posts) != 1 {
		t.Fatal("original input and committed DAT not separately projected", string(raw))
	}
	assertContentOmitsPrivate(t, raw, r)
}

func assertContentOmitsPrivate(t *testing.T, raw []byte, r AcceptedEvidence) {
	t.Helper()
	for _, field := range []string{"SECRET_CREDENTIAL", `"private"`, `"source_ip"`, `"rate_keys"`, "prepared_frame_base64"} {
		if bytes.Contains(raw, []byte(field)) {
			t.Fatal("private field disclosed", field)
		}
	}
	metadata, e := r.Project(nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, found := metadata["content"]; found {
		t.Fatal("unselected content disclosed")
	}
}

func TestAcceptedContentRejectsChangedFrameBinding(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	var p postingProposal
	if e := json.Unmarshal(r.Proposal.Payload, &p); e != nil {
		t.Fatal(e)
	}
	p.FrameSHA[0] ^= 1
	r.Proposal.Payload, _ = json.Marshal(p)
	if _, e := r.Project([]string{"content"}); e == nil {
		t.Fatal("mismatched frame accepted")
	}
}

func TestAcceptedContentAppendDoesNotInventPublicTitle(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	var p postingProposal
	if e := json.Unmarshal(r.Proposal.Payload, &p); e != nil {
		t.Fatal(e)
	}
	create, e := base64.StdEncoding.Strict().DecodeString(p.Frame)
	if e != nil {
		t.Fatal(e)
	}
	frame := replyFixture(t, create)
	f, op, e := postingFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	p.Frame, p.FrameSHA, p.OperationID, p.ThreadSeq = base64.StdEncoding.EncodeToString(frame), sha256.Sum256(frame), f.Records[0].ID, op.Revision
	r.Proposal.Payload, _ = json.Marshal(p)
	setAcceptedFixtureDecision(t, &r)
	selected, e := r.Project([]string{"content"})
	if e != nil {
		t.Fatal(e)
	}
	content := selected["content"].(map[string]any)
	if content["public_title"].(*string) != nil || *content["public_title_missing_reason"].(*string) != "not_in_append_operation" {
		t.Fatal("append title invented")
	}
}
