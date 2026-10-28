// CAP専用板の初期公開・管理入力・投稿境界・保存復旧を検証する。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func TestAdminCapBoardCreateAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	_, page := c.request("GET", "/boards/new", "", nil)
	if !strings.Contains(page, `name="posting_mode"`) || !strings.Contains(page, "CAP専用板") {
		t.Fatal("creation picker missing")
	}
	fields := pageFields(page)
	fields.Set("key", "capboard")
	fields.Set("name", "CAP専用板")
	fields.Set("posting_mode", "cap_only")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	fields.Set("key", "invalid-key")
	res, page := c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 400 || !strings.Contains(page, `value="cap_only" selected`) {
		t.Fatal("invalid input lost selection", res.StatusCode)
	}
	fields.Set("key", "capboard")
	fields.Set("posting_mode", "unknown")
	res, _ = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 400 {
		t.Fatal("invalid mode", res.StatusCode)
	}
	fields.Set("posting_mode", "cap_only")
	res, _ = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("create", res.StatusCode)
	}
	location := res.Header.Get("Location")
	boards, err := repo.Boards()
	if err != nil || len(boards) != 1 {
		t.Fatal("boards", err)
	}
	board := boards[0]
	res, view := c.board(board.ID.String())
	if res.StatusCode != 200 || view.Settings.Create != "cap_only" || view.Settings.Reply != "cap_only" {
		t.Fatal("initial restrictions", res.StatusCode)
	}
	res, _ = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 303 || res.Header.Get("Location") != location {
		t.Fatal("identical retry", res.StatusCode)
	}
	fields.Set("posting_mode", "anyone")
	res, _ = c.request("POST", "/boards", fields.Encode(), headers)
	if res.StatusCode != 409 {
		t.Fatal("different mode overwrote existing board", res.StatusCode)
	}
	b := repo.posting[board.ID]
	if _, err = b.worker.Submit(t.Context(), func() (any, error) {
		h := store.Header{Kind: 2, Owner: board.ID, BaseSeq: uint64(b.control.State().Seq), Generation: 2}
		raw, e := store.EncodeControlSnapshot(h, b.control.State(), 6, snapshotBoardValue)
		if e != nil {
			return nil, e
		}
		_, e = store.DecodeControlSnapshot(raw, h, snapshotBoardValue)
		return nil, e
	}); err != nil {
		t.Fatal("initial snapshot", err)
	}
	cap, secret := createTestCap(t, repo, c, board.ID, []string{"create", "post"})
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	fields = url.Values{"bbs": {"capboard"}, "subject": {"案内"}, "MESSAGE": {"本文"}, "oimo_request_id": {"cap-board-anonymous-001"}}
	posted, err := sendForm(form, fields)
	if err != nil || posted.Accepted {
		t.Fatal("anonymous creation", err)
	}
	fields.Set("mail", "#cap:"+cap.ID.String()+":"+secret)
	fields.Set("oimo_request_id", "cap-board-create-001")
	posted, err = sendForm(form, fields)
	if err != nil || !posted.Accepted {
		t.Fatal("CAP creation", err)
	}
	fields.Del("subject")
	fields.Del("mail")
	fields.Set("key", fmt.Sprint(posted.Key))
	fields.Set("oimo_request_id", "cap-board-anonymous-reply-001")
	reply, err := sendForm(form, fields)
	if err != nil || reply.Accepted {
		t.Fatal("anonymous reply", err)
	}
	fields.Set("mail", "#cap:"+cap.ID.String()+":"+secret)
	fields.Set("oimo_request_id", "cap-board-reply-001")
	reply, err = sendForm(form, fields)
	if err != nil || !reply.Accepted {
		t.Fatal("CAP reply", err)
	}
	if rec := publicLocalRules(t, repo, "/capboard/", nil); rec.Code != 200 {
		t.Fatal("public reading", rec.Code)
	}
	form.Close()
	c.server.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	if report, e := checkLockedPosting(cfg, false, true); e != nil || report.MinimumReader != 73 {
		t.Fatal("check/reader", report, e)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen", err)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("recovered login")
	}
	res, view = c.board(board.ID.String())
	if res.StatusCode != 200 || view.Settings.Create != "cap_only" || view.Settings.Reply != "cap_only" {
		t.Fatal("recovered restrictions", res.StatusCode)
	}
}
