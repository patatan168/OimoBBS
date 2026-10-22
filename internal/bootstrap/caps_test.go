// キャップの実HTTP発行・投稿・停止・秘密除去・正本復旧を確認する。
package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/textcodec"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (c *adminClient) capChange(path string, input any, etag, csrf, key string) (*http.Response, AdminCap, string, string) {
	raw, _ := json.Marshal(input)
	h := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {csrf}, "If-Match": {etag}, "Idempotency-Key": {key}}
	res, body := c.request("POST", path, string(raw), h)
	var v struct {
		Data   AdminCap `json:"data"`
		Secret string   `json:"secret"`
	}
	_ = json.Unmarshal([]byte(body), &v)
	return res, v.Data, v.Secret, body
}
func createTestCap(t *testing.T, r *Repository, c *adminClient, board domain.ID, permissions []string) (AdminCap, string) {
	t.Helper()
	list, _ := c.request("GET", "/api/v1/caps", "", nil)
	res, view, secret, body := c.capChange("/api/v1/caps", capInput{"<運営>", []domain.ID{board}, permissions, domain.Time(time.Now().Add(24 * time.Hour).UnixNano())}, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 || len(secret) != 43 {
		t.Fatal("cap create", res.StatusCode, body)
	}
	return view, secret
}
func TestCapLifecycle(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	board, e := r.CreateBoard(context.Background(), "caps", "キャップ試験")
	if e != nil {
		t.Fatal(e)
	}
	other, e := r.CreateBoard(context.Background(), "other", "別板")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	if res, _ := c.request("GET", "/api/v1/caps", "", nil); res.StatusCode != 403 {
		t.Fatal("reauth bypass")
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	list, _ := c.request("GET", "/api/v1/caps", "", nil)
	input := capInput{"<運営>", []domain.ID{board.ID}, []string{"create", "post"}, domain.Time(time.Now().Add(24 * time.Hour).UnixNano())}
	request := domain.NewID().String()
	res, cap, secret, body := c.capChange("/api/v1/caps", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), request)
	if res.StatusCode != 200 || len(secret) != 43 || cap.Revision != 1 {
		t.Fatal("create", res.StatusCode, body)
	}
	res, replayed, replaySecret, replayBody := c.capChange("/api/v1/caps", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), request)
	if res.StatusCode != 200 || replayed.ID != cap.ID || replaySecret != "" || strings.Contains(replayBody, secret) {
		t.Fatal("secret replay")
	}
	input.Name = "別名"
	if res, _, _, _ := c.capChange("/api/v1/caps", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), request); res.StatusCode != 409 {
		t.Fatal("request conflict")
	}
	if res, page := c.request("GET", "/caps", "", nil); res.StatusCode != 200 || !strings.Contains(page, "&lt;運営&gt;") || strings.Contains(page, secret) {
		t.Fatal("html", res.StatusCode, page)
	}
	form := formServer(t, r, siteID(r.site.State()), board.ID)
	defer func() { form.Close() }()
	fields := url.Values{"bbs": {"caps"}, "subject": {"運営から"}, "FROM": {"名#private-trip-key"}, "mail": {"sage #cap:" + cap.ID.String() + ":" + secret}, "MESSAGE": {"キャップ本文"}, "oimo_request_id": {"cap-create-request-001"}}
	pending, e := sendFormOnce(form, fields, "")
	if e != nil || pending.Confirmation == nil || pending.Confirmation.Preview.Cap != cap.Name || strings.Contains(pending.Confirmation.Preview.Mail, secret) {
		t.Fatal("confirmation", pending, e)
	}
	preview := httptest.NewRecorder()
	writePostingPage(preview, 200, postingPage{Heading: "確認", Confirmation: pending.Confirmation})
	previewText := strings.SplitN(preview.Body.String(), "<form", 2)[0]
	if !strings.Contains(previewText, "名前：&lt;運営&gt; ★") || strings.Contains(previewText, "◆") {
		t.Fatal("cap preview name")
	}
	accepted, e := sendFormOnce(form, fields, pending.Confirmation.Token)
	if e != nil || !accepted.Accepted {
		t.Fatal("cap post", accepted, e)
	}
	assertCapPrincipalProjection(t, r, board.ID, cap.ID, secret)
	if replay, e := sendForm(form, fields); e != nil || !replay.Duplicate || replay.Key != accepted.Key {
		t.Fatal("post replay", replay, e)
	}
	snapshot, e := r.Thread(context.Background(), board.ID, accepted.Key)
	if e != nil || snapshot == nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(snapshot.DAT), "CAP_USER") || strings.Contains(string(snapshot.DAT), secret) {
		t.Fatal("DAT")
	}
	decodedDAT, e := textcodec.Decode(snapshot.DAT)
	if e != nil || !strings.HasPrefix(decodedDAT, "&lt;運営&gt; ★<>sage<>") || strings.Contains(decodedDAT, "◆") {
		t.Fatal("cap display", e)
	}
	var state siteState
	if e = json.Unmarshal(r.site.State().Rows["site:state"].Value, &state); e != nil || state.MinimumReader < 36 {
		t.Fatal("cap display reader", e)
	}
	wrongForm := formServer(t, r, siteID(r.site.State()), other.ID)
	defer wrongForm.Close()
	fields.Set("bbs", "other")
	if result, e := sendForm(wrongForm, fields); e != nil || result.Accepted || result.Confirmation != nil {
		t.Fatal("scope", result, e)
	}
	fields.Set("bbs", "caps")
	if e := filepath.WalkDir(cfg.DataDir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if strings.Contains(string(data), secret) || strings.Contains(string(data), "private-trip-key") {
			t.Fatal("secret persisted", path)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// frameを捕捉付きで直接渡しても、認証済みフォーム入口を迂回できない。
	for _, j := range r.posting[board.ID].journals {
		for _, entry := range j.Entries() {
			if entry.Event.Kind != "evidence_proposal" {
				continue
			}
			var v struct {
				Capture json.RawMessage `json:"capture"`
				Frame   string          `json:"prepared_frame_base64"`
				Key     domain.U64      `json:"thread_key"`
			}
			if e = json.Unmarshal(entry.Payload, &v); e != nil {
				t.Fatal(e)
			}
			frame, _ := base64.StdEncoding.DecodeString(v.Frame)
			var payload map[string]json.RawMessage
			if e = json.Unmarshal(v.Capture, &payload); e != nil {
				t.Fatal(e)
			}
			for _, field := range []string{"cap", "token"} {
				bad := make(map[string]json.RawMessage, len(payload))
				for k, val := range payload {
					bad[k] = val
				}
				delete(bad, field)
				data, _ := json.Marshal(bad)
				if postcapture.Validate(data) == nil {
					t.Fatal("missing cap component", field)
				}
			}
			for _, change := range []func(*postcapture.CapEvidence){func(p *postcapture.CapEvidence) { p.ID = domain.NewID() }, func(p *postcapture.CapEvidence) { p.Name = "別資格" }, func(p *postcapture.CapEvidence) { p.Revision++ }, func(p *postcapture.CapEvidence) { p.KeyID = 4 }} {
				var proof postcapture.CapEvidence
				if e = json.Unmarshal(payload["cap"], &proof); e != nil {
					t.Fatal(e)
				}
				change(&proof)
				bad := make(map[string]json.RawMessage, len(payload))
				for k, val := range payload {
					bad[k] = val
				}
				bad["cap"], _ = json.Marshal(proof)
				data, _ := json.Marshal(bad)
				if postcapture.ValidateFrame(data, frame, uint64(v.Key)) == nil {
					t.Fatal("cap binding bypass")
				}
			}
			// 観測だけの旧schemaへ偽装しても低レベル入口からcapを受理しない。
			if result := r.Post(context.Background(), board.ID, 0, frame, payload["observation"]); result.Status != store.NotWritten {
				t.Fatal("old observation bypass")
			}

			if e = postcapture.ValidateFrame(v.Capture, frame, uint64(v.Key)); e != nil {
				t.Fatal(e)
			}
			checkLegacyCapCapture(t, v.Capture, frame, uint64(v.Key))
			if result := r.Post(context.Background(), board.ID, 0, frame, v.Capture); result.Status != store.NotWritten {
				t.Fatal("direct cap bypass")
			}
		}
	}
	detail, _ := c.request("GET", "/api/v1/caps/"+cap.ID.String(), "", nil)
	revokePath := "/api/v1/caps/" + cap.ID.String() + "/revoke"
	revokeKey := domain.NewID().String()
	res, revoked, _, body := c.capChange(revokePath, struct{}{}, detail.Header.Get("ETag"), detail.Header.Get("X-CSRF-Token"), revokeKey)
	if res.StatusCode != 200 || revoked.Enabled || revoked.Revision != 2 {
		t.Fatal("revoke", res.StatusCode, body)
	}
	if res, replayed, raw, _ := c.capChange(revokePath, struct{}{}, detail.Header.Get("ETag"), detail.Header.Get("X-CSRF-Token"), revokeKey); res.StatusCode != 200 || replayed.Enabled || raw != "" {
		t.Fatal("revoke replay")
	}
	fields.Set("key", fmt.Sprint(accepted.Key))
	fields.Del("subject")
	fields.Set("MESSAGE", "停止後")
	fields.Set("oimo_request_id", "cap-reply-after-revoke")
	if result, e := sendForm(form, fields); e != nil || result.Accepted || result.Confirmation != nil {
		t.Fatal("revoked", result, e)
	}
	c.server.Close()
	form.Close()
	wrongForm.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reopen", e)
	}
	if r.liveCaps.Load().Records[cap.ID].Enabled {
		t.Fatal("cap revived")
	}
	if snapshot, e = r.Thread(context.Background(), board.ID, accepted.Key); e != nil || snapshot == nil {
		t.Fatal("old accepted post lost", e)
	}
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "caps-candidate")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal("cap snapshot", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal("cap snapshot activation", e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("snapshot reopen", e)
	}
	if r.liveCaps.Load().Records[cap.ID].Enabled {
		t.Fatal("snapshot revived cap")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	backup, keys, work := filepath.Join(parent, "body"), filepath.Join(parent, "keys"), filepath.Join(parent, "work")
	if _, e = CaptureOfflineBackup(context.Background(), cfg, backup); e != nil {
		t.Fatal("capture caps", e)
	}
	if _, e = ExportBackupKeys(context.Background(), cfg, backup, keys); e != nil {
		t.Fatal("export keys", e)
	}
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	report, e := VerifyBackupReplay(context.Background(), backup, keys, work)
	if e != nil || !report.Replayed || report.RestoreReady {
		t.Fatal("cap replay", report, e)
	}

}
