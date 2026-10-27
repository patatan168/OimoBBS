// 別backup/板集合/捕捉位置への転用と未知/重複欄を、実鍵の有効署名でも拒否する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupRequiredSignedBoundary(t *testing.T) {
	cfg, r, board := requiredHoldStorageFixture(t)
	if e := r.ensureRequiredHoldStorage(t.Context(), board); e != nil {
		t.Fatal(e)
	}
	state := r.site.State()
	site := siteID(state)
	at := domain.Time(time.Now().UnixNano())
	m := backupManifest{ID: domain.NewID(), Site: site, RequiredHoldsOmitted: true, ControlCut: []backupCut{{Kind: "site", Owner: site, Sequence: state.Seq}}}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	public := key.Public().(ed25519.PublicKey)
	raw, e := encodeBackupRequiredOmission(m.ID, site, state.Seq, at, []domain.ID{board}, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = verifyRequiredOmissionPayload(raw, m, state, at, public); e != nil {
		t.Fatal(e)
	}
	var original backupOptionalEnvelope
	if e = strictjson.Decode(raw, &original); e != nil {
		t.Fatal(e)
	}
	var payload backupRequiredOmission
	if e = strictjson.Decode(original.Payload, &payload); e != nil {
		t.Fatal(e)
	}
	mutations := map[string]func(*backupRequiredOmission){
		"backup":          func(p *backupRequiredOmission) { p.Backup = domain.NewID() },
		"site":            func(p *backupRequiredOmission) { p.Site = domain.NewID() },
		"sequence":        func(p *backupRequiredOmission) { p.Sequence++ },
		"capture":         func(p *backupRequiredOmission) { p.Captured++ },
		"unknown_board":   func(p *backupRequiredOmission) { p.Boards = []domain.ID{domain.NewID()} },
		"missing_board":   func(p *backupRequiredOmission) { p.Boards = []domain.ID{} },
		"duplicate_board": func(p *backupRequiredOmission) { p.Boards = []domain.ID{board, board} },
		"reason":          func(p *backupRequiredOmission) { p.Reason = "independent_history_restored" },
		"schema":          func(p *backupRequiredOmission) { p.Schema = "unknown" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := payload
			mutate(&changed)
			encoded, e := json.Marshal(changed)
			if e != nil {
				t.Fatal(e)
			}
			env := backupOptionalEnvelope{encoded, base64.StdEncoding.EncodeToString(ed25519.Sign(key, backupRequiredMessage(encoded)))}
			signed, e := json.Marshal(env)
			if e != nil {
				t.Fatal(e)
			}
			if e = verifyRequiredOmissionPayload(signed, m, state, at, public); e == nil {
				t.Fatal("signed boundary substitution accepted")
			}
		})
	}
	if e = verifyRequiredOmissionPayload(raw, m, state, at, ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("wrong trust root accepted")
	}
	original.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, backupOptionalMessage(original.Payload)))
	wrongPurpose, _ := json.Marshal(original)
	if e = verifyRequiredOmissionPayload(wrongPurpose, m, state, at, public); e == nil {
		t.Fatal("other omission signature reused")
	}
}
