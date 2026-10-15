// 板所有の全投稿・日別記録を列挙し、未知ファイルや予約外キーを拒否してから復旧する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const postingScanLimit = 65536

func (r *Repository) openPostings() error {
	owners, e := childIDs(filepath.Join(r.cfg.DataDir, "evidence"))
	if e != nil {
		return e
	}
	for _, id := range owners {
		if r.boards[id] == nil {
			return errors.New("evidence has no active board")
		}
	}
	for id := range r.boards {
		if e = r.openPostingBoard(id); e != nil {
			return fmt.Errorf("posting board %s: %w", id, e)
		}
	}
	return nil
}
func (r *Repository) openPostingBoard(id domain.ID) error {
	if r.guard == nil {
		r.guard = &abuseGuard{settings: defaultAbuseGuard()}
	}
	if r.posting[id] != nil {
		return nil
	}
	if e := validateAnonymousBoardFeatures(r.site.State(), r.boards[id].State()); e != nil {
		return e
	}
	seed, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return errors.New("invalid signing seed")
	}
	b := &postingBoard{guard: r.guard, reserveCapacity: r.reservePosting, admission: r.admission, owner: id, root: r.cfg.DataDir, threadsDir: filepath.Join(r.cfg.DataDir, "boards", id.String(), "threads"), evidenceDir: filepath.Join(r.cfg.DataDir, "evidence", id.String()), control: r.boards[id], threads: map[uint64]*app.PostingLog{}, journals: map[uint64]*evidence.Journal{}, key: ed25519.NewKeyFromSeed(seed), validate: bindPostingCapture(r.captureValidator, siteID(r.site.State()), id), checkpoint: r.checkpoint, clock: time.Now, operations: map[domain.ID]uint64{}}
	policy, e := currentPostingPolicy(b.control.State())
	if e != nil {
		return e
	}
	b.postingPolicy = policy
	b.rememberAudit = r.rememberAuditLog
	b.controlExpiryFloor = &r.controlExpiryFloor
	b.liveCaps = &r.liveCaps
	b.liveNetworks = &r.liveNetworks
	b.networkHosts = r.networkHosts
	b.capCommitted = map[domain.ID]domain.Time{}
	ok := false
	defer func() {
		if !ok {
			_ = b.close()
		}
	}()
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return err
	}
	defer clear(master)
	if b.dedupKey, err = identity.DeriveKey(master, "dedup", 8); err != nil {
		return err
	}
	if b.publicKey, err = identity.DeriveKey(master, "public_id", 1); err != nil {
		return err
	}
	if b.slipNetKey, err = identity.DeriveKey(master, "slip_net", 2); err != nil {
		return err
	}
	if b.slipUAKey, err = identity.DeriveKey(master, "slip_ua", 3); err != nil {
		return err
	}
	if b.confirmKey, err = identity.DeriveKey(master, "confirm", 5); err != nil {
		return err
	}
	if b.csrfKey, err = identity.DeriveKey(master, "csrf", 6); err != nil {
		return err
	}
	if b.capKey, err = identity.DeriveKey(master, "cap", 9); err != nil {
		return err
	}
	dirs, err := siteDirectories(r.site.State())
	if err != nil {
		return err
	}
	if dirs[id] == nil {
		return errors.New("missing board directory")
	}
	b.slug = dirs[id].Key
	if e = b.loadDenials(); e != nil {
		return e
	}
	r.denialCount += len(b.denials)
	if r.denialCount > 10000 {
		return errors.New("site rule capacity exceeded")
	}
	var publicState boardValue
	if err = strictjson.Decode(b.control.State().Rows["board:state"].Value, &publicState); err != nil {
		return err
	}
	b.publicName = publicState.Name
	b.autoReports.Store(publicState.Settings.Posting.AutoReports)
	b.noReprint.Store(publicState.Settings.Presentation.reprintDenied())
	b.hidden.Store(publicState.Settings.Presentation.unlisted())
	b.readingNetworks.Store(&publicState.Settings.Identity.Networks)
	b.checkPostingReading = func(capture []byte) error { return r.checkCapturedReading(id.String(), capture) }
	baseValidator := b.validate
	b.validateBase = baseValidator
	b.validate = func(raw []byte) error {
		if e := baseValidator(raw); e != nil {
			return e
		}
		if e := postcapture.ValidateKey(raw, b.dedupKey); e != nil {
			return e
		}
		if e := b.validateOverrideCapture(raw); e != nil {
			return e
		}
		if e := validateCapCapture(raw, b.liveCaps.Load(), b.owner); e != nil {
			return e
		}
		proof, at, _, e := postcapture.CapMetadata(raw)
		if proof != nil {
			b.capCommitted[proof.ID] = max(b.capCommitted[proof.ID], at)
		}
		return e
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	b.packsEnabled = site.MinimumReader >= 13
	b.reserveDeletionPack = r.reserveDeletionPack
	b.expirySiteVersion = site.PublicRevision
	r.publicRevision.Store(uint64(site.PublicRevision))
	b.currentSiteRevision = func() domain.U64 { return domain.U64(r.publicRevision.Load()) }
	b.retentionEnabled = site.MinimumReader >= 16
	b.bodyReclaimEnabled = site.MinimumReader >= 26
	b.carryEnabled = site.MinimumReader >= 27
	b.requiredRetirementEnabled = site.MinimumReader >= 45
	b.requiredRejectedEnabled = site.MinimumReader >= 52
	if e = b.loadDeletions(); e != nil {
		return e
	}
	actions, e := b.threadActions()
	if e != nil || len(actions) > 0 && site.MinimumReader < 25 {
		return errors.Join(store.ErrCorrupt, e)
	}
	if e = r.openRequiredHoldStorage(b); e != nil {
		return e
	}
	if e = b.recover(); e != nil {
		return e
	}
	if e = b.recoverDeletions(); e != nil {
		return e
	}
	if e = b.resumePublicBodies(); e != nil {
		return e
	}
	delay := time.Minute
	if site.MinimumReader >= 16 {
		for key, p := range b.threads {
			b.bindExpiry(key, p)
		}
		delay, e = b.scanExpiry(true)
		if e != nil {
			return e
		}
	}
	if e = b.cleanPublicBodies(8); e != nil {
		return e
	}
	b.worker = board.NewWorker()
	b.postBatch = &board.Batch{RunReady: b.runPostingReadyBatch}
	if site.MinimumReader >= 16 {
		b.startExpiry(delay)
	}
	if r.cfg.AutoReports != nil {
		var receipt *app.PostingSnapshot
		receipt, e = receiptSnapshotForBoard(r.cfg.Public.BaseURL, b.slug, r.operations().Reports, b.autoReports.Load())
		if e != nil {
			return e
		}
		b.receipt.Store(receipt)
		if b.threads[reportReceiptKey] != nil {
			return errors.New("report receipt key already occupied")
		}
	}
	r.posting[id] = b
	readingBoards := &readingBoardIndex{Boards: map[string]*postingBoard{}}
	for owner, board := range r.posting {
		readingBoards.Boards[owner.String()] = board
	}
	r.liveReadingBoards.Store(readingBoards)
	ok = true
	return nil
}
func (b *postingBoard) recover() error {
	proofs, e := b.bodyReclamations()
	if e != nil {
		return e
	}
	keys, e := postingNames(b.threadsDir)
	if e != nil {
		return e
	}
	var water struct {
		Last domain.U64 `json:"last_reserved_key"`
	}
	if e = strictjson.Decode(b.control.State().Rows["key_watermark:thread"].Value, &water); e != nil {
		return e
	}
	for _, key := range keys {
		if key > uint64(water.Last) {
			return errors.New("thread key exceeds reservation watermark")
		}
		dir := filepath.Join(b.threadsDir, fmt.Sprint(key))
		if proof, ok := proofs[key]; ok {
			if e = store.CheckReclaimedBody(context.Background(), dir, proof.Files); e != nil {
				return e
			}
			continue
		}
		if e = privatePath(dir, true); e != nil {
			return e
		}
		m, _, err := store.InspectThreadFiles(dir)
		if err != nil {
			// current未設置だけは、後段の全署名journal照合で作成途中か判定する。
			if _, currentErr := os.Lstat(filepath.Join(dir, "current.json")); !os.IsNotExist(currentErr) {
				return err
			}
		}
		if m.Base != nil && !b.packsEnabled {
			return errors.New("pack requires minimum reader 13")
		}
		names, err := boundedAuditNames(dir, 4096)
		if err != nil {
			return err
		}
		for _, name := range names {
			if e = privatePath(filepath.Join(dir, name), false); e != nil {
				return e
			}
		}
	}
	days, e := postingNames(b.evidenceDir)
	if os.IsNotExist(e) {
		days = nil
	} else if e != nil {
		return e
	}
	journals := make([]*evidence.Journal, 0, len(days)+1)
	for _, day := range days {
		path := filepath.Join(b.evidenceDir, fmt.Sprint(day))
		if e = inspectPostingJournalDirectory(path); e != nil {
			return e
		}
		inspection, err := evidence.InspectJournal(path, b.owner, day, 10, b.key, app.PostingValidator(b.validate))
		if err != nil {
			return err
		}
		if inspection.MinimumReader >= 52 && !b.requiredRejectedEnabled {
			return store.ErrCorrupt
		}
		if e = checkRequiredJournalBoundary(inspection, b.requiredRetirementEnabled, domain.Time(b.clock().UnixNano())); e != nil {
			return e
		}
		j, e := evidence.OpenJournal(path, b.owner, day, 10, b.key, app.PostingValidator(b.validate))
		if e != nil {
			return e
		}
		b.journals[day] = j
		journals = append(journals, j)
	}
	if len(keys) == 0 && len(journals) == 0 {
		b.createRequests = map[createRequestKey]uint64{}
		return nil
	}
	now := b.clock()
	active, e := b.journal(now)
	if e != nil {
		return e
	}
	found := false
	for _, j := range journals {
		if j == active {
			found = true
		}
	}
	if !found {
		journals = append(journals, active)
	}
	// 記録だけに残った予約外キーも、decisionを補完する前に拒否する。
	if e = app.CheckPostingKeys(journals, uint64(water.Last)); e != nil {
		return e
	}
	if b.requiredRetirementEnabled {
		carries, err := b.recoveryBodyCarries(proofs)
		if err != nil {
			return err
		}
		b.threads, e = app.OpenPostingsWithRetiredOriginals(b.threadsDir, b.owner, keys, journals, active, domain.Time(now.UnixNano()), proofs, carries, b.key.Public().(ed25519.PublicKey))
	} else {
		b.threads, e = app.OpenPostingsWithReclamations(b.threadsDir, b.owner, keys, journals, active, domain.Time(now.UnixNano()), proofs, b.key.Public().(ed25519.PublicKey))
	}
	if e != nil {
		return e
	}
	for key, p := range b.threads {
		b.publicReaders.Store(key, p.PublicReader())
		for _, id := range p.OperationIDs() {
			b.operations[id] = key
		}
	}
	return b.restoreCreateRequests(domain.Time(now.UnixNano()))
}

// postingNames は読み取る件数を制限し、正規十進ディレクトリ以外を拒否する。
func postingNames(dir string) ([]uint64, error) {
	if e := privatePath(dir, true); e != nil {
		return nil, e
	}
	f, e := os.Open(dir)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	names, e := f.Readdirnames(postingScanLimit + 1)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(names) > postingScanLimit {
		return nil, errors.New("posting recovery directory limit exceeded")
	}
	keys := make([]uint64, 0, len(names))
	for _, name := range names {
		key, e := strconv.ParseUint(name, 10, 64)
		if e != nil || key == 0 || fmt.Sprint(key) != name {
			return nil, errors.New("noncanonical posting directory")
		}
		if e = privatePath(filepath.Join(dir, name), true); e != nil {
			return nil, e
		}
		keys = append(keys, key)
	}
	return keys, nil
}
func ensurePostingDirectory(path string) error {
	if _, e := os.Lstat(path); e == nil {
		return privatePath(path, true)
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := makePrivateDir(path); e != nil {
		return e
	}
	return store.SyncDirectory(path)
}
