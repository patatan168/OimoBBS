// 板所有列で必須原本の案件予約を署名保存し、コピー失敗/再起動を跨ぐGC保護を提供する。
package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"slices"
)

const requiredHoldsDay uint64 = 20000101

// MaxRequiredHolds は現台帳の案件数上限。解除済みIDも再利用しない。
const MaxRequiredHolds = 128

// MaxRequiredHoldPostings は一案件で保護する受理操作数上限。
const MaxRequiredHoldPostings = 100

// RequiredHoldBinding は先行案件intentの固定範囲。本人情報や自由文を含まない。
type RequiredHoldBinding struct {
	Case     domain.ID   `json:"case_id"`
	Revision domain.U64  `json:"case_revision"`
	Board    domain.ID   `json:"board_id"`
	Thread   domain.U64  `json:"thread_key"`
	From     domain.Time `json:"from_ns"`
	To       domain.Time `json:"to_ns"`
	Until    domain.Time `json:"hold_until_ns"`
}

// RequiredHoldSource は元の位置だけ。本文/IP/資格情報を予約に複製しない。
type RequiredHoldSource struct {
	Day      domain.U64 `json:"source_subkey"`
	Sequence domain.U64 `json:"source_control_seq"`
}

// RequiredHeldPosting は照合済み受理対応と両側原本の固定位置。
type RequiredHeldPosting struct {
	Identity evidence.RequiredPostingIdentity `json:"posting_identity"`
	Proposal RequiredHoldSource               `json:"proposal_source"`
	Decision RequiredHoldSource               `json:"decision_source"`
}

// RequiredHoldReceipt は署名済み予約の耐久参照。期限後の解除照合にも使う。
type RequiredHoldReceipt struct {
	Binding  RequiredHoldBinding   `json:"binding"`
	Sequence domain.U64            `json:"sequence"`
	SHA      domain.Hash           `json:"event_sha256"`
	At       domain.Time           `json:"recorded_at_ns"`
	State    string                `json:"state"`
	Postings []RequiredHeldPosting `json:"postings"`
}

type requiredHoldPayload struct {
	Approval         *RequiredHoldApproval `json:"renewal_approval"`
	Schema           string                `json:"schema"`
	Owner            domain.ID             `json:"source_owner_id"`
	Day              domain.U64            `json:"source_subkey"`
	Sequence         domain.U64            `json:"source_control_seq"`
	Board            domain.ID             `json:"board_id"`
	At               domain.Time           `json:"recorded_at_ns"`
	Action           string                `json:"action"`
	Binding          *RequiredHoldBinding  `json:"binding"`
	ExpectedSequence domain.U64            `json:"expected_case_sequence"`
	ExpectedSHA      domain.Hash           `json:"expected_case_sha256"`
	Postings         []RequiredHeldPosting `json:"postings"`
}

// RequiredOriginalHolds は板所有ワーカー専用。予約・原本取得・GCの排他を呼出元で共有する。
type RequiredOriginalHolds struct {
	journal                  *evidence.Journal
	board                    domain.ID
	public                   ed25519.PublicKey
	keyID                    uint32
	holds                    map[domain.ID]RequiredHoldReceipt
	originals                map[domain.ID]RequiredHoldReceipt
	activeReceipts           map[domain.ID]RequiredHoldReceipt
	renewals                 map[domain.ID]requiredHoldRenewal
	minimumReader            uint32
	heldUntil                map[domain.ID]domain.Time
	floor                    domain.Time
	initialized              bool
	stopped                  bool
	initializationCheckpoint func(string) error
}

func requiredHoldsOwner(board domain.ID) domain.ID {
	h := sha256.Sum256(append([]byte("oimo/required-original-holds/v1"), board[:]...))
	var id domain.ID
	copy(id[:], h[:16])
	return id
}

// OpenRequiredOriginalHolds は予約台帳を署名/連鎖/CAS検査して開く。required時の欠落は補完しない。
func OpenRequiredOriginalHolds(path string, board domain.ID, keyID uint32, key ed25519.PrivateKey, required bool) (*RequiredOriginalHolds, error) {
	if board == (domain.ID{}) || len(key) != ed25519.PrivateKeySize {
		return nil, store.ErrCorrupt
	}
	if e := inspectRequiredHoldsBeforeOpen(path, required); e != nil {
		return nil, e
	}
	h := &RequiredOriginalHolds{board: board, keyID: keyID, public: slices.Clone(key.Public().(ed25519.PublicKey)), holds: map[domain.ID]RequiredHoldReceipt{}, heldUntil: map[domain.ID]domain.Time{}}
	j, e := evidence.OpenJournalWithCreationIntent(path, requiredHoldsOwner(board), requiredHoldsDay, keyID, key, requiredHoldValidator(board), func(point string) error {
		if h.initializationCheckpoint != nil {
			return h.initializationCheckpoint(point)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	h.journal = j
	if e = j.Visit(h.replayEntry); e != nil {
		_ = h.Close()
		return nil, e
	}
	if required && !h.initialized {
		_ = h.Close()
		return nil, store.ErrCorrupt
	}
	h.rebuildHeldUntil()
	return h, nil
}

// inspectRequiredHoldsBeforeOpen は初期化前の不在だけ許し、既存領域の未知fileを拒否する。
func inspectRequiredHoldsBeforeOpen(path string, required bool) error {
	pending, e := requiredHoldsCreationPending(path)
	if e != nil {
		return e
	}
	if pending {
		if required {
			return store.ErrIncomplete
		}
		return nil
	}
	if _, e := os.Lstat(path); e != nil {
		if os.IsNotExist(e) && !required {
			return nil
		}
		return e
	}
	return inspectRequiredHoldDirectory(path)
}

// Initialize は空集合も署名Syncして耐久確定する。再送は追加行を作らない。
func (h *RequiredOriginalHolds) Initialize(now domain.Time) error {
	if e := h.checkClock(now); e != nil {
		return e
	}
	if h.initialized {
		return nil
	}
	return h.append(requiredHoldPayload{Action: "initialize", At: now, Postings: []RequiredHeldPosting{}})
}

func (h *RequiredOriginalHolds) checkClock(now domain.Time) error {
	if h.stopped || h.journal == nil {
		return store.ErrIncomplete
	}
	if now < h.floor {
		return evidence.ErrRetirementClock
	}
	if now <= 0 {
		return store.ErrCorrupt
	}
	return nil
}

func (h *RequiredOriginalHolds) append(p requiredHoldPayload) error {
	event, result := h.journal.Append(domain.NewID(), "checkpoint", p.At, func(src evidence.Source) ([]byte, error) {
		schema := "required-original-hold-v2"
		p.Schema, p.Owner, p.Day, p.Sequence, p.Board = schema, src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), h.board
		return json.Marshal(p)
	})
	if result.Status != store.Durable {
		if result.Status == store.Unknown {
			h.stopped = true
		}
		return result.Err
	}
	raw, e := json.Marshal(p)
	if e == nil {
		e = h.replayEntry(evidence.Entry{Event: event, Payload: raw})
	}
	if e != nil {
		h.stopped = true
		return e
	}
	h.rebuildHeldUntil()
	return nil
}

// Receipt は現在予約を独立コピーで返す。開示認可は別に検査する。
func (h *RequiredOriginalHolds) Receipt(id domain.ID) (RequiredHoldReceipt, bool, error) {
	if h.stopped {
		return RequiredHoldReceipt{}, false, store.ErrIncomplete
	}
	r, ok := h.holds[id]
	r.Postings = slices.Clone(r.Postings)
	return r, ok, nil
}

// OriginalReceipt は署名検査済み初回予約を返す。解除後の案件参照回復に使い、原本を再取得しない。
func (h *RequiredOriginalHolds) OriginalReceipt(id domain.ID) (RequiredHoldReceipt, bool, error) {
	if h.stopped {
		return RequiredHoldReceipt{}, false, store.ErrIncomplete
	}
	r, ok := h.originals[id]
	r.Postings = slices.Clone(r.Postings)
	return r, ok, nil
}

// LastActiveReceipt は解除直前の署名済み予約を返す。延長後の終端参照回復にも使う。
func (h *RequiredOriginalHolds) LastActiveReceipt(id domain.ID) (RequiredHoldReceipt, bool, error) {
	if h.stopped {
		return RequiredHoldReceipt{}, false, store.ErrIncomplete
	}
	r, ok := h.activeReceipts[id]
	r.Postings = slices.Clone(r.Postings)
	return r, ok, nil
}

// Held はGC直前に同じ所有列で呼ぶ。台帳不明/時計逆行は回収を拒否する。
func (h *RequiredOriginalHolds) Held(id domain.ID, now domain.Time) (bool, error) {
	if e := h.checkClock(now); e != nil {
		return false, e
	}
	if !h.initialized {
		return false, errors.New("required holds not initialized")
	}
	return h.heldUntil[id] > now, nil
}

func (h *RequiredOriginalHolds) rebuildHeldUntil() {
	h.heldUntil = map[domain.ID]domain.Time{}
	for _, r := range h.holds {
		if r.State != "active" {
			continue
		}
		for _, p := range r.Postings {
			h.heldUntil[p.Identity.ProposalID] = max(h.heldUntil[p.Identity.ProposalID], r.Binding.Until)
			h.heldUntil[p.Identity.DecisionID] = max(h.heldUntil[p.Identity.DecisionID], r.Binding.Until)
		}
	}
}

// Close は所有列を停止し、署名鍵を持つJournalを閉じる。
func (h *RequiredOriginalHolds) Close() error {
	h.stopped = true
	clear(h.public)
	if h.journal == nil {
		return nil
	}
	return h.journal.Close()
}

// requiredHoldsCreationPending は候補を変更せず検出する。有効化済み台帳では候補復旧を許さない。
func requiredHoldsCreationPending(path string) (bool, error) {
	intent := evidence.JournalCreationIntentPath(path)
	for _, candidate := range []string{intent, intent + ".tmp"} {
		if _, e := os.Lstat(candidate); e == nil {
			return true, nil
		} else if !os.IsNotExist(e) {
			return false, e
		}
	}
	return false, nil
}
