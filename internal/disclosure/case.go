// Package disclosure は制限領域の案件台帳・保全コピー・提出物を同期保存する。
package disclosure

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
	"unicode/utf8"
)

const MaxRecords = 100
const MaxCases = 128
const MaxArtifactBytes = 64 << 20

var ErrRevision = errors.New("evidence revision conflict")
var ErrConflict = errors.New("evidence revision or request conflict")
var ErrExpired = errors.New("evidence case expired or released")
var ErrLimit = errors.New("evidence case capacity exceeded")
var ErrInvalid = errors.New("invalid evidence request")

// Scope は明示された一板のスレッド・投稿日時範囲。全サイト保全は許可しない。
type Scope struct {
	Board   domain.ID   `json:"board_id"`
	Thread  domain.U64  `json:"thread_key"`
	From    domain.Time `json:"from_ns"`
	To      domain.Time `json:"to_ns"`
	Records []domain.ID `json:"record_ids"`
}

// Case は案件管理情報だけを持つ。IP・投稿本文は別の期限付きコピーへ保存する。
type Case struct {
	Rejected          *RejectedHold          `json:"rejected_hold"`
	ID                domain.ID              `json:"id"`
	Number            string                 `json:"case_number"`
	Organization      string                 `json:"requesting_organization"`
	Reference         string                 `json:"request_reference"`
	Reason            string                 `json:"reason"`
	Creator           domain.ID              `json:"created_by"`
	Created           domain.Time            `json:"created_at_ns"`
	Until             domain.Time            `json:"hold_until_ns"`
	Review            domain.Time            `json:"review_at_ns"`
	Scope             Scope                  `json:"scope"`
	State             string                 `json:"state"`
	Revision          domain.U64             `json:"revision"`
	Items             []Item                 `json:"items"`
	Exports           []Export               `json:"exports"`
	Closed            domain.Time            `json:"closed_at_ns"`
	RequiredExtension *RequiredHoldExtension `json:"required_hold_extension"`
	Extension         *HoldExtension         `json:"hold_extension"`
	HTTP              *HTTPHold              `json:"optional_http_hold"`
	Required          *RequiredSourceHold    `json:"required_original_hold"`
}

// Item は保全対象の原本hashと保全コピーhashだけを台帳へ保存する。
type Item struct {
	Record  domain.ID   `json:"record_id"`
	Source  domain.Hash `json:"source_event_sha256"`
	SHA     domain.Hash `json:"held_sha256"`
	Expires domain.Time `json:"source_expires_at_ns"`
	State   string      `json:"state"`
}

// Export は提出物の期限と消費状態。ダウンロードを受渡し完了へ読み替えない。
type Export struct {
	RejectedHeld    bool                 `json:"rejected_held"`
	ID              domain.ID            `json:"id"`
	SHA             domain.Hash          `json:"sha256"`
	Bytes           domain.U64           `json:"bytes"`
	Created         domain.Time          `json:"created_at_ns"`
	Until           domain.Time          `json:"retention_until_ns"`
	Columns         []string             `json:"columns"`
	State           string               `json:"state"`
	Kind            string               `json:"record_kind"`
	RejectedSources []app.RejectedSource `json:"rejected_sources"`
	HTTPSelection   domain.Hash          `json:"optional_http_selection_sha256"`
}

// Transfer は保存済み署名監査に含まれる受渡し情報の読み取り型。新規登録は行わない。
type Transfer struct {
	Export       domain.ID   `json:"export_id"`
	Organization string      `json:"organization"`
	Reference    string      `json:"reference"`
	Method       string      `json:"method"`
	At           domain.Time `json:"transferred_at_ns"`
	Acknowledged bool        `json:"acknowledged"`
}

// Audit は署名された案件操作。本文・IPを含めず、選択項目と結果を記録する。
type Audit struct {
	Owner      domain.ID   `json:"source_owner_id"`
	Subkey     domain.U64  `json:"source_subkey"`
	Seq        domain.U64  `json:"source_control_seq"`
	At         domain.Time `json:"at_ns"`
	Actor      domain.ID   `json:"actor_id"`
	Action     string      `json:"action"`
	Purpose    string      `json:"purpose"`
	Columns    []string    `json:"columns"`
	RequestKey domain.Hash `json:"request_key_hmac"`
	Request    domain.Hash `json:"request_hmac"`
	Case       Case        `json:"case"`
	Transfer   *Transfer   `json:"transfer"`
}

// Store は呼出元が排他を保持する案件所有者。保存不明時は再起動まで停止する。
type Store struct {
	logExplanation    func(Scope) (string, error)
	completionTail    bool
	exportCleanupTail bool
	checkpoint        func(string) error
	requests          map[domain.ID]map[domain.Hash]domain.ID
	root              string
	key               ed25519.PrivateKey
	logs              map[domain.ID]*store.ControlLog
	retired           map[domain.Hash]struct{}
	stopped           bool
}

// Open は既存案件の署名・連鎖と固定名を検証する。未知ファイルを補完しない。
func Open(root string, key ed25519.PrivateKey) (*Store, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	info, e := os.Lstat(root)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, store.ErrCorrupt
	}
	s := &Store{root: root, key: slices.Clone(key), logs: map[domain.ID]*store.ControlLog{}, requests: map[domain.ID]map[domain.Hash]domain.ID{}}
	if e := s.resumeCreations(); e != nil {
		s.Close()
		return nil, e
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	if len(entries) > MaxCases {
		return nil, ErrLimit
	}
	for _, entry := range entries {
		var id domain.ID
		if !entry.IsDir() || json.Unmarshal([]byte(fmt.Sprintf("%q", entry.Name())), &id) != nil || id == (domain.ID{}) {
			s.Close()
			return nil, store.ErrCorrupt
		}
		if info, e := entry.Info(); e != nil || info.Mode().Perm() != 0700 {
			s.Close()
			return nil, store.ErrCorrupt
		}
		path := filepath.Join(root, entry.Name())
		names, err := os.ReadDir(path)
		if err != nil {
			s.Close()
			return nil, err
		}
		for _, name := range names {
			if name.Name() != "control" && name.Name() != "items" && name.Name() != "exports" && name.Name() != "http" {
				s.Close()
				return nil, store.ErrCorrupt
			}
			if !name.IsDir() {
				s.Close()
				return nil, store.ErrCorrupt
			}
		}
		log, err := store.OpenControl(filepath.Join(path, "control"), 9, id, 0, s.validator(id))
		if err != nil {
			s.Close()
			return nil, err
		}
		s.logs[id] = log
		if err = s.walkHistory(id, log.State(), func(a Audit, event evidence.Event) error { return s.rememberRequest(id, a, event) }); err != nil {
			s.Close()
			return nil, err
		}
		last, err := s.lastAudit(id)
		if err == nil {
			err = s.inspectHTTPArtifacts(last.Case, true)
		}
		if err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close は案件正本を閉じ、鍵コピーを消去する。
func (s *Store) Close() error {
	var errs []error
	for _, l := range s.logs {
		errs = append(errs, l.Close())
	}
	clear(s.key)
	s.stopped = true
	return errors.Join(errs...)
}
func (s *Store) validator(id domain.ID) store.ValueValidator {
	return func(collection, key string, old, next json.RawMessage) error {
		if collection != "transfer" || len(old) != 0 {
			return store.ErrCorrupt
		}
		return s.validateCaseEventValue(id, key, next)
	}
}

// validateCaseEventValue は署名/完全型/尾部枠をControl保存前に照合する。
func (s *Store) validateCaseEventValue(id domain.ID, key string, next json.RawMessage) error {
	var event evidence.Event
	if strictjson.Decode(next, &event) != nil || key != event.RecordID.String() {
		return store.ErrCorrupt
	}
	raw, e := evidence.Verify(evidence.Source{Owner: id, Seq: sequence(event)}, event, event.PreviousSHA, 10, s.key.Public().(ed25519.PublicKey))
	if e != nil {
		return fmt.Errorf("case signature: %w", e)
	}
	var a Audit
	if e = strictjson.Decode(raw, &a); e != nil {
		return e
	}
	if e = validateAudit(id, a); e != nil {
		return e
	}
	if e = validateCaseCompletionAudit(a); e != nil {
		return e
	}
	return s.checkCaseTailAppend(a)
}
func sequence(event evidence.Event) uint64 {
	var a struct {
		Seq domain.U64 `json:"source_control_seq"`
	}
	_ = json.Unmarshal(decode(event.Payload), &a)
	return uint64(a.Seq)
}
func (s *Store) history(id domain.ID) ([]Audit, error) {
	log := s.logs[id]
	if log == nil {
		return nil, os.ErrNotExist
	}
	return s.historyState(id, log.State())
}
func (s *Store) historyState(id domain.ID, state store.ControlState) ([]Audit, error) {
	out := []Audit{}
	e := s.walkHistory(id, state, func(a Audit, _ evidence.Event) error { out = append(out, a); return nil })
	return out, e
}

// Cases は本文を含まない案件の現在値を返す。
func (s *Store) Cases() ([]Case, error) {
	out := []Case{}
	for id := range s.logs {
		v, e := s.Get(id)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, nil
}

// Get は署名検証済み台帳の最新案件を返す。
func (s *Store) Get(id domain.ID) (Case, error) {
	a, e := s.lastAudit(id)
	return a.Case, e
}

// ETag は案件のCAS版を返す。
func (c Case) ETag() string { return fmt.Sprintf(`"evidence:%s:%d"`, c.ID, c.Revision) }

// IDFor は同一操作者・要求IDの作成再送を同じ案件へ束縛する。
func (s *Store) IDFor(actor domain.ID, key string) domain.ID {
	h := s.mac("case-id", actor[:], []byte(key))
	var id domain.ID
	copy(id[:], h[:16])
	return id
}
func (s *Store) mac(purpose string, parts ...[]byte) domain.Hash {
	h := hmac.New(sha256.New, s.key.Seed())
	h.Write([]byte(purpose))
	for _, p := range parts {
		fmt.Fprintf(h, "%d:", len(p))
		h.Write(p)
	}
	var out domain.Hash
	copy(out[:], h.Sum(nil))
	return out
}
func validText(v string, required bool) bool {
	return utf8.ValidString(v) && len(v) <= 2048 && (!required || len(v) > 0)
}
func validateAudit(id domain.ID, a Audit) error {
	c := a.Case
	if a.Owner != id || a.Subkey != 0 || a.Seq == 0 || a.At <= 0 || a.Actor == (domain.ID{}) || c.ID != id || c.Created <= 0 || c.Created > a.At || c.Revision != a.Seq || !validText(c.Number, true) || !validText(c.Reason, true) || !validText(c.Organization, false) || !validText(c.Reference, false) || !validText(a.Purpose, true) || c.Scope.Board == (domain.ID{}) || c.Scope.From <= 0 || c.Scope.From >= c.Scope.To || c.Until <= c.Created || len(c.Scope.Records) > MaxRecords || len(c.Items) > MaxRecords || len(c.Exports) > maxCaseExports || !slices.Contains([]string{"draft", "preparing", "active", "partial", "releasing", "closed"}, c.State) || !slices.Contains([]string{"create", "http_query", "rejected_query", "rejected_hold_intent", "rejected_hold_complete", "hold_intent", "hold_complete", "hold_reserved", "hold_reconciled", "hold_released", "required_extend_intent", "required_extend_complete", "http_hold_intent", "http_hold_complete", "http_hold_reserved", "http_hold_released", "query", "extend", "extend_intent", "extend_complete", "release", "expire", "export_intent", "export_resume", "export_ready", "download", "transfer", "cleanup", "export_cleanup"}, a.Action) || !ValidColumns(a.Columns) {
		return ErrInvalid
	}
	if c.HTTP != nil && c.HTTP.Reservation != nil {
		ref := c.HTTP.Reservation
		if ref.Binding.Case != c.ID || ref.Binding.Revision > c.Revision || ref.Binding.Board != c.Scope.Board || ref.Binding.From != c.Scope.From || ref.Binding.To != c.Scope.To || ref.Binding.Until > c.RetentionUntil() || ref.At > a.At {
			return store.ErrCorrupt
		}
	}
	if e := validateUnboundHTTPCase(c); e != nil {
		return e
	}
	if e := validateHTTPQueryAudit(a); e != nil {
		return e
	}
	if e := validateRejectedHold(c, a.At); e != nil {
		return e
	}
	if e := validateRejectedCaseAudit(a); e != nil {
		return e
	}
	if e := validateHTTPReleaseCase(c, a.At); e != nil {
		return e
	}
	if e := validateExtension(c, a.At); e != nil {
		return e
	}
	if e := validateRequiredExtensionAudit(a); e != nil {
		return e
	}
	if e := validateRequiredSourceCase(c, a.At); e != nil {
		return e
	}
	return validateHTTPHold(c.HTTP, a.At)
}

// ValidColumns は許可された部分列だけを受け付け、重複・未知列を拒否する。
func ValidColumns(columns []string) bool { return app.ValidAcceptedColumns(columns) }

// Create は明示範囲と期限を検査し、署名付き案件作成を同期保存する。
func (s *Store) Create(c Case, actor domain.ID, etag, key string, now time.Time) (Case, error) {
	c.ID = s.IDFor(actor, key)
	if _, retired := s.retired[s.CaseRetirementFingerprint(c.ID)]; retired {
		return Case{}, ErrExpired
	}
	if c.Scope.Records == nil {
		c.Scope.Records = []domain.ID{}
	}
	if _, ok := s.logs[c.ID]; ok {
		if v, ok, e := s.Replay(c.ID, actor, "create", etag, key, creationInput(c)); ok || e != nil {
			return v, e
		}
		return Case{}, ErrConflict
	}
	if etag != `"evidence:new"` {
		return Case{}, ErrRevision
	}
	if len(s.logs) >= MaxCases {
		return Case{}, ErrLimit
	}
	request := creationInput(c)
	at := domain.Time(now.UnixNano())
	if c.Until == 0 {
		c.Until = at + domain.Time(30*24*time.Hour)
	}
	if c.Until <= at || c.Until > at+domain.Time(180*24*time.Hour) || c.Scope.To > at || c.Scope.From >= c.Scope.To || c.Scope.From <= 0 || c.Scope.Board == (domain.ID{}) || len(c.Scope.Records) > MaxRecords {
		return Case{}, ErrInvalid
	}
	seen := map[domain.ID]bool{}
	for _, id := range c.Scope.Records {
		if id == (domain.ID{}) || seen[id] {
			return Case{}, ErrInvalid
		}
		seen[id] = true
	}
	c.Created = at
	c.Creator = actor
	c.State = "draft"
	c.Revision = 0
	c.Items = []Item{}
	c.Exports = []Export{}
	c.Review = c.Until - domain.Time(7*24*time.Hour)
	return s.append(c, actor, "create", c.Reason, nil, etag, key, request, now)
}

// Replay は同一要求の確定結果を返す。入力変更の再送は拒否する。
func (s *Store) Replay(id, actor domain.ID, action, etag, key string, input any) (Case, bool, error) {
	if s.logs[id] == nil {
		return Case{}, false, nil
	}
	raw, e := json.Marshal(input)
	if e != nil {
		return Case{}, false, e
	}
	kh := s.mac("request-key", actor[:], []byte(key))
	rh := s.mac("request", actor[:], []byte(action), []byte(etag), raw)
	a, found, e := s.requestAudit(id, kh)
	if e != nil || !found {
		return Case{}, false, e
	}
	if a.Request != rh {
		return Case{}, false, ErrConflict
	}
	return a.Case, true, nil
}
func (s *Store) state(id domain.ID) store.ControlState {
	if l := s.logs[id]; l != nil {
		return l.State()
	}
	return store.ControlState{}
}

// AuthorizeState は期限・解除・時計逆行・CASを検査する。残存bytesを期限後に救済しない。
func (s *Store) AuthorizeState(id domain.ID, etag string, now time.Time) (Case, error) {
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.ETag() != etag {
		return c, ErrRevision
	}
	last, e := s.lastAudit(id)
	if e != nil {
		return c, e
	}
	at := domain.Time(now.UnixNano())
	if at < last.At || at >= c.Until || c.State == "closed" || c.State == "releasing" || c.State == "draft" && at >= c.Created+domain.Time(7*24*time.Hour) {
		return c, ErrExpired
	}
	return c, nil
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

func creationInput(c Case) any {
	return struct {
		Number, Organization, Reference, Reason string
		Until                                   domain.Time
		Scope                                   Scope
	}{c.Number, c.Organization, c.Reference, c.Reason, c.Until, c.Scope}
}
