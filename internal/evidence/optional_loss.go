// 個人情報を含まない欠測集計を署名し、再起動時の未確認期間と既知件数を分離する。
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// OptionalLossFile は専用private root内の唯一の確定集計名。
const OptionalLossFile = "loss.json"
const optionalLossCandidate = "loss.pending"
const optionalLossLimit = 8192

// OptionalLossCounts は再起動を越えて累積する既知の欠測。未確認期間の件数は推測しない。
type OptionalLossCounts struct {
	Failed           uint64 `json:"failed"`
	Capacity         uint64 `json:"dropped_capacity"`
	Invalid          uint64 `json:"dropped_invalid"`
	Closed           uint64 `json:"dropped_closed"`
	Shutdown         uint64 `json:"dropped_shutdown"`
	StartupDiscarded uint64 `json:"startup_discarded"`
}

// OptionalLossSummary は固定型だけの署名対象。IP・UA・要求ID・自由文errorを受け取らない。
type OptionalLossSummary struct {
	Schema           string             `json:"schema"`
	Completeness     string             `json:"completeness"`
	Site             domain.ID          `json:"site_id"`
	Sequence         domain.U64         `json:"sequence"`
	Previous         domain.Hash        `json:"previous_sha256"`
	Boot             domain.ID          `json:"monitor_boot_id"`
	Opened           domain.Time        `json:"opened_at_ns"`
	Observed         domain.Time        `json:"observed_at_ns"`
	Clean            bool               `json:"clean_shutdown"`
	Prior            OptionalLossCounts `json:"prior_known_losses"`
	Queue            OptionalStatus     `json:"queue"`
	StartupDiscarded uint64             `json:"startup_discarded"`
	UncleanBoots     uint64             `json:"unclean_boots"`
	UnknownFrom      domain.Time        `json:"unknown_from_ns"`
	UnknownUntil     domain.Time        `json:"unknown_until_ns"`
	KnownLossFrom    domain.Time        `json:"known_loss_from_ns"`
	KnownLossUntil   domain.Time        `json:"known_loss_until_ns"`
}
type optionalLossEnvelope struct {
	Summary   json.RawMessage `json:"summary"`
	Signature string          `json:"signature"`
}

// Known は署名snapshotまでに確定した欠測だけを返し、未確認期間の要求数を足さない。
func (v OptionalLossSummary) Known() (OptionalLossCounts, error) {
	old := v.Prior
	next := OptionalLossCounts{v.Queue.Failed, v.Queue.DroppedCapacity, v.Queue.DroppedInvalid, v.Queue.DroppedClosed, v.Queue.DroppedShutdown, v.StartupDiscarded}
	a := []uint64{old.Failed, old.Capacity, old.Invalid, old.Closed, old.Shutdown, old.StartupDiscarded}
	b := []uint64{next.Failed, next.Capacity, next.Invalid, next.Closed, next.Shutdown, next.StartupDiscarded}
	for i := range a {
		if b[i] > math.MaxUint64-a[i] {
			return OptionalLossCounts{}, store.ErrCorrupt
		}
		a[i] += b[i]
	}
	return OptionalLossCounts{a[0], a[1], a[2], a[3], a[4], a[5]}, nil
}

// OptionalLossStore は呼出元がroot排他を保持する二fileの集計所有者。保存不明後は再開まで停止する。
type OptionalLossStore struct {
	mu         sync.Mutex
	root       string
	site       domain.ID
	key        ed25519.PrivateKey
	current    *OptionalLossSummary
	hash       domain.Hash
	stopped    bool
	begun      bool
	checkpoint func(string) error
}

// OpenOptionalLoss は既存署名を照合し、同期済みの直後候補だけを起動時に設置する。
// rootは事前に0700で作成する。空領域は過去に欠測がなかった証明ではない。
func OpenOptionalLoss(root string, site domain.ID, key ed25519.PrivateKey) (*OptionalLossStore, error) {
	if site == (domain.ID{}) || len(key) != ed25519.PrivateKeySize {
		return nil, store.ErrCorrupt
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !key.Public().(ed25519.PublicKey).Equal(derived.Public()) {
		return nil, store.ErrCorrupt
	}
	s := &OptionalLossStore{root: root, site: site, key: append(ed25519.PrivateKey(nil), key...)}
	if e := s.load(false); e != nil {
		clear(s.key)
		return nil, e
	}
	return s, nil
}

// InspectOptionalLoss は候補を変更せず検出し、署名・所有者・集計整合だけを照合する。
func InspectOptionalLoss(root string, site domain.ID, public ed25519.PublicKey) error {
	if site == (domain.ID{}) || len(public) != ed25519.PublicKeySize {
		return store.ErrCorrupt
	}
	s := &OptionalLossStore{root: root, site: site, key: make(ed25519.PrivateKey, 64)}
	copy(s.key[32:], public)
	return s.load(true)
}

func optionalLossMessage(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return append([]byte("oimo/optional-http-loss-summary/v1\x00"), sum[:]...)
}

// decode は固定型と正本の公開鍵に束縛した署名を検査する。
func (s *OptionalLossStore) decode(raw []byte) (OptionalLossSummary, domain.Hash, error) {
	var env optionalLossEnvelope
	var v OptionalLossSummary
	if len(raw) > optionalLossLimit || strictjson.Decode(raw, &env) != nil || strictjson.Decode(env.Summary, &v) != nil {
		return v, domain.Hash{}, store.ErrCorrupt
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || len(sig) != 64 || base64.StdEncoding.EncodeToString(sig) != env.Signature || !ed25519.Verify(ed25519.PublicKey(s.key[32:]), optionalLossMessage(env.Summary), sig) {
		return v, domain.Hash{}, store.ErrCorrupt
	}
	if v.Site != s.site || validateOptionalLoss(v) != nil {
		return v, domain.Hash{}, store.ErrCorrupt
	}
	return v, sha256.Sum256(env.Summary), nil
}

// Begin はworker受付前の未終了印を同期する。前回未終了の期間を件数不明として累積する。
func (s *OptionalLossStore) Begin(now time.Time, startupDiscarded uint64) (OptionalLossSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.begun {
		return OptionalLossSummary{}, store.ErrIncomplete
	}
	at := domain.Time(now.UnixNano())
	v := OptionalLossSummary{Schema: "optional-http-loss-summary-v1", Completeness: "snapshot_only", Site: s.site, Boot: domain.NewID(), Opened: at, Observed: at, StartupDiscarded: startupDiscarded}
	if s.current != nil {
		p := *s.current
		if at < p.Observed {
			return v, store.ErrCorrupt
		}
		known, e := p.Known()
		if e != nil {
			return v, e
		}
		v.Prior = known
		v.KnownLossFrom, v.KnownLossUntil = p.KnownLossFrom, p.KnownLossUntil
		v.UncleanBoots, v.UnknownFrom, v.UnknownUntil = p.UncleanBoots, p.UnknownFrom, p.UnknownUntil
		if !p.Clean {
			if v.UncleanBoots == math.MaxUint64 {
				return v, store.ErrCorrupt
			}
			v.UncleanBoots++
			if v.UnknownFrom == 0 {
				v.UnknownFrom = p.Observed
			}
			v.UnknownUntil = at
		}
	}
	result, err := s.save(v)
	if err == nil {
		s.begun = true
	}
	return result, err
}

// Capture は起動内の単調な集計を同期する。cleanは受付停止・全worker終了後だけ指定する。
func (s *OptionalLossStore) Capture(status OptionalStatus, now time.Time, clean bool) (OptionalLossSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || !s.begun || s.current == nil {
		return OptionalLossSummary{}, store.ErrIncomplete
	}
	v := *s.current
	v.Queue = status
	v.Observed = domain.Time(now.UnixNano())
	v.Clean = clean
	if status.LossStarted > 0 {
		if v.KnownLossFrom == 0 {
			v.KnownLossFrom = status.LossStarted
		} else {
			v.KnownLossFrom = min(v.KnownLossFrom, status.LossStarted)
		}
		v.KnownLossUntil = max(v.KnownLossUntil, status.LossFinished)
	}
	return s.save(v)
}

// Summary は最後に同期できたsnapshotを返す。現在までの完全な記録とは扱わない。
func (s *OptionalLossStore) Summary() (OptionalLossSummary, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return OptionalLossSummary{}, false
	}
	return *s.current, true
}

// Close は追加書込みを止め鍵コピーを消去する。clean印は明示Captureなしには付けない。
func (s *OptionalLossStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	clear(s.key)
}

// save は直前hashとseqを束縛し、候補Sync→rename→親Sync後だけメモリを確定する。
func (s *OptionalLossStore) save(v OptionalLossSummary) (OptionalLossSummary, error) {
	v.Sequence = 1
	if s.current != nil {
		if s.current.Sequence == domain.U64(math.MaxUint64) {
			return v, store.ErrCorrupt
		}
		v.Sequence = s.current.Sequence + 1
	}
	v.Previous = s.hash
	if e := validateOptionalLoss(v); e != nil {
		return v, e
	}
	if s.current != nil {
		if e := validateOptionalLossTransition(*s.current, v); e != nil {
			return v, e
		}
	}
	raw, e := json.Marshal(v)
	if e != nil {
		return v, e
	}
	encoded, e := json.Marshal(optionalLossEnvelope{raw, base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, optionalLossMessage(raw)))})
	if e != nil {
		return v, e
	}
	candidate := filepath.Join(s.root, optionalLossCandidate)
	if e = writeOptionalIntent(candidate, encoded); e != nil {
		s.stopped = true
		return v, e
	}
	if s.checkpoint != nil {
		if e = s.checkpoint("loss:candidate_synced"); e != nil {
			s.stopped = true
			return v, e
		}
	}
	if e = os.Rename(candidate, filepath.Join(s.root, OptionalLossFile)); e != nil {
		s.stopped = true
		return v, e
	}
	if s.checkpoint != nil {
		if e = s.checkpoint("loss:renamed"); e != nil {
			s.stopped = true
			return v, e
		}
	}
	if e = store.SyncDirectory(s.root); e != nil {
		s.stopped = true
		return v, e
	}
	s.current = &v
	s.hash = sha256.Sum256(raw)
	return v, nil
}

// load は未知file/権限違反を拒否し、一致または直後の署名候補だけを補完する。
func (s *OptionalLossStore) load(readOnly bool) error {
	info, e := os.Lstat(s.root)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	entries, e := os.ReadDir(s.root)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.Name() != OptionalLossFile && entry.Name() != optionalLossCandidate {
			return store.ErrCorrupt
		}
	}
	canonical, e := readOptionalPrivate(filepath.Join(s.root, OptionalLossFile), optionalLossLimit)
	if e == nil {
		v, h, e := s.decode(canonical)
		if e != nil {
			return e
		}
		s.current = &v
		s.hash = h
	} else if !os.IsNotExist(e) {
		return e
	}
	candidate, e := readOptionalPrivate(filepath.Join(s.root, optionalLossCandidate), optionalLossLimit)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	v, h, e := s.decode(candidate)
	if e != nil {
		return e
	}
	if s.current == nil {
		if v.Sequence != 1 || v.Previous != (domain.Hash{}) {
			return store.ErrCorrupt
		}
	} else if h != s.hash {
		if v.Previous != s.hash || validateOptionalLossTransition(*s.current, v) != nil {
			return store.ErrCorrupt
		}
	}
	if readOnly {
		return store.ErrIncomplete
	}
	if s.current != nil && h == s.hash {
		e = os.Remove(filepath.Join(s.root, optionalLossCandidate))
	} else {
		e = os.Rename(filepath.Join(s.root, optionalLossCandidate), filepath.Join(s.root, OptionalLossFile))
	}
	if e != nil {
		return e
	}
	if e = store.SyncDirectory(s.root); e != nil {
		return e
	}
	s.current = &v
	s.hash = h
	return nil
}

// validateOptionalLoss は件数収支、期限、clean終了と未確認期間の整合を検査する。
func validateOptionalLoss(v OptionalLossSummary) error {
	q := v.Queue
	if v.Schema != "optional-http-loss-summary-v1" || v.Completeness != "snapshot_only" || v.Site == (domain.ID{}) || v.Boot == (domain.ID{}) || v.Sequence == 0 || (v.Sequence == 1) != (v.Previous == (domain.Hash{})) || v.Opened <= 0 || v.Observed < v.Opened || q.Pending < 0 || q.Pending > MaxOptionalRecords || q.PendingBytes < 0 || q.PendingBytes > MaxOptionalBytes || (q.Pending == 0) != (q.PendingBytes == 0) || v.Clean && (!q.Closed || q.Pending != 0 || q.PendingBytes != 0) {
		return store.ErrCorrupt
	}
	counts := []uint64{q.Saved, q.Failed, q.DroppedShutdown, uint64(q.Pending)}
	total := uint64(0)
	for _, n := range counts {
		if n > math.MaxUint64-total {
			return store.ErrCorrupt
		}
		total += n
	}
	if total != q.Accepted {
		return store.ErrCorrupt
	}
	lost := q.Failed > 0 || q.DroppedCapacity > 0 || q.DroppedInvalid > 0 || q.DroppedClosed > 0 || q.DroppedShutdown > 0
	if lost != (q.LossStarted > 0) || lost != (q.LossFinished > 0) || q.LossFinished < q.LossStarted || q.LossFinished > v.Observed || lost && q.LossStarted < v.Opened {
		return store.ErrCorrupt
	}
	if v.UncleanBoots == 0 {
		if v.UnknownFrom != 0 || v.UnknownUntil != 0 {
			return store.ErrCorrupt
		}
	} else if v.UnknownFrom <= 0 || v.UnknownUntil < v.UnknownFrom || v.UnknownUntil > v.Opened {
		return store.ErrCorrupt
	}
	known, e := v.Known()
	if e != nil {
		return e
	}
	knownLoss := known.Failed > 0 || known.Capacity > 0 || known.Invalid > 0 || known.Closed > 0 || known.Shutdown > 0
	if knownLoss != (v.KnownLossFrom > 0) || knownLoss != (v.KnownLossUntil > 0) || v.KnownLossUntil < v.KnownLossFrom || v.KnownLossUntil > v.Observed {
		return store.ErrCorrupt
	}
	return nil
}

// validateOptionalLossTransition は同一起動内の減少と再起動時の既知集計の消失を拒否する。
func validateOptionalLossTransition(old, next OptionalLossSummary) error {
	if old.Sequence == domain.U64(math.MaxUint64) || next.Sequence != old.Sequence+1 || next.Observed < old.Observed {
		return store.ErrCorrupt
	}
	if next.Boot != old.Boot {
		known, e := old.Known()
		if e != nil || next.Prior != known || next.Queue != (OptionalStatus{}) || next.Clean || next.Opened != next.Observed || next.KnownLossFrom != old.KnownLossFrom || next.KnownLossUntil != old.KnownLossUntil {
			return store.ErrCorrupt
		}
		unclean := old.UncleanBoots
		if !old.Clean {
			if unclean == math.MaxUint64 {
				return store.ErrCorrupt
			}
			unclean++
		}
		if next.UncleanBoots != unclean {
			return store.ErrCorrupt
		}
		from, until := old.UnknownFrom, old.UnknownUntil
		if !old.Clean {
			if from == 0 {
				from = old.Observed
			}
			until = next.Opened
		}
		if next.UnknownFrom != from || next.UnknownUntil != until {
			return store.ErrCorrupt
		}
		return nil
	}
	if next.Opened != old.Opened || next.Prior != old.Prior || next.StartupDiscarded != old.StartupDiscarded || next.UncleanBoots != old.UncleanBoots || next.UnknownFrom != old.UnknownFrom || next.UnknownUntil != old.UnknownUntil || old.Clean && !next.Clean || old.Queue.Closed && !next.Queue.Closed {
		return store.ErrCorrupt
	}
	if old.KnownLossFrom != 0 && next.KnownLossFrom != old.KnownLossFrom || next.KnownLossUntil < old.KnownLossUntil {
		return store.ErrCorrupt
	}
	a, b := old.Queue, next.Queue
	if b.Accepted < a.Accepted || b.Saved < a.Saved || b.Failed < a.Failed || b.DroppedCapacity < a.DroppedCapacity || b.DroppedInvalid < a.DroppedInvalid || b.DroppedClosed < a.DroppedClosed || b.DroppedShutdown < a.DroppedShutdown || a.LossStarted != 0 && a.LossStarted != b.LossStarted || b.LossFinished < a.LossFinished {
		return store.ErrCorrupt
	}
	return nil
}

// Stopped は保存不明またはClose後の状態を返す。停止ownerへ追加保存しない。
func (s *OptionalLossStore) Stopped() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.stopped }

// Resume は同じ稼働プロセスが保存不明後に検証済みsnapshotへ戻る入口。
// bootはそのプロセスがBeginで生成済みのIDに限る。別起動は必ず新しいBeginを使う。
func (s *OptionalLossStore) Resume(boot domain.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.begun || s.current == nil || boot == (domain.ID{}) || s.current.Boot != boot {
		return store.ErrIncomplete
	}
	s.begun = true
	return nil
}
