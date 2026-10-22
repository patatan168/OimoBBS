// 署名イベントを日別kind8 journalへ同期保存し、再読込時に連鎖を検証する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"slices"
	"time"
)

// PayloadValidator は秘密除去後の種別別完全スキーマを検査する。nilは使用不可。
// 入力は変更せず、同じ追記内の同一種別・完全byteの検査結果を共有できる純粋な検査とする。
type PayloadValidator func(kind string, payload []byte) error

// Entry は署名検証済みの非公開イベント。HTTPへそのまま返してはならない。
type Entry struct {
	Event   Event           `json:"event"`
	Payload json.RawMessage `json:"payload"`
}

// journalRowOverhead はkind8 snapshot行の固定項目・最大桁数・32桁ID・長さprefixの上界。
const journalRowOverhead = 192

// Journal は板所有ワーカー専用。排他ロックは呼出元が保持する。
// 初回Appendまでディレクトリを作らず、未知の既存ディレクトリは補完しない。
type Journal struct {
	preparedPayloads       map[domain.Hash]preparedPayload
	retainedBytes          int64
	replaySignatures       map[verifiedSignature]struct{}
	dir                    string
	owner                  domain.ID
	day                    uint64
	keyID                  uint32
	key                    ed25519.PrivateKey
	validate               PayloadValidator
	log                    *store.ControlLog
	entries                []Entry
	entryIndex             map[domain.ID]int
	ids                    map[domain.ID]bool
	stopped                bool
	retention              domain.Time
	requiredFloor          domain.Time
	seq                    uint64
	create                 func(string, store.Header, []byte, store.ValueValidator) (*store.ControlLog, error)
	optionalReclaimPending bool
	optionalHold           func(domain.ID, domain.Time) bool
}

// OpenJournal は保存済み全イベントの署名・source・連続seq・前hashを照合する。
func OpenJournal(dir string, owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator) (*Journal, error) {
	date := fmt.Sprint(day)
	if _, e := time.Parse("20060102", date); e != nil || len(date) != 8 || owner == (domain.ID{}) || keyID == 0 || len(key) != ed25519.PrivateKeySize || validate == nil {
		return nil, errors.New("invalid journal parameters")
	}
	j := &Journal{dir: dir, owner: owner, day: day, keyID: keyID, key: bytes.Clone(key), validate: validate, ids: map[domain.ID]bool{}}
	if _, e := os.Lstat(dir); os.IsNotExist(e) {
		return j, nil
	} else if e != nil {
		return nil, e
	}
	j.replaySignatures = map[verifiedSignature]struct{}{}
	defer func() { j.replaySignatures = nil }()
	log, e := store.OpenControl(dir, 8, owner, day, j.validateValue)
	if e != nil {
		return nil, e
	}
	j.log = log
	if e = j.replay(); e != nil {
		_ = j.Close()
		return nil, e
	}
	if e = j.resumeOptionalPrune(); e != nil {
		_ = j.Close()
		return nil, e
	}
	return j, nil
}

func (j *Journal) validateValue(collection, key string, old, next json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(next), []byte("null")) {
		return j.validateRemoval(collection, key, old)
	}
	if len(old) != 0 {
		return errors.New("evidence is append only")
	}
	var event Event
	if e := strictjson.Decode(next, &event); e != nil {
		return e
	}
	if collection != event.Kind || key != event.RecordID.String() {
		return errors.New("evidence row mismatch")
	}
	// 実際のseqとpreviousは全行の順序が確定したreplayでも照合する。
	public := j.key.Public().(ed25519.PublicKey)
	if e := validateEnvelope(event, event.PreviousSHA, j.keyID, public); e != nil {
		return e
	}
	payload, e := decodePayload(event)
	if e != nil || !matchesPayloadEncoding(payload, event.Payload) {
		return errors.New("invalid payload encoding")
	}
	src, e := payloadSource(payload)
	if e != nil {
		return e
	}
	if src.Owner != j.owner || src.Subkey != j.day {
		return errors.New("evidence owner mismatch")
	}
	payload, e = j.verifyPayloadSignature(src, event, payload)
	if e != nil {
		return e
	}
	if e := validateCheckpointEntry(event, payload); e != nil {
		return e
	}
	return j.validatePreparedPayload(event, payload)
}

func (j *Journal) replay() error {
	return j.replayState(j.log.State())
}

// replayState は署名済み現在行と回収証跡から元の連続seqを読み取り検証する。
func (j *Journal) replayState(state store.ControlState) error {
	j.entries = nil
	j.retainedBytes = 0
	j.entryIndex = nil
	j.ids = map[domain.ID]bool{}
	j.retention = 0
	j.requiredFloor = 0
	rows := make([]store.ControlRow, 0, len(state.Rows))
	for _, row := range state.Rows {
		j.retainedBytes += int64(len(row.Value) + journalRowOverhead)
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b store.ControlRow) int {
		if a.Revision < b.Revision {
			return -1
		}
		if a.Revision > b.Revision {
			return 1
		}
		return 0
	})
	chain := map[uint64]Event{}
	for _, row := range rows {
		if row.Revision == 0 || row.Expires != nil {
			return errors.New("invalid evidence row sequence or expiry")
		}
		var event Event
		if e := strictjson.Decode(row.Value, &event); e != nil {
			return e
		}
		if j.ids[event.RecordID] {
			return errors.New("duplicate evidence ID")
		}
		payload, e := j.verifyReplayPayload(Source{j.owner, j.day, uint64(row.Revision)}, event)
		if e != nil {
			return e
		}
		j.rememberRetention(payload)
		if e := validateCheckpointEntry(event, payload); e != nil {
			return e
		}
		j.rememberCheckpointFloor(event, payload)
		j.entries = append(j.entries, retainJournalEntry(event, payload))
		j.ids[event.RecordID] = true
		if _, exists := chain[uint64(row.Revision)]; exists {
			return store.ErrCorrupt
		}
		chain[uint64(row.Revision)] = event
		if event.Kind == "tombstone" {
			if e = j.addRemoved(chain, payload); e != nil {
				return e
			}
		}
	}
	if uint64(len(chain)) != uint64(state.Seq) {
		return errors.New("evidence sequence gap")
	}
	var previous domain.Hash
	for seq := uint64(1); seq <= uint64(state.Seq); seq++ {
		event, ok := chain[seq]
		if !ok || event.PreviousSHA != previous {
			return store.ErrCorrupt
		}
		previous = event.EventSHA
	}
	j.seq = uint64(state.Seq)
	return nil
}

// Append はsourceを渡してpayloadを組み立て、検証・署名・WAL Syncを行う。
// 一度でも保存結果が不明になったインスタンスは再開せず、再読込を必要とする。
func (j *Journal) Append(id domain.ID, kind string, committed domain.Time, build func(Source) ([]byte, error)) (Event, store.CommitResult) {
	fail := func(e error) (Event, store.CommitResult) {
		return Event{}, store.CommitResult{Status: store.NotWritten, Err: e}
	}
	if j.stopped || build == nil || j.ids[id] {
		return fail(errors.New("journal stopped or duplicate event"))
	}
	if kind == "tombstone" {
		return fail(errors.New("retirement tombstones require pruning transaction"))
	}
	seq := j.seq + 1
	source := Source{j.owner, j.day, seq}
	payload, e := build(source)
	if e != nil {
		return fail(e)
	}
	if e = j.validatePayload(kind, payload); e != nil {
		return fail(e)
	}
	var prev domain.Hash
	if len(j.entries) > 0 {
		prev = j.entries[len(j.entries)-1].Event.EventSHA
	}
	event, e := Seal(source, id, kind, payload, prev, j.keyID, j.key)
	if e != nil {
		return fail(e)
	}
	value, e := json.Marshal(event)
	if e != nil {
		return fail(e)
	}
	op := store.ControlOperation{Schema: 1, Seq: domain.U64(seq), Committed: committed, ExpectedSeq: domain.U64(seq - 1), Actor: domain.Actor{Kind: "system", Reason: "evidence"}, Mutations: []store.Mutation{{Collection: kind, Key: id.String(), Value: value}}, Result: store.ControlResult{Code: "evidence_saved", Targets: []string{id.String()}}}
	raw, e := json.Marshal(op)
	if e != nil {
		return fail(e)
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: seq, Records: []store.Record{{ID: id, JSON: raw}}})
	if e != nil {
		return fail(e)
	}
	// CreateControlの前にも全体検証し、型エラーを保存不明と区別する。
	if j.log == nil {
		if _, e = store.ApplyControl(store.ControlState{}, 8, store.Frame{FirstSeq: seq, Records: []store.Record{{ID: id, JSON: raw}}}, j.validateValue); e != nil {
			return fail(e)
		}
	}
	var result store.CommitResult
	if j.log == nil {
		create := j.create
		if create == nil {
			create = store.CreateControl
		}
		j.log, e = create(j.dir, store.Header{Kind: 8, Owner: j.owner, Key: j.day, Generation: 1}, frame, j.validateValue)
		result = store.CommitResult{Status: store.Durable}
		if e != nil {
			result = store.CommitResult{Status: store.Unknown, Err: e}
		}
	} else {
		result = j.log.Append(frame)
	}
	if result.Status == store.Unknown {
		j.stopped = true
	}
	if result.Status == store.Durable {
		j.seq = seq
		j.retainedBytes += int64(len(value) + journalRowOverhead)
		j.rememberRetention(payload)
		j.rememberCheckpointFloor(event, payload)
		j.entries = append(j.entries, retainJournalEntry(event, bytes.Clone(payload)))
		j.entryIndex = nil
		j.ids[id] = true
	}
	return event, result
}

// Entries は検証済み記録のコピーを返す。公開DTOではない。
func (j *Journal) Entries() []Entry {
	entries := make([]Entry, len(j.entries))
	for i, e := range j.entries {
		e = completeJournalEntry(e)
		entries[i] = Entry{e.Event, bytes.Clone(e.Payload)}
	}
	return entries
}

// Close は追記を停止しfileを閉じる。鍵の所有コピーを消去する。
func (j *Journal) Close() error {
	j.stopped = true
	clear(j.key)
	if j.log == nil {
		return nil
	}
	e := j.log.Close()
	j.log = nil
	return e
}

func decodePayload(event Event) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(event.Payload)
}

// Owner はjournalを所有する板IDを返す。
func (j *Journal) Owner() domain.ID { return j.owner }

// HasKind は所有列内で検証済み現在行の種別だけを調べる。payloadを復元・複製しない。
func (j *Journal) HasKind(kind string) bool {
	for _, entry := range j.entries {
		if entry.Event.Kind == kind {
			return true
		}
	}
	return false
}

// rememberRetention は検証済みpayloadの最短保持期限を所有列のメモリへ反映する。
// 保持期限のない汎用journalは零のままとする。
func (j *Journal) rememberRetention(payload []byte) {
	var v struct {
		Until domain.Time `json:"retention_until_ns"`
	}
	if json.Unmarshal(payload, &v) == nil && v.Until > 0 && (j.retention == 0 || v.Until < j.retention) {
		j.retention = v.Until
	}
}

// Visit は所有列内で検証済み記録を走査する。参照は変更・保持せず、必要な行だけ複製する。
func (j *Journal) Visit(visit func(Entry) error) error {
	for _, entry := range j.entries {
		if e := visit(completeJournalEntry(entry)); e != nil {
			return e
		}
	}
	return nil
}

// optionalHeld は元所有列が同期済みの案件予約だけを期限回収から除外する。
func (j *Journal) optionalHeld(id domain.ID, at domain.Time) bool {
	return j.optionalHold != nil && j.optionalHold(id, at)
}

// lookupEntry は所有排他内で固定IDの現在行を取得する。索引は最初の照会でだけ作り、payloadは独立所有で返す。
// 追記・部分回収・replayで索引を無効化し、回収した元IDを古いoffsetから返さない。
func (j *Journal) lookupEntry(id domain.ID) (Entry, bool, error) {
	if j.stopped {
		return Entry{}, false, store.ErrIncomplete
	}
	if j.entryIndex == nil {
		index := make(map[domain.ID]int, len(j.entries))
		for i, entry := range j.entries {
			if _, duplicate := index[entry.Event.RecordID]; duplicate {
				return Entry{}, false, store.ErrCorrupt
			}
			index[entry.Event.RecordID] = i
		}
		j.entryIndex = index
	}
	offset, found := j.entryIndex[id]
	if !found {
		return Entry{}, false, nil
	}
	if offset < 0 || offset >= len(j.entries) || j.entries[offset].Event.RecordID != id {
		return Entry{}, false, store.ErrCorrupt
	}
	entry := completeJournalEntry(j.entries[offset])
	return Entry{Event: entry.Event, Payload: bytes.Clone(entry.Payload)}, true, nil
}

// Lookup は所有列内で固定IDの現在原本を独立コピーで返す。停止列/回収済み原本は返さない。
// 非公開payloadを含むため、公開ルーターへ渡してはならない。
func (j *Journal) Lookup(id domain.ID) (Entry, bool, error) { return j.lookupEntry(id) }

// rememberCheckpointFloor は日末確認後の時計逆行で原本を再表示/回収させない。
func (j *Journal) rememberCheckpointFloor(event Event, payload []byte) {
	if event.Kind != "journal_checkpoint" {
		return
	}
	p, e := DecodeJournalCheckpoint(payload)
	if e == nil {
		j.requiredFloor = max(j.requiredFloor, p.At)
	}
}
