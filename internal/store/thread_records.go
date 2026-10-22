// 投稿と接続記録の照合に使う、WAL由来の操作識別子と確定frame hashを保持する。
package store

import (
	"crypto/sha256"
	"oimobbs/internal/domain"
)

// ThreadRecord は公開用ではない。再送判定に必要なHMACを含む。
type ThreadRecord struct {
	ID        domain.ID
	Seq       domain.U64
	FrameSHA  domain.Hash
	Type      string
	Committed domain.Time
	Dedup     *domain.Dedup
}

// PackedSequence は現在の耐久packの基準位置。未圧縮なら零を返す。
func (t *ThreadLog) PackedSequence() domain.U64 {
	if t.manifest.Base == nil {
		return 0
	}
	return t.manifest.Base.Seq
}

// ValidateThreadFrame は保存前に候補全体を検証する。既存状態は変更しない。
func ValidateThreadFrame(old *domain.Thread, prepared []byte) (*domain.Thread, error) {
	frame, e := decodeFrameView(prepared)
	if e != nil {
		return nil, ErrCorrupt
	}
	return applyFrame(old, frame)
}

func frameRecords(f Frame) []ThreadRecord {
	// ReadFrameが受理した正規binary構造は、JSON/DAT元byteを維持して再符号化できる。
	encoded, _ := EncodeFrame(f)
	hash := sha256.Sum256(encoded)
	records := make([]ThreadRecord, 0, len(f.Records))
	for _, r := range f.Records {
		op, _ := domain.ParseOperation(r.JSON) // applyFrame後だけ呼ぶ。
		records = append(records, ThreadRecord{r.ID, op.Revision, hash, op.Type, op.Committed, op.Dedup})
	}
	return records
}

// Records は検証済み操作のコピーを返す。公開前のevidence照合と再送索引専用。
func (t *ThreadLog) Records() []ThreadRecord {
	records := append([]ThreadRecord(nil), t.records...)
	for i := range records {
		records[i] = cloneThreadRecord(records[i])
	}
	return records
}

// FirstRecord はスレ立ての再送照合用に、返信履歴を複製せず初回操作だけを返す。
func (t *ThreadLog) FirstRecord() (ThreadRecord, bool) {
	if len(t.records) == 0 {
		return ThreadRecord{}, false
	}
	return cloneThreadRecord(t.records[0]), true
}

// DedupRecord は期限内の同一再送キーだけを探し、一致した一件だけを複製する。
// 明示IDの本文不一致も返す。呼出元が競合を判定し、保存済み情報を変更しない。
func (t *ThreadLog) DedupRecord(want *domain.Dedup, now domain.Time) (ThreadRecord, bool) {
	key, ok := dedupLookupKey(want)
	if !ok {
		return ThreadRecord{}, false
	}
	t.extendDedupIndex()
	for _, index := range t.dedupIndex[key] {
		record := t.records[index]
		if record.Dedup != nil && now < record.Dedup.Expires {
			return cloneThreadRecord(record), true
		}
	}
	return ThreadRecord{}, false
}

// PublicationDates は公開版の日時条件を、非公開再送情報の複製なしで検算する。
func (t *ThreadLog) PublicationDates() (modified domain.Time, safe, exact bool) {
	safe = true
	for i, record := range t.records {
		if i > 0 && record.Committed < modified || record.Type != "create" && record.Type != "append" {
			safe = false
		}
		exact = i == 0 || record.Committed/1e9 > modified/1e9
		modified = record.Committed
	}
	return
}
func cloneThreadRecord(record ThreadRecord) ThreadRecord {
	if record.Dedup != nil {
		d := *record.Dedup
		if d.RequestID != nil {
			id := *d.RequestID
			d.RequestID = &id
		}
		record.Dedup = &d
	}
	return record
}
