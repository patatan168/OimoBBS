// 日別署名journalを変更せず検査し、必須原本回収のreader/時計境界を返す。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"time"
)

// JournalInspection は署名/連鎖検証済みのmetadata。本文を返さない。
type JournalInspection struct {
	Sequence            uint64
	RequiredRetirements int
	RequiredFloor       domain.Time
	MinimumReader       uint32
}

// InspectJournal は署名・source・seq/前hashを読取り専用で検査する。GC/snapshot再開は行わない。
func InspectJournal(dir string, owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator) (JournalInspection, error) {
	return inspectJournal(dir, owner, day, keyID, key, validate, nil)
}

// VisitJournalReadOnly は全署名/連鎖の検査後に借用原本を走査する。参照を変更・保持しない。
// GC/修復を行わず、callback拒否時も保存元を変更しない。
func VisitJournalReadOnly(dir string, owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator, visit func(Entry) error) (JournalInspection, error) {
	if visit == nil {
		return JournalInspection{}, store.ErrCorrupt
	}
	return inspectJournal(dir, owner, day, keyID, key, validate, visit)
}

func inspectJournal(dir string, owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator, visit func(Entry) error) (JournalInspection, error) {
	date := fmt.Sprint(day)
	if _, e := time.Parse("20060102", date); e != nil || len(date) != 8 || owner == (domain.ID{}) || keyID == 0 || len(key) != ed25519.PrivateKeySize || validate == nil {
		return JournalInspection{}, store.ErrCorrupt
	}
	j := &Journal{owner: owner, day: day, keyID: keyID, key: bytes.Clone(key), validate: validate}
	defer clear(j.key)
	state, e := store.InspectControl(dir, 8, owner, day, j.validateValue)
	if e != nil {
		return JournalInspection{}, e
	}
	if e = j.replayState(state); e != nil {
		return JournalInspection{}, e
	}
	if visit != nil {
		if e = j.Visit(visit); e != nil {
			return JournalInspection{}, e
		}
	}
	retired, e := j.RequiredRetirements()
	if e != nil {
		return JournalInspection{}, e
	}
	return j.inspectionMetadata(retired), nil
}

// requiredRetirementReader は原本の署名期限と異なる24時間回収を旧readerへ渡さない。
func requiredRetirementReader(retired []RequiredRetirement) uint32 {
	if len(retired) == 0 {
		return 0
	}
	for _, r := range retired {
		if r.Envelope.Kind == "rejected_connection" {
			return 52
		}
		if r.Identity.Outcome == "not_accepted" && RequiredOriginalDeadline(r.Identity, domain.Time(math.MaxInt64)) == r.Until {
			return 52
		}
	}
	return 45
}

// inspectionMetadata は本文を返さず、新形式の現存行と回収署名の双方からreader境界を得る。
func (j *Journal) inspectionMetadata(retired []RequiredRetirement) JournalInspection {
	minimum := requiredRetirementReader(retired)
	for _, entry := range j.entries {
		if entry.Event.Kind == "rejected_connection" {
			minimum = max(minimum, 52)
		}
		if entry.Event.Kind == "journal_checkpoint" {
			minimum = max(minimum, 55)
		}
	}
	return JournalInspection{Sequence: j.seq, RequiredRetirements: len(retired), RequiredFloor: j.requiredFloor, MinimumReader: minimum}
}
