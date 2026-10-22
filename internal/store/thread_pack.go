// 投稿packの基準照合・世代配置・停止中の同期切替を実装する。
package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// PackVerifier は署名済み操作からpack全体を照合し、基準までの操作識別を復元する。
type PackVerifier func(PackSnapshot) ([]ThreadRecord, error)

// InspectThreadFiles はcurrentだけを正本として参照し、残存世代の最大値を返す。
// 旧世代・current切替前の孤立候補は採用しない。予期しない名前やsymlinkは拒否する。
func InspectThreadFiles(dir string) (Manifest, uint64, error) {
	if e := privateRegular(dir, true); e != nil {
		return Manifest{}, 0, e
	}
	f, e := os.Open(dir)
	if e != nil {
		return Manifest{}, 0, e
	}
	names, e := f.Readdirnames(4097)
	ce := f.Close()
	if e != nil && e != io.EOF {
		return Manifest{}, 0, e
	}
	if ce != nil {
		return Manifest{}, 0, ce
	}
	if len(names) > 4096 {
		return Manifest{}, 0, ErrCorrupt
	}
	if e = privateRegular(filepath.Join(dir, "current.json"), false); e != nil {
		return Manifest{}, 0, e
	}
	raw, e := readBounded(filepath.Join(dir, "current.json"), 16<<10)
	if e != nil {
		return Manifest{}, 0, e
	}
	m, e := DecodeCurrent(raw)
	if e != nil {
		return Manifest{}, 0, e
	}
	largest := uint64(m.Generation)
	for _, name := range names {
		if e = privateRegular(filepath.Join(dir, name), false); e != nil {
			return Manifest{}, 0, e
		}
		if name == "current.json" {
			continue
		}
		// atomicFileの途中停止で残った非参照current。復旧元としては使わない。
		if strings.HasPrefix(name, ".install-") {
			continue
		}
		prefix, suffix := "delta-", ".wal"
		if strings.HasPrefix(name, "base-") {
			prefix, suffix = "base-", ".pack"
		}
		digits := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
		g, err := strconv.ParseUint(digits, 10, 64)
		if err != nil || g == 0 || name != fmt.Sprintf("%s%06d%s", prefix, g, suffix) {
			return Manifest{}, 0, ErrCorrupt
		}
		largest = max(largest, g)
	}
	return m, largest, nil
}

// PreparePack は確定済みdeltaだけを再生し、次の空いている保存世代の候補を返す。
// 呼出元は板の直列実行と排他を維持する。正本への変更は行わない。
func (t *ThreadLog) PreparePack(at domain.Time, level uint8) ([]byte, error) {
	if t.writer.stopped {
		return nil, errors.New("writer stopped")
	}
	_, generation, e := InspectThreadFiles(t.dir)
	if e != nil {
		return nil, e
	}
	if generation == math.MaxUint64 {
		return nil, ErrCorrupt
	}
	b := NewPackBuilder(t.base)
	_, partial, e := Scan(io.NewSectionReader(t.file, 0, t.end), t.header, t.manifest.Delta, b.Apply)
	if e != nil {
		return nil, e
	}
	if partial {
		return nil, ErrCorrupt
	}
	s := b.Snapshot(t.header.Owner, t.header.Key, generation+1, at)
	if s.State == nil || s.State.Revision != t.state.Revision {
		return nil, ErrCorrupt
	}
	return EncodePack(s, level)
}

// SwitchPack は現行の全状態と一致するpack・空deltaを同期してcurrentを切り替える。
// 非公開証拠の照合は呼出元の責務。旧世代は残し、保存開始後の失敗では追記を停止する。
func (t *ThreadLog) SwitchPack(raw []byte) CommitResult {
	return t.switchPack(raw, func(string) error { return nil })
}

// SwitchPackGuarded は保存開始前とcurrent置換直前に公開期限などの条件を再確認する。
// 保存開始後の失効はUnknownとしてwriterを止め、current置換を行わない。
func (t *ThreadLog) SwitchPackGuarded(raw []byte, valid func() error) CommitResult {
	if valid == nil {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	if e := valid(); e != nil {
		return CommitResult{NotWritten, e}
	}
	return t.switchPack(raw, func(stage string) error {
		if stage == "current_sync" {
			return valid()
		}
		return nil
	})
}

func (t *ThreadLog) switchPack(raw []byte, boundary func(string) error) (result CommitResult) {
	if t.writer.stopped {
		return CommitResult{Unknown, errors.New("writer stopped")}
	}
	s, e := DecodePack(raw)
	if e != nil {
		return CommitResult{NotWritten, e}
	}
	want, e := t.PreparePack(s.At, 0)
	if e != nil {
		return CommitResult{NotWritten, e}
	}
	normalized, e := EncodePack(s, 0)
	if e != nil || !bytes.Equal(want, normalized) {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	h := Header{Owner: s.Owner, Key: s.Key, Generation: s.Generation, BaseSeq: uint64(s.State.Revision)}
	hb, e := EncodeHeader(h)
	if e != nil {
		return CommitResult{NotWritten, e}
	}
	packName, deltaName := fmt.Sprintf("base-%06d.pack", s.Generation), fmt.Sprintf("delta-%06d.wal", s.Generation)
	m := Manifest{Schema: 1, BoardID: s.Owner, ThreadKey: domain.U64(s.Key), Generation: domain.U64(s.Generation), Base: &Base{packName, domain.U64(len(raw)), sha256.Sum256(raw), s.State.Revision, s.State.After.DATGeneration}, Delta: Delta{deltaName, s.State.Revision, s.State.Revision, 64, sha256.Sum256(hb)}}
	current, e := EncodeCurrent(m)
	if e != nil {
		return CommitResult{NotWritten, e}
	}
	result.Status = Unknown
	defer func() {
		if result.Status != Durable {
			t.writer.stopped = true
		}
	}()
	if e = writeSwitchFile(filepath.Join(t.dir, packName), raw); e != nil {
		return CommitResult{Unknown, e}
	}
	if e = boundary("pack_sync"); e != nil {
		return CommitResult{Unknown, e}
	}
	saved, e := readBounded(filepath.Join(t.dir, packName), MaxPackFile)
	if e != nil || !bytes.Equal(saved, raw) {
		return CommitResult{Unknown, errors.Join(e, ErrCorrupt)}
	}
	if e = writeSwitchFile(filepath.Join(t.dir, deltaName), hb); e != nil {
		return CommitResult{Unknown, e}
	}
	if e = SyncDirectory(t.dir); e != nil {
		return CommitResult{Unknown, e}
	}
	if e = boundary("generation_sync"); e != nil {
		return CommitResult{Unknown, e}
	}
	next, e := os.OpenFile(filepath.Join(t.dir, deltaName), os.O_RDWR|os.O_APPEND, 0)
	if e != nil {
		return CommitResult{Unknown, e}
	}
	adopted := false
	defer func() {
		if !adopted {
			result.Err = errors.Join(result.Err, next.Close())
		}
	}()
	// 共通のcurrent切替はcontrolと同じrename/Sync境界を持つが、threadの形式で検証済み。
	if e = installNamedSwitch(t.dir, "current.json", current, boundary); e != nil {
		return CommitResult{Unknown, e}
	}
	if e = t.file.Close(); e != nil {
		return CommitResult{Unknown, e}
	}
	t.file = next
	t.writer = NewWriter(next)
	t.header = h
	t.manifest = m
	t.state = s.State
	t.packLevel = packMinimumLevel(raw)
	t.packCodec = packCompressionCodec(raw)
	t.base = &s
	t.replaceRecords(retainPackRecords(t.records, s.At))
	t.end = 64
	adopted = true
	if e = boundary("handle_switched"); e != nil {
		return CommitResult{Unknown, e}
	}
	return CommitResult{Durable, nil}
}

// retainPackRecords は回収済み再送情報を時計逆行で復活させない。操作識別は残す。
func retainPackRecords(records []ThreadRecord, at domain.Time) []ThreadRecord {
	out := make([]ThreadRecord, len(records))
	for i, r := range records {
		out[i] = cloneThreadRecord(r)
		if r.Dedup != nil && r.Dedup.Expires <= at {
			out[i].Dedup = nil
		}
	}
	return out
}

// StorageStopped は所有ワーカーが保存停止を上位へ伝えるための状態。
func (t *ThreadLog) StorageStopped() bool { return t.writer.stopped }
