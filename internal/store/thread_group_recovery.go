// 共有WALの全署名照合と全対象の事前検査を終えてから、個別本文の未同期末尾を再実行する。
package store

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"slices"
)

// threadReplayFile は復旧中のWrite/Sync/Close障害を同じ境界で検査する所有file。
type threadReplayFile interface {
	SyncWriter
	io.ReaderAt
	io.Seeker
	Truncate(int64) error
	Close() error
}

type threadGroupReplay struct {
	key        uint64
	generation uint64
	start      int64
	end        int64
	size       int64
	firstSeq   uint64
	lastSeq    uint64
	blocks     [][]byte
	matched    int
	file       threadReplayFile
}

// RecoverThreadCommitGroup は所有排他下、本文を開く前に呼ぶ。
// authorizeは署名検証済みproposalとの完全一致とnot_accepted決定の不存在を確認する。
// 全候補を照合するまでは変更せず、一致済みblockを保持する。全本文Sync/Close後だけ共有WALを削除する。
func RecoverThreadCommitGroup(parent string, owner domain.ID, authorize func(uint64, []byte) error) (err error) {
	path := filepath.Join(parent, ThreadGroupFile)
	if _, err = os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if owner == (domain.ID{}) || authorize == nil {
		return ErrCorrupt
	}
	if err = privateRegular(path, false); err != nil {
		return err
	}
	raw, err := readBounded(path, maxThreadGroupBytes)
	if err != nil {
		return err
	}
	records, err := decodeThreadGroups(raw)
	if err != nil {
		return err
	}
	plans, err := prepareThreadGroupReplay(records, owner, authorize)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeThreadGroupReplays(plans)) }()
	for _, plan := range plans {
		if err = plan.open(parent, owner); err != nil {
			return err
		}
	}
	return replayThreadGroupPlans(parent, plans)
}

// prepareThreadGroupReplay は有界な全blockを元frameへ戻し、署名との結合と連続位置を照合する。
func prepareThreadGroupReplay(records []threadGroupRecord, owner domain.ID, authorize func(uint64, []byte) error) ([]*threadGroupReplay, error) {
	byKey := map[uint64]*threadGroupReplay{}
	framesTotal := 0
	frameBytesTotal := 0
	for _, record := range records {
		if record.Owner != owner {
			return nil, ErrCorrupt
		}
		seen := map[domain.U64]bool{}
		count, size := 0, 0
		for _, write := range record.Writes {
			block := write.Block
			if write.Key == 0 || seen[write.Key] || write.Generation == 0 || write.Offset < 64 || write.Offset > math.MaxInt64-int64(len(block)) {
				return nil, ErrCorrupt
			}
			seen[write.Key] = true
			frames, n, err := ReadWALBlock(bytes.NewReader(block))
			if err != nil || n != int64(len(block)) || len(frames) == 0 {
				return nil, ErrCorrupt
			}
			framesTotal += len(frames)
			if framesTotal > maxThreadGroupFrames {
				return nil, ErrCorrupt
			}
			plan := byKey[uint64(write.Key)]
			if plan == nil {
				plan = &threadGroupReplay{key: uint64(write.Key), generation: uint64(write.Generation), start: write.Offset, end: write.Offset, firstSeq: frames[0].FirstSeq, lastSeq: frames[0].FirstSeq - 1}
				byKey[plan.key] = plan
			}
			if plan.generation != uint64(write.Generation) || plan.end != write.Offset {
				return nil, ErrCorrupt
			}
			for _, frame := range frames {
				if frame.FirstSeq == 0 || plan.lastSeq == math.MaxUint64 || frame.FirstSeq != plan.lastSeq+1 || len(frame.Records) != 1 {
					return nil, ErrCorrupt
				}
				canonical, err := EncodeFrame(frame)
				if err != nil {
					return nil, err
				}
				frameBytesTotal += len(canonical)
				if frameBytesTotal > maxThreadGroupFrameBytes {
					return nil, ErrCorrupt
				}
				count++
				size += len(canonical)
				if count > MaxCommitFrames || size > 8<<20 {
					return nil, ErrCorrupt
				}
				if err = authorize(plan.key, canonical); err != nil {
					return nil, err
				}
				plan.lastSeq = frame.FirstSeq
			}
			plan.blocks = append(plan.blocks, block)
			plan.end += int64(len(block))
		}
	}
	keys := make([]uint64, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var plans []*threadGroupReplay
	for _, key := range keys {
		plans = append(plans, byKey[key])
	}
	return plans, nil
}

// open はcurrentの世代・必須prefix・再実行開始位置の全てが合うfileだけを保持する。
func (p *threadGroupReplay) open(parent string, owner domain.ID) error {
	dir := filepath.Join(parent, fmt.Sprint(p.key))
	m, _, err := InspectThreadFiles(dir)
	if err != nil || m.BoardID != owner || uint64(m.ThreadKey) != p.key || uint64(m.Generation) != p.generation || uint64(m.Delta.RequiredEnd) > uint64(p.start) {
		return ErrCorrupt
	}
	path := filepath.Join(dir, m.Delta.File)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	p.file = file
	info, err := file.Stat()
	if err != nil || info.Size() < p.start || info.Size() > p.end {
		return ErrCorrupt
	}
	p.size = info.Size()
	hb := make([]byte, 64)
	if _, err = file.ReadAt(hb, 0); err != nil {
		return err
	}
	header, err := DecodeHeader(hb)
	want := Header{Owner: owner, Key: p.key, Generation: p.generation}
	if m.Base != nil {
		want.BaseSeq = uint64(m.Base.Seq)
	}
	if err != nil || header != want {
		return ErrCorrupt
	}
	last := header.BaseSeq
	end, partial, err := Scan(io.NewSectionReader(file, 0, p.start), header, m.Delta, func(frame Frame) error {
		last = frame.FirstSeq + uint64(len(frame.Records)) - 1
		return nil
	})
	if err != nil || partial || end != p.start || last == math.MaxUint64 || last+1 != p.firstSeq {
		return ErrCorrupt
	}
	return nil
}
