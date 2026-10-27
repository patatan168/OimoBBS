// 制御WALの確定済みprefixだけを、読取り位置を変更せず有界に走査する。
package store

import (
	"context"
	"errors"
	"io"
	"math"
)

// ErrHistoryCompacted はsnapshot以前の操作履歴が現行deltaに存在しないことを示す。
var ErrHistoryCompacted = errors.New("control history was compacted")

var ErrHistoryBudget = errors.New("control history scan budget exceeded")

// HistoryBudget は複数所有単位を通じた読取りbyte数とframe数の残量。並行共有しない。
type HistoryBudget struct {
	Bytes  int64
	Frames uint64
}

// VisitCommitted は所有ワーカーから呼ぶ。Sync失敗後の末尾はstate.Seqより先なので参照しない。
// callbackには秘密を含む正本が渡る。外部応答へは許可した要約だけをコピーすること。
func (c *ControlLog) VisitCommitted(ctx context.Context, budget *HistoryBudget, visit func(Record, ControlOperation) error) error {
	var cursor HistoryCursor
	return c.VisitCommittedFrom(ctx, &cursor, budget, visit)
}

// HistoryCursor は単一の開いたControlLog専用の走査位置。保存・改変せず、再起動時はゼロから復元する。
// callbackが成功したframeだけ進める。所有ワーカー外で共有しない。
type HistoryCursor struct {
	log     *ControlLog
	offset  int64
	seq     uint64
	header  Header
	pending []Frame
}

// VisitCommittedFrom は前回成功した位置以降を読む。callbackは再実行に耐える保存処理にする。
func (c *ControlLog) VisitCommittedFrom(ctx context.Context, cursor *HistoryCursor, budget *HistoryBudget, visit func(Record, ControlOperation) error) error {
	if c.header.BaseSeq != 0 {
		return ErrHistoryCompacted
	}
	return c.VisitDeltaFrom(ctx, cursor, budget, visit)
}

// VisitDeltaFrom は現行世代のbase_seqより後だけを走査する。圧縮前の履歴は含まない。
// 全履歴の証明には呼出元でsnapshot境界の証明を照合する。世代切替前のcursorは拒否する。
func (c *ControlLog) VisitDeltaFrom(ctx context.Context, cursor *HistoryCursor, budget *HistoryBudget, visit func(Record, ControlOperation) error) error {
	if cursor == nil || budget == nil || visit == nil {
		return ErrHistoryBudget
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if cursor.log != nil && (cursor.log != c || cursor.header != c.header) {
		return ErrCorrupt
	}
	if cursor.log == c && cursor.seq == uint64(c.state.Seq) {
		return nil
	}
	if cursor.log == nil {
		if budget.Bytes < 64 {
			return ErrHistoryBudget
		}
		hb := make([]byte, 64)
		n, e := c.file.ReadAt(hb, 0)
		budget.Bytes -= int64(n)
		if e != nil {
			return e
		}
		header, e := DecodeHeader(hb)
		if e != nil || header != c.header {
			return ErrCorrupt
		}
		*cursor = HistoryCursor{log: c, offset: 64, seq: c.header.BaseSeq, header: c.header}
	}
	reader := &io.LimitedReader{R: io.NewSectionReader(c.file, cursor.offset, math.MaxInt64-cursor.offset), N: budget.Bytes}
	before := reader.N
	defer func() { budget.Bytes -= before - reader.N }()
	for cursor.seq < uint64(c.state.Seq) {
		if e := ctx.Err(); e != nil {
			return e
		}
		if budget.Frames == 0 || reader.N <= 0 && len(cursor.pending) == 0 {
			return ErrHistoryBudget
		}
		if len(cursor.pending) == 0 {
			frames, n, err := ReadWALBlock(reader)
			if err != nil {
				if reader.N == 0 && (errors.Is(err, ErrIncomplete) || errors.Is(err, io.EOF)) {
					return ErrHistoryBudget
				}
				return err
			}
			cursor.offset += n
			cursor.pending = frames
		}
		frame := cursor.pending[0]
		budget.Frames--
		seq := cursor.seq + 1
		if frame.FirstSeq != seq || len(frame.Records) != 1 || len(frame.Records[0].DAT) != 0 {
			return ErrCorrupt
		}
		var op ControlOperation
		var e error
		op, e = decodeStoredControlOperation(frame.Records[0].JSON)
		if e != nil {
			return e
		}
		if uint64(op.Seq) != seq || uint64(op.ExpectedSeq) != seq-1 || op.Actor.Validate() != nil {
			return ErrCorrupt
		}
		if e := visit(frame.Records[0], op); e != nil {
			return e
		}
		cursor.seq = seq
		cursor.pending[0] = Frame{}
		cursor.pending = cursor.pending[1:]
	}
	return nil
}

// HistoryHeader は移管証明を所有者・世代・開始seqへ束縛するための読取り専用情報を返す。
func (c *ControlLog) HistoryHeader() Header { return c.header }
