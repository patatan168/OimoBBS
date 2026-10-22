// 個別frameの復旧契約を変えず、同じスレッドへの連続した返信を一括同期する。
package store

// CommitStats はこのスレッドWALの保存呼出し数を返す。current/親同期は含まない。
func (t *ThreadLog) CommitStats() CommitStats { return t.writer.Stats() }

// AppendBatch は全frameを順番に検証し、一度のWrite/Sync後だけ復旧状態を交換する。
// 失敗時は候補を公開せず、保存結果不明のWriterは再開しない。
func (t *ThreadLog) AppendBatch(frames [][]byte) CommitResult {
	if len(frames) == 0 || len(frames) > MaxCommitFrames {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	next := t.state
	var records []ThreadRecord
	var size int64
	for _, prepared := range frames {
		if len(frames) > 1 && int64(len(prepared)) > (8<<20)-size {
			return CommitResult{NotWritten, ErrCorrupt}
		}
		f, e := decodeFrameView(prepared)
		if e != nil {
			return CommitResult{NotWritten, ErrCorrupt}
		}
		next, e = applyFrame(next, f)
		if e != nil {
			return CommitResult{NotWritten, e}
		}
		records = append(records, frameRecords(f)...)
		size += int64(len(prepared))
	}
	before := t.writer.Stats().Bytes
	result := t.writer.CommitBatch(frames)
	if result.Status == Durable {
		t.state = next
		t.end += int64(t.writer.Stats().Bytes - before)
		t.records = append(t.records, records...)
	}
	return result
}
