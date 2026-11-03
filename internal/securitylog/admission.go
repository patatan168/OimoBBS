// 検出ログの背景保存を投稿優先のI/O枠へ接続し、表示・終了・滞留時には進行を確保する。
package securitylog

import (
	"context"
	"errors"
	"time"
)

// Admission は背景保存開始を調整する。pressureまたはwakeの通知後は優先条件を再評価する。
// 成功時のreleaseを一度呼び、取消時は枠を返さずctxのerrorを返すこと。
type Admission func(ctx context.Context, pressure func() bool, wake <-chan struct{}) (release func(), err error)

const admissionBacklog = 128
const admissionTimeout = time.Second

// pressure は表示・終了の保存要求か、固定長受付列が半分に達した状態を返す。
func (l *Log) pressure() bool { return l.urgent.Load() > 0 || len(l.queue) >= admissionBacklog }

// signalAdmission は主体や本文を渡さず、待機中writerに進行条件の変化だけを通知する。
func (l *Log) signalAdmission() {
	if l.admission == nil || !l.pressure() {
		return
	}
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// acquire は通常は投稿完了を待ち、最長1秒後には一つの背景保存枠の空きを待つ。
// 期限後も他の背景保存とは直列にし、検出件数の保存を無期限に延期しない。
func (l *Log) acquire() (func(), error) {
	if l.admission == nil {
		return func() {}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), admissionTimeout)
	defer cancel()
	release, err := l.admission(ctx, l.pressure, l.wake)
	if errors.Is(err, context.DeadlineExceeded) {
		return l.admission(context.Background(), func() bool { return true }, nil)
	}
	return release, err
}

// requireFlush は背景優先制御だけを打ち切る。返した解除は表示・終了の完了後に呼ぶ。
func (l *Log) requireFlush() func() {
	l.urgent.Add(1)
	l.signalAdmission()
	return func() { l.urgent.Add(-1) }
}
