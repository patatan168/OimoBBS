// HTTP要求を伴わない制御streamの大量入力を、接続ごとの有限creditで止める。
package http3native

import (
	"io"
	"time"
)

const initialControlBudget = 64 << 10
const maximumControlBudget = 512 << 10

// grantControl は検証を通った要求にだけ最大field section一つ分を補充する。
// 空stream・不正headerでは補充せず、未使用creditも無制限に貯めない。
func (c *connection) grantControl() {
	for {
		before := c.controlBudget.Load()
		after := min(int64(maximumControlBudget), before+(16<<10))
		if c.controlBudget.CompareAndSwap(before, after) {
			return
		}
	}
}

type controlReader struct {
	conn   *connection
	reader io.Reader
}

func (r *controlReader) Read(dst []byte) (int, error) {
	credit := r.conn.controlBudget.Load()
	if credit <= 0 {
		return 0, &connectionError{errExcessive}
	}
	n, err := r.reader.Read(dst[:min(len(dst), int(credit))])
	if n > 0 && r.conn.controlBudget.Add(-int64(n)) < 0 {
		return 0, &connectionError{errExcessive}
	}
	return n, err
}

func (r *controlReader) SetReadDeadline(t time.Time) error {
	if stream, ok := r.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return stream.SetReadDeadline(t)
	}
	return nil
}
