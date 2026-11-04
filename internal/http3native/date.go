// HTTPのDate値を秒単位で共有し、応答ごとの日時書式化と文字列割り当てを避ける。
package http3native

import (
	"net/http"
	"sync/atomic"
	"time"
)

type datedValue struct {
	second int64
	value  string
}

var responseDate atomic.Pointer[datedValue]

// httpDate はtimerや常駐goroutineを作らず、時計の巻き戻りにも当該秒の値を返す。
func httpDate(now time.Time) string {
	second := now.Unix()
	if cached := responseDate.Load(); cached != nil && cached.second == second {
		return cached.value
	}
	current := &datedValue{second: second, value: now.UTC().Format(http.TimeFormat)}
	responseDate.Store(current)
	return current.value
}
