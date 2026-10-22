// 管理応答の先頭ヘッダまでの時間を、ブラウザのServer Timingへ渡す。
package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type adminTimingKey struct{}

type adminResponseTiming struct {
	http.ResponseWriter
	start                 time.Time
	reading, session      time.Duration
	written               bool
	auditMeasured         bool
	auditQuery, auditView time.Duration
}

// withAdminTiming は要求枠に入った後の接続元判定・認証・描画の待機を測る。
// 本文や操作者情報は収集せず、実際にヘッダを送る直前の経過時間だけを公開する。
// ヘッダへの追加は送信予約より前に行い、計測値の通信量も帯域予算へ含める。
func withAdminTiming(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timing := &adminResponseTiming{ResponseWriter: w, start: time.Now()}
		ctx := context.WithValue(r.Context(), adminTimingKey{}, timing)
		next.ServeHTTP(timing, r.WithContext(ctx))
	})
}

func (w *adminResponseTiming) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *adminResponseTiming) prepare() {
	if !w.written {
		w.Header().Set("Server-Timing", fmt.Sprintf("admin;dur=%.3f, admin_reading;dur=%.3f, admin_session;dur=%.3f", float64(time.Since(w.start))/float64(time.Millisecond), float64(w.reading)/float64(time.Millisecond), float64(w.session)/float64(time.Millisecond)))
		if w.auditMeasured {
			w.Header().Set("Server-Timing", w.Header().Get("Server-Timing")+fmt.Sprintf(", admin_audit_query;dur=%.3f, admin_audit_view;dur=%.3f", float64(w.auditQuery)/float64(time.Millisecond), float64(w.auditView)/float64(time.Millisecond)))
		}
	}
}

func (w *adminResponseTiming) WriteHeader(status int) {
	if status >= 200 {
		w.prepare()
		w.written = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *adminResponseTiming) Write(body []byte) (int, error) {
	return w.WriteChecked(body, nil)
}

// WriteHeaderChecked は送信予約後の失効検査を維持したまま計測ヘッダを追加する。
func (w *adminResponseTiming) WriteHeaderChecked(status int, check func() error) error {
	w.prepare()
	if checked, ok := w.ResponseWriter.(interface{ WriteHeaderChecked(int, func() error) error }); ok {
		err := checked.WriteHeaderChecked(status, check)
		w.written = w.written || err == nil
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	w.WriteHeader(status)
	return nil
}

// WriteChecked は送信片ごとの権限・期限の再検査を下流の帯域制御へ渡す。
func (w *adminResponseTiming) WriteChecked(body []byte, check func() error) (int, error) {
	w.prepare()
	var n int
	var err error
	if checked, ok := w.ResponseWriter.(interface {
		WriteChecked([]byte, func() error) (int, error)
	}); ok {
		n, err = checked.WriteChecked(body, check)
	} else {
		if check != nil {
			if err = check(); err != nil {
				return 0, err
			}
		}
		n, err = w.ResponseWriter.Write(body)
	}
	w.written = w.written || err == nil
	return n, err
}
