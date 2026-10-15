// 案件照会の送信中も権限・案件状態・非必須原本期限を再検査する。
package bootstrap

import (
	"errors"
	"io"
	"net/http"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// evidenceQueryWriter は最大32KiBごとの送信直前に失効を検査する。失効後はHTTP応答を中断する。
type evidenceQueryWriter struct {
	http.ResponseWriter
	check func() error
}

func (w *evidenceQueryWriter) WriteHeader(status int) {
	if w.check() != nil {
		panic(http.ErrAbortHandler)
	}
	if checked, ok := w.ResponseWriter.(interface{ WriteHeaderChecked(int, func() error) error }); ok {
		if checked.WriteHeaderChecked(status, w.check) != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write は元writerへ小さな区切りで渡し、返されたbytesとerrorを維持する。
func (w *evidenceQueryWriter) Write(raw []byte) (int, error) {
	written := 0
	for len(raw) > 0 {
		if w.check() != nil {
			panic(http.ErrAbortHandler)
		}
		size := min(len(raw), 32<<10)
		var n int
		var e error
		if checked, ok := w.ResponseWriter.(interface {
			WriteChecked([]byte, func() error) (int, error)
		}); ok {
			n, e = checked.WriteChecked(raw[:size], w.check)
			if e != nil {
				panic(http.ErrAbortHandler)
			}
		} else {
			n, e = w.ResponseWriter.Write(raw[:size])
		}
		written += n
		if e != nil {
			return written, e
		}
		if n != size {
			return written, io.ErrShortWrite
		}
		raw = raw[size:]
	}
	return written, nil
}

// guardEvidenceQuery は原本の最短期限を固定し、APIとHTML双方の送信を同じ失効検査へ接続する。
func (h *adminHandler) guardEvidenceQuery(w http.ResponseWriter, s adminauth.Session, c disclosure.Case, data any, liveRejected ...bool) http.ResponseWriter {
	rejected := len(liveRejected) > 0 && liveRejected[0]
	httpOnly := len(liveRejected) > 1 && liveRejected[1]
	ordinaryHTTP := httpOnly && (c.HTTP == nil || !c.HTTP.Unbound)
	cutoff := c.Until
	if (rejected || httpOnly) && c.State == "draft" {
		cutoff = min(cutoff, c.Created+domain.Time(7*24*time.Hour))
	}
	if rows, ok := data.([]map[string]any); ok && (c.HTTP == nil || rejected || httpOnly) {
		for _, row := range rows {
			if ordinaryHTTP || rejected && c.Rejected == nil {
				if until, ok := row["retention_until_ns"].(domain.Time); ok {
					cutoff = min(cutoff, until)
				}
			}
			if logs, ok := row["optional_http"].([]evidence.OptionalEvidence); ok {
				for _, log := range logs {
					cutoff = min(cutoff, log.Record.Until)
				}
			}
		}
	}
	return &evidenceQueryWriter{ResponseWriter: w, check: func() error {
		h.repo.mu.Lock()
		defer h.repo.mu.Unlock()
		if e := h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true); e != nil {
			return e
		}
		current, e := h.repo.evidenceCases.Get(c.ID)
		if e != nil {
			return e
		}
		current, e = h.repo.evidenceCases.AuthorizeState(c.ID, current.ETag(), time.Now())
		if e != nil {
			return e
		}
		now := domain.Time(time.Now().UnixNano())
		if current.State != "active" && current.State != "partial" && !((rejected || httpOnly) && current.State == "draft") || now >= current.Until || now >= cutoff || now < c.Created {
			return disclosure.ErrExpired
		}
		if current.Scope.Board != c.Scope.Board {
			return errors.New("evidence query scope changed")
		}
		return nil
	}}
}
