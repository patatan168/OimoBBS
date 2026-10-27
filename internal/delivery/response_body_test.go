// 確定応答の一括予約、公開失効、通信課金、短い書込みと枠回収を検査する。
package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

type responseBodyWriter struct {
	*httptest.ResponseRecorder
	sizes []int
	short bool
}

func (w *responseBodyWriter) Write(body []byte) (int, error) {
	w.sizes = append(w.sizes, len(body))
	if w.short {
		return len(body) - 1, nil
	}
	return w.ResponseRecorder.Write(body)
}

func TestCompleteResponseAccountingAndBounds(t *testing.T) {
	for _, size := range []int{1, 1000, Chunk, 3*Chunk + 17} {
		s, err := New(MaxBudgetBits)
		if err != nil {
			t.Fatal(err)
		}
		out := &responseBodyWriter{ResponseRecorder: httptest.NewRecorder()}
		w := &Response{ResponseWriter: out, scheduler: s, ip: netip.MustParseAddr("192.0.2.1"), ctx: t.Context()}
		w.Header().Set("Content-Type", "text/plain")
		header := w.headerBytes(206)
		body := bytes.Repeat([]byte("x"), size)
		n, err := w.WriteResponse(206, body)
		if n != size || err != nil || out.Code != 206 || !bytes.Equal(out.Body.Bytes(), body) {
			t.Fatal("incomplete response", n, err)
		}
		var want uint64
		for i, chunk := range out.sizes {
			if i == 0 {
				chunk += header
			}
			if chunk > Chunk {
				t.Fatal("oversized unchecked send")
			}
			want += uint64(estimatedWireBytes(chunk))
		}
		if s.Status().Reserved != want {
			t.Fatal("wire accounting changed", s.Status(), want)
		}
		if q, n, a := s.Stats(); q != 0 || n != 0 || a != 0 {
			t.Fatal("send slot retained", q, n, a)
		}
		s.Close()
	}
}

func TestCompleteResponseRevocationAndShortWrite(t *testing.T) {
	for _, mode := range []string{"before-header", "after-header", "after-body", "short"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := New(MaxBudgetBits)
			defer s.Close()
			out := &responseBodyWriter{ResponseRecorder: httptest.NewRecorder(), short: mode == "short"}
			w := &Response{ResponseWriter: out, scheduler: s, ip: netip.MustParseAddr("192.0.2.1"), ctx: t.Context()}
			gone := errors.New("revoked")
			calls := 0
			check := func() error {
				calls++
				if mode == "before-header" || mode == "after-header" && calls > 1 || mode == "after-body" && calls > 2 {
					return gone
				}
				return nil
			}
			n, err := w.WriteResponseChecked(200, bytes.Repeat([]byte("secret"), Chunk), check)
			want := gone
			if mode == "short" {
				want = io.ErrShortWrite
			}
			if !errors.Is(err, want) || n >= Chunk {
				t.Fatal("revocation/fault ignored", n, err)
			}
			if (mode == "before-header" || mode == "after-header") && len(out.sizes) != 0 {
				t.Fatal("revoked body sent")
			}
			if mode == "before-header" && w.started {
				t.Fatal("revoked header sent")
			}
			if _, _, active := s.Stats(); active != 0 {
				t.Fatal("failed write retained permit")
			}
		})
	}
}

func TestImmediateReservationKeepsLimits(t *testing.T) {
	s := &Scheduler{subjects: make(map[netip.Addr]*subject), rate: MaxBudgetBits,
		tokens: burstBytes(MaxBudgetBits) * 8 * uint64(time.Second), last: time.Now(), wake: make(chan struct{}, 1), stop: make(chan struct{})}
	ip := netip.MustParseAddr("192.0.2.1")
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	p, err := s.reserveHTTP(ctx, ip, Chunk)
	if err != nil {
		t.Fatal("available capacity waited for dispatcher", err)
	}
	if s.Status().Reserved != uint64(estimatedWireBytes(Chunk)) {
		t.Fatal("immediate reservation bypassed charge")
	}
	p.Release()
	if q, n, a := s.Stats(); q != 0 || n != 0 || a != 0 {
		t.Fatal("immediate reservation retained state", q, n, a)
	}
}

func TestCompleteResponseHTTPBudgetEnvelope(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		s, _ := New(100_000_000)
		body := bytes.Repeat([]byte("x"), 2<<20)
		server := httptest.NewUnstartedServer(s.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.(interface {
				WriteResponse(int, []byte) (int, error)
			}).WriteResponse(200, body)
		})))
		server.EnableHTTP2 = http2
		server.StartTLS()
		started := time.Now()
		response, err := server.Client().Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(response.Body)
		response.Body.Close()
		elapsed := time.Since(started)
		if err != nil || !bytes.Equal(got, body) || (response.ProtoMajor == 2) != http2 {
			t.Fatal("truncated HTTP body", err, response.Proto)
		}
		limit := uint64(elapsed)*100_000_000/(8*uint64(time.Second)) + burstBytes(100_000_000)
		if reserved := s.Status().Reserved; reserved > limit || reserved < uint64(len(body)) {
			t.Fatal("reservation envelope bypassed", reserved, limit)
		}
		server.Close()
		s.Close()
	}
}

func TestReleaseImmediatelyDrainsAvailableSlot(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	r := &request{size: 1000, ready: make(chan *Permit, 1)}
	s := &Scheduler{subjects: map[netip.Addr]*subject{ip: {active: 4, queue: []*request{r}}},
		order: []netip.Addr{ip}, queued: 1, rate: MaxBudgetBits,
		tokens: burstBytes(MaxBudgetBits) * 8 * uint64(time.Second), last: time.Now(), wake: make(chan struct{}, 1)}
	p := &Permit{scheduler: s, ip: ip}
	p.Release()
	select {
	case granted := <-r.ready:
		if s.Status().Reserved != 1000 || s.Status().Active != 4 || s.Status().Queued != 0 {
			t.Fatal("release bypassed accounting or active limit", s.Status())
		}
		granted.Release()
	default:
		t.Fatal("available slot waited for dispatcher")
	}
	p.Release()
	if s.Status().Active != 3 || len(s.wake) != 0 {
		t.Fatal("duplicate release or idle wake", s.Status())
	}
}
