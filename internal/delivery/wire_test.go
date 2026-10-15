// 推定通信量の課金と100Mbpsでの短時間送信上限を固定時刻で検査する。
package delivery

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestHTTPWireEstimateThroughput(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "TLS-HTTP1", true: "TLS-HTTP2"}[http2], func(t *testing.T) {
			s, err := New(100_000_000)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			body := bytes.Repeat([]byte("x"), 8<<20)
			server := httptest.NewUnstartedServer(s.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(body)
			})))
			server.EnableHTTP2 = http2
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			client.Timeout = 5 * time.Second
			started := time.Now()
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			elapsed := time.Since(started)
			if err != nil || !bytes.Equal(got, body) || (response.ProtoMajor == 2) != http2 {
				t.Fatal("incomplete body or wrong protocol", len(got), response.Proto, err)
			}
			reserved := s.Status().Reserved
			if reserved < uint64(len(body)/Chunk*estimatedWireBytes(Chunk)) {
				t.Fatal("wire accounting bypassed", reserved)
			}
			limit := uint64(elapsed)*100_000_000/(8*uint64(time.Second)) + burstBytes(100_000_000)
			if reserved > limit {
				t.Fatal("HTTP exceeded reservation envelope", reserved, limit)
			}
			t.Logf("loopback only: body %.2f Mbps, estimated %.2f Mbps, duration %s", float64(len(body))*8/elapsed.Seconds()/1e6, float64(reserved)*8/elapsed.Seconds()/1e6, elapsed)
		})
	}
}

func TestEmptyAndErrorResponsesChargeWireEstimate(t *testing.T) {
	for _, status := range []int{200, 302, 304, 503} {
		s, err := New(100_000_000)
		if err != nil {
			t.Fatal(err)
		}
		w := &Response{ResponseWriter: httptest.NewRecorder(), scheduler: s, ip: netip.MustParseAddr("192.0.2.1"), ctx: context.Background()}
		w.WriteHeader(status)
		if got, want := s.Status().Reserved, uint64(estimatedWireBytes(w.headerBytes(status))); got != want {
			t.Fatalf("status %d: got %d, want %d", status, got, want)
		}
		s.Close()
	}
}

func TestFailureResponseChargesWireEstimate(t *testing.T) {
	s, err := New(100_000_000)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	recorder := httptest.NewRecorder()
	w := &Response{ResponseWriter: recorder, scheduler: s, ip: netip.MustParseAddr("192.0.2.1"), ctx: context.Background()}
	w.fail(context.DeadlineExceeded)
	if recorder.Code != http.StatusServiceUnavailable || !w.failureResponse {
		t.Fatal("missing failure response")
	}
	if got, want := s.Status().Reserved, uint64(estimatedWireBytes(w.headerBytes(503)+recorder.Body.Len())); got != want {
		t.Fatalf("failure response bypassed accounting: got %d, want %d", got, want)
	}
}

func TestWireReservationIncludesPacketOverhead(t *testing.T) {
	for _, tc := range []struct{ size, want int }{{1, 177}, {1136, 1312}, {1137, 1425}, {1200, 1488}, {1201, 1489}, {Chunk, 18016}} {
		if got := estimatedWireBytes(tc.size); got != tc.want {
			t.Fatalf("size=%d: got %d, want %d", tc.size, got, tc.want)
		}
	}
	s, err := New(100_000_000)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w := &Response{ResponseWriter: httptest.NewRecorder(), scheduler: s, ip: netip.MustParseAddr("2001:db8::1"), ctx: context.Background()}
	if _, err := w.Write(make([]byte, Chunk)); err != nil {
		t.Fatal(err)
	}
	header := w.headerBytes(200)
	if got, want := s.Status().Reserved, uint64(estimatedWireBytes(header)+estimatedWireBytes(Chunk)); got != want {
		t.Fatalf("HTTP did not charge wire estimate: got %d, want %d", got, want)
	}
}

func TestHundredMbpsEstimatedEnvelope(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	s := &Scheduler{subjects: map[netip.Addr]*subject{}, rate: 100_000_000, last: now, tokens: burstBytes(100_000_000) * 8 * uint64(time.Second), wake: make(chan struct{}, 1)}
	// 各時点で32件を投入し、1ms刻みの固定時刻で1秒間飽和させる。
	for tick := 0; tick <= 1000; tick++ {
		sub := s.subjects[ip]
		if sub == nil {
			sub = &subject{}
			s.subjects[ip] = sub
			s.order = []netip.Addr{ip}
		}
		for len(sub.queue) < 32 {
			sub.queue = append(sub.queue, &request{size: estimatedWireBytes(Chunk), ready: make(chan *Permit, 1)})
			s.queued++
		}
		pending := append([]*request(nil), sub.queue...)
		s.pumpLocked(now.Add(time.Duration(tick) * time.Millisecond))
		for _, r := range pending {
			if r.permit != nil {
				r.permit.Release()
			}
		}
		limit := uint64(32768 + tick*12500)
		if s.reservedBytes > limit {
			t.Fatalf("tick=%d: reserved %d > envelope %d", tick, s.reservedBytes, limit)
		}
	}
	if s.reservedBytes < 12_000_000 {
		t.Fatal("saturated scheduler did not progress", s.reservedBytes)
	}
}
