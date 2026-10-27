// 並列変換の境界・エラーの優先順位・worker枠・結果の専有を検査する。
package textcodec

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestParallelConversionMatchesPrevious は分割境界・拡大出力・拒否条件を旧実装と照合する。
func TestParallelConversionMatchesPrevious(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(old)
	fixtures := []string{
		strings.Repeat("name<>日本語、ｱｲｳとABC123\n", 10000),
		strings.Repeat("日本語\n", 33000),
		strings.Repeat("ｱｲｳｴｵ", 20000),
		strings.Repeat("😀𠮷", 30000),
		strings.Repeat("😀", 18000) + strings.Repeat("日本語", 30000),
		strings.Repeat("日", 131072),
		strings.Repeat("ASCII", 60000),
		strings.Repeat("a", parallelMinimum-1) + "日本語😀\xff",
		"😀" + strings.Repeat("日本語", 30000) + "\xff",
		strings.Repeat("\x80", parallelMinimum),
	}
	for _, cpus := range []int{1, 2, 4} {
		runtime.GOMAXPROCS(cpus)
		for _, s := range fixtures {
			for _, allow := range []bool{false, true} {
				want, wantErr := referenceEncode(s, allow)
				got, err := Encode(s, allow)
				if !bytes.Equal(got, want) || !sameError(err, wantErr) {
					t.Fatalf("encode P=%d allow=%v: %v / %v", cpus, allow, err, wantErr)
				}
				if wantErr == nil {
					checkLargeDecode(t, got)
				}
			}
		}
	}
	if activeConversions.Load() != 0 || codecHelpers.Load() != 0 {
		t.Fatal("worker reservation leaked")
	}
}

func checkLargeDecode(t *testing.T, b []byte) {
	t.Helper()
	want, wantErr := referenceDecode(b)
	got, err := Decode(b)
	if got != want || !sameError(err, wantErr) {
		t.Fatalf("decode differs: %v / %v", err, wantErr)
	}
}

// TestDecodeBoundariesAndErrors はleadでもtrailでもあるbyteと不正byteの位置を検査する。
func TestDecodeBoundariesAndErrors(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(old)
	b := bytes.Repeat([]byte{0x82, 0xa0, 0x93, 0xfa, 'A', 0xa1}, 50000)
	for jobs := 2; jobs <= codecMaxWorkers; jobs++ {
		bounds, ok := decodeBounds(b, jobs)
		if !ok {
			t.Fatal("normal input did not split")
		}
		for i := 0; i < jobs; i++ {
			if !Valid(b[bounds[i]:bounds[i+1]]) {
				t.Fatalf("invalid chunk %d/%d", i, jobs)
			}
		}
		for cut := 1; cut < jobs; cut++ {
			for delta := -2; delta <= 2; delta++ {
				at := len(b)*cut/jobs + delta
				for _, value := range []byte{0xff, 0x81, 0x7f, 0x00} {
					bad := bytes.Clone(b)
					bad[at] = value
					checkLargeDecode(t, bad)
				}
			}
		}
	}
	checkLargeDecode(t, append(bytes.Clone(b), 0x81))
	if _, ok := decodeBounds(bytes.Repeat([]byte{0x93, 0xfa}, 100000), 4); ok {
		t.Fatal("ambiguous long lead run must use serial fallback")
	}
}

// TestConcurrentConversions は共有枠の飽和・回収と、返却結果の専有を検査する。
func TestConcurrentConversions(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(old)
	s := strings.Repeat("日本語とABC123、😀\n", 16000)
	want, _ := referenceEncode(s, true)
	decoded, _ := referenceDecode(want)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 8 {
				out, err := Encode(s, true)
				if err != nil || !bytes.Equal(out, want) {
					t.Error("concurrent encode differs", err)
					return
				}
				got, err := Decode(out)
				clear(out)
				if err != nil || got != decoded {
					t.Error("decode differs or aliases input", err)
					return
				}
			}
		})
	}
	wg.Wait()
	if activeConversions.Load() != 0 || codecHelpers.Load() != 0 {
		t.Fatal("worker reservation leaked")
	}
	activeConversions.Add(1)
	helpers := reserveCodecHelpers(len(s))
	if helpers != 3 {
		t.Fatalf("got %d helpers, want 3", helpers)
	}
	started, release, done := make(chan struct{}, 4), make(chan struct{}), make(chan struct{})
	go func() {
		runCodecChunks(helpers, func(int) { started <- struct{}{}; <-release })
		close(done)
	}()
	for range 4 {
		<-started
	}
	if extra := reserveCodecHelpers(len(s)); extra != 0 {
		t.Errorf("reserved %d extra helpers at capacity", extra)
		codecHelpers.Add(-int32(extra))
	}
	out, err := Encode(s, true)
	if err != nil || !bytes.Equal(out, want) {
		t.Error("serial fallback differs", err)
	}
	close(release)
	<-done
	activeConversions.Add(-1)
	if codecHelpers.Load() != 0 {
		t.Fatal("helper slots not returned")
	}
}
