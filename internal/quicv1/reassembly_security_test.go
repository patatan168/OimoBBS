// 空区間と再送を組み合わせ、受信再構成の進捗と処理枠を検査する。
package quicv1

import "testing"

func TestQUICEmptySegmentsDoNotBlockReassembly(t *testing.T) {
	r := reassembly{limit: 4096}
	if newly, err := r.insert(2, nil, false); err != nil || newly != 2 {
		t.Fatalf("empty segment retained: newly=%d parts=%d err=%v", newly, len(r.parts), err)
	}
	for offset, data := range []string{"ab", "cd", "ef"} {
		if _, err := r.insert(uint64(offset*2), []byte(data), offset == 2); err != nil {
			t.Fatal(err)
		}
	}
	var got []byte
	for block := r.pop(); block != nil; block = r.pop() {
		got = append(got, block...)
	}
	if string(got) != "abcdef" || len(r.parts) != 0 || r.next != 6 {
		t.Fatalf("reassembly stalled: %q next=%d parts=%d", got, r.next, len(r.parts))
	}
	if _, err := r.insert(7, nil, false); err == nil {
		t.Fatal("empty segment beyond final size accepted")
	}
}

// FuzzReassemblySequence は同じ受信状態へ断片・空区間・再送を重ねて資源枠を検査する。
func FuzzReassemblySequence(f *testing.F) {
	f.Add([]byte{2, 0, 0, 0, 0, 2, 0, 'a', 'b', 2, 2, 1, 'c', 'd'})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := reassembly{limit: 4096}
		for steps := 0; len(data) >= 3 && steps < 512; steps++ {
			offset, size, fin := uint64(data[0]), min(int(data[1]), len(data)-3), data[2]&1 != 0
			_, err := r.insert(offset, data[3:3+size], fin)
			if err != nil {
				break
			}
			if r.buffered > r.limit || len(r.parts) > 256 {
				t.Fatal("reassembly budget exceeded")
			}
			for block := r.pop(); block != nil; block = r.pop() {
			}
			data = data[3+size:]
		}
	})
}
