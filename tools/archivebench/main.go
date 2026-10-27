// ダミーDATと保存Post形式から作る有界blockで、gzipと独自保存Zstandardを比較する。
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/testutil"
	"oimobbs/internal/textcodec"
	"oimobbs/internal/zstddecode"
	"oimobbs/internal/zstdencode"
	"os"
	"runtime"
	"strings"
	"time"
)

// blocks は設計fixtureのPost外枠を使い、DAT64KiB/展開512KiBの製品境界で分割する。
func blocks(dat []byte) [][]byte {
	fixture, err := os.ReadFile("docs/design/fixtures/pack-zstd-layout.json")
	must(err)
	var file struct {
		Hex string `json:"pack_hex"`
	}
	must(json.Unmarshal(fixture, &file))
	packed, err := hex.DecodeString(file.Hex)
	must(err)
	snapshot, err := store.DecodePack(packed)
	must(err)
	template := snapshot.State.Posts[0]
	result := [][]byte{}
	raw := make([]byte, 16)
	copy(raw, "OIMOBLK1")
	offset, count := 0, 0
	finish := func() {
		binary.LittleEndian.PutUint32(raw[8:], uint32(count))
		result = append(result, raw)
		raw = make([]byte, 16)
		copy(raw, "OIMOBLK1")
		offset, count = 0, 0
	}
	for number, line := range bytes.SplitAfter(dat, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		decoded, err := textcodec.Decode(line)
		must(err)
		fields := strings.Split(strings.TrimSuffix(decoded, "\n"), "<>")
		if len(fields) != 5 {
			panic("invalid sample DAT")
		}
		post := template
		post.Number = uint32(number + 1)
		post.Name = fields[0]
		post.Body = fields[3]
		post.DATLength = uint32(len(line))
		post.Created += domain.Time(number * 1000000000)
		post.Identity.ID = fmt.Sprint(number)
		private := *template.Private
		private.SourceIP = fmt.Sprintf("127.%d.%d.%d", number/65536, (number/256)%256, number%256)
		private.RateKeys = append([]domain.RateKey(nil), private.RateKeys...)
		for i := range private.RateKeys {
			private.RateKeys[i].Subject = domain.Hash(sha256.Sum256([]byte(fmt.Sprintf("dummy-%d-%d", number, i))))
		}
		post.Private = &private
		encode := func() []byte {
			post.DATOffset = uint32(offset)
			payload, err := json.Marshal(post)
			must(err)
			entry := make([]byte, 16+len(payload)+len(line))
			binary.LittleEndian.PutUint64(entry, uint64(number+1))
			binary.LittleEndian.PutUint32(entry[8:], uint32(len(payload)))
			copy(entry[12:], payload)
			at := 12 + len(payload)
			binary.LittleEndian.PutUint32(entry[at:], uint32(len(line)))
			copy(entry[at+4:], line)
			return entry
		}
		entry := encode()
		if count > 0 && (offset+len(line) > 64<<10 || len(raw)+len(entry) > store.MaxPackRaw) {
			finish()
			entry = encode()
		}
		if len(raw)+len(entry) > store.MaxPackRaw {
			panic("sample record too large")
		}
		raw = append(raw, entry...)
		offset += len(line)
		count++
	}
	if count > 0 {
		finish()
	}
	return result
}

type result struct {
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Raw, Stored int
	Ns          int64  `json:"ns_per_thread"`
	Alloc       uint64 `json:"allocated_bytes_per_thread"`
}

// measure は同じblock列を反復し、独立復号を時間計測の外で検査する。
func measure(name, mode string, chunks [][]byte, count, depth, level, hash int) result {
	var encoder zstdencode.Encoder
	encode := func(raw []byte) []byte {
		if depth == -1 {
			chunk, err := store.EncodePackChunk(raw, uint8(level))
			must(err)
			return chunk.Stored
		}
		if depth > 0 {
			out, err := encoder.EncodeArchive(raw, zstdencode.ArchiveOptions{HashBytes: hash, AccuracyLog: uint(level)})
			must(err)
			return out
		}
		var buffer bytes.Buffer
		writer, err := gzip.NewWriterLevel(&buffer, level)
		must(err)
		_, err = writer.Write(raw)
		must(err)
		must(writer.Close())
		return buffer.Bytes()
	}
	rawBytes, storedBytes := 0, 0
	for _, raw := range chunks {
		out := encode(raw)
		var decoded []byte
		var err error
		if depth != 0 {
			decoded, err = testutil.DecodeZstd(out)
			must(err)
			ours, e := zstddecode.Decode(out, len(raw))
			must(e)
			if !bytes.Equal(ours, decoded) {
				panic("independent decode mismatch")
			}
		} else {
			reader, e := gzip.NewReader(bytes.NewReader(out))
			must(e)
			decoded, err = io.ReadAll(reader)
			must(reader.Close())
		}
		must(err)
		if !bytes.Equal(decoded, raw) {
			panic("roundtrip mismatch")
		}
		rawBytes += len(raw)
		storedBytes += len(out)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	for range count {
		n := 0
		for _, raw := range chunks {
			n += len(encode(raw))
		}
		if n != storedBytes {
			panic("unstable size")
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	return result{name, mode, rawBytes, storedBytes, int64(elapsed) / int64(count), (after.TotalAlloc - before.TotalAlloc) / uint64(count)}
}

// main は本文を出力せず、圧縮の測定集計だけを新規0600 JSONへ保存する。
func main() {
	dat := flag.String("dat", "", "隔離ダミーDAT")
	pack := flag.String("pack", "", "隔離実投稿のpack（全体の生成と検証を計測）")
	output := flag.String("output", "", "新規JSON出力")
	count := flag.Int("count", 20, "各条件の反復数")
	flag.Parse()
	if (*dat == "") == (*pack == "") || *output == "" || *count < 1 || *count > 1000 {
		panic("invalid arguments")
	}
	var results []result
	if *pack != "" {
		actual := readBounded(*pack, 64<<20)
		snapshot, err := store.DecodePack(actual)
		must(err)
		for range 3 {
			for _, level := range []int{0, 1, 6, 9} {
				results = append(results, measurePack(snapshot, level, *count))
			}
		}
		writeResults(*output, results)
		return
	}
	actual := readBounded(*dat, 1<<20)
	if len(actual) == 0 || len(actual) > 1<<20 {
		panic("invalid DAT size")
	}
	for _, sample := range []struct {
		name string
		dat  []byte
	}{{"actual", actual}, {"text", testutil.DATFixture("text")}, {"mixed", testutil.DATFixture("mixed")}} {
		chunks := blocks(sample.dat)
		for range 3 {
			for _, level := range []int{1, 6, 9} {
				results = append(results, measure(sample.name, fmt.Sprint("gzip-", level), chunks, *count, 0, level, 0))
			}
			for _, level := range []int{1, 6, 9} {
				results = append(results, measure(sample.name, fmt.Sprint("archive-", level), chunks, *count, -1, level, 0))
			}
			for _, hash := range []int{0, 4, 5, 6, 7} {
				for _, log := range []int{7, 8, 9} {
					results = append(results, measure(sample.name, fmt.Sprintf("zstd-hash-%d-log-%d", hash, log), chunks, *count, 1, log, hash))
				}
			}
		}
	}
	writeResults(*output, results)
}

// writeResults は本文を含まない集計を上書きせず保存する。
func writeResults(output string, results []result) {
	encoded, err := json.MarshalIndent(results, "", "  ")
	must(err)
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(err)
	_, err = file.Write(encoded)
	must(err)
	must(file.Close())
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}

// readBounded は入力を上限+1まで読み、超過を拒否する。
func readBounded(path string, limit int64) []byte {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	must(err)
	if len(raw) == 0 || int64(len(raw)) > limit {
		panic("input size exceeded")
	}
	return raw
}

// measurePack は同じ実投稿snapshotの全pack生成・自己検証を計測する。署名照合やdisk切替は含めない。
func measurePack(snapshot store.PackSnapshot, level, count int) result {
	encode := func() []byte {
		raw, err := store.EncodePack(snapshot, uint8(level))
		must(err)
		return raw
	}
	raw, err := store.EncodePack(snapshot, 0)
	must(err)
	out := encode()
	stored := len(out)
	decoded, err := store.DecodePack(out)
	must(err)
	normalized, err := store.EncodePack(decoded, 0)
	must(err)
	if !bytes.Equal(raw, normalized) {
		panic("snapshot changed")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	for range count {
		if len(encode()) != stored {
			panic("unstable size")
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	mode := fmt.Sprint("zstd-", level)
	if level == 0 {
		mode = "raw"
	}
	return result{"actual-full-pack", mode, len(raw), stored, int64(elapsed) / int64(count), (after.TotalAlloc - before.TotalAlloc) / uint64(count)}
}
