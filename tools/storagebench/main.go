// 合成DAT・署名HTTP記録・snapshot相当の同じ入力で、保存codecの速度とサイズを比較する。
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstddecode"
	"oimobbs/internal/zstdencode"
	"os"
	"runtime"
	"time"
)

type sample struct {
	name   string
	chunks [][]byte
}
type result struct {
	Sample    string `json:"sample"`
	Codec     string `json:"codec"`
	Trial     int    `json:"trial"`
	Raw       int    `json:"raw_bytes"`
	Stored    int    `json:"stored_bytes"`
	EncodeNS  int64  `json:"encode_ns"`
	DecodeNS  int64  `json:"decode_ns"`
	Allocated uint64 `json:"encode_allocated_bytes"`
}

// id は稼働データを使わず、毎回同じ分布のIDを作る。
func id(n int) domain.ID {
	h := sha256.Sum256([]byte(fmt.Sprint("storage-bench-", n)))
	var v domain.ID
	copy(v[:], h[:16])
	return v
}

// corpus は独立した署名・hash・IDを持つHTTP記録と、圧縮特性の異なるDATを生成する。
func corpus() []sample {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	var frames [][]byte
	var previous domain.Hash
	for n := 1; n <= 128; n++ {
		now := domain.Time(1792195200000000000 + int64(n)*1000000)
		r := evidence.OptionalRecord{Schema: "optional-http-v1", ID: id(n), Site: id(1000), Boot: id(1001), Connection: id(2000 + n%40), Request: id(3000 + n), Received: now, Finished: now + 1000000, Until: now + domain.Time(evidence.OptionalRetention), Peer: evidence.Endpoint{IP: fmt.Sprintf("192.0.2.%d", n%200+1), Port: 12345}, Local: evidence.Endpoint{IP: "192.0.2.254", Port: 443}, Method: "GET", Route: "dat", Kind: "access", Outcome: "served", Status: 200, Bytes: 12345, UAStatus: "captured", FinishStage: "handler_return", HTTPVersion: "HTTP/1.1"}
		must(r.Validate())
		payload, err := json.Marshal(evidence.OptionalPayload{Owner: evidence.OptionalOwner(r.Site), Day: 20261017, Seq: domain.U64(n), Record: r})
		must(err)
		event, err := evidence.Seal(evidence.Source{Owner: evidence.OptionalOwner(r.Site), Subkey: 20261017, Seq: uint64(n)}, r.ID, "receipt", payload, previous, 10, key)
		must(err)
		previous = event.EventSHA
		value, err := json.Marshal(event)
		must(err)
		op := store.ControlOperation{Schema: 1, Seq: domain.U64(n), ExpectedSeq: domain.U64(n - 1), Committed: r.Finished, Actor: domain.Actor{Kind: "system", Reason: "evidence"}, Mutations: []store.Mutation{{Collection: "receipt", Key: r.ID.String(), Value: value}}, Result: store.ControlResult{Code: "saved", Targets: []string{}}}
		raw, err := json.Marshal(op)
		must(err)
		frame, err := store.EncodeFrame(store.Frame{FirstSeq: uint64(n), Records: []store.Record{{ID: r.ID, JSON: raw}}})
		must(err)
		frames = append(frames, frame)
	}
	all := bytes.Join(frames, nil)
	items := []sample{{"http_wal_individual", frames}, {"http_wal_batch_64", [][]byte{bytes.Join(frames[:64], nil), bytes.Join(frames[64:], nil)}}, {"signed_log_snapshot", [][]byte{all}}}
	for _, kind := range []string{"text", "mixed", "entropy"} {
		raw := testutil.DATFixture(kind)
		var chunks [][]byte
		for len(raw) > 0 {
			n := min(len(raw), 64<<10)
			chunks = append(chunks, bytes.Clone(raw[:n]))
			raw = raw[n:]
		}
		items = append(items, sample{"dat_" + kind, chunks})
	}
	return items
}

// codec はworkerを再利用し、標準gzipと現行保存Zstandardを同じ入力へ適用する。
func codec(name string) (func([]byte) []byte, func([]byte, int) []byte) {
	var encoder zstdencode.Encoder
	var buffer bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buffer, 6)
	must(err)
	encode := func(raw []byte) []byte {
		switch name {
		case "raw":
			return bytes.Clone(raw)
		case "gzip6":
			buffer.Reset()
			writer.Reset(&buffer)
			_, err := writer.Write(raw)
			must(err)
			must(writer.Close())
			return bytes.Clone(buffer.Bytes())
		case "zstd_fast":
			return encoder.Encode(raw)
		default:
			level := uint8(1)
			if name == "archive6" {
				level = 6
			}
			if name == "archive9" {
				level = 9
			}
			chunk, err := store.EncodePackChunk(raw, level)
			must(err)
			return chunk.Stored
		}
	}
	decode := func(raw []byte, n int) []byte {
		if name == "raw" {
			return bytes.Clone(raw)
		}
		if name == "gzip6" {
			reader, err := gzip.NewReader(bytes.NewReader(raw))
			must(err)
			out, err := io.ReadAll(reader)
			must(err)
			must(reader.Close())
			return out
		}
		out, err := zstddecode.Decode(raw, n)
		must(err)
		return out
	}
	return encode, decode
}

// measure は全chunkの復号一致を先に検査し、初期確保と検証を計時から分離する。
func measure(s sample, name string, trial, count int) result {
	encode, decode := codec(name)
	r := result{Sample: s.name, Codec: name, Trial: trial}
	var encoded [][]byte
	for _, raw := range s.chunks {
		stored := encode(raw)
		if !bytes.Equal(decode(stored, len(raw)), raw) {
			panic("roundtrip mismatch")
		}
		if name != "raw" && name != "gzip6" {
			independent, err := testutil.DecodeZstd(stored)
			must(err)
			if !bytes.Equal(independent, raw) {
				panic("independent decoder mismatch")
			}
		}
		r.Raw += len(raw)
		r.Stored += len(stored)
		encoded = append(encoded, stored)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	for range count {
		for _, raw := range s.chunks {
			_ = encode(raw)
		}
	}
	r.EncodeNS = time.Since(start).Nanoseconds() / int64(count)
	runtime.ReadMemStats(&after)
	r.Allocated = (after.TotalAlloc - before.TotalAlloc) / uint64(count)
	start = time.Now()
	for range count {
		for i, stored := range encoded {
			_ = decode(stored, len(s.chunks[i]))
		}
	}
	r.DecodeNS = time.Since(start).Nanoseconds() / int64(count)
	return r
}

func main() {
	output := flag.String("output", "", "新規JSON出力")
	count := flag.Int("count", 10, "反復数")
	flag.Parse()
	if *output == "" || *count < 1 {
		panic("invalid arguments")
	}
	var rows []result
	for trial := 1; trial <= 3; trial++ {
		for _, s := range corpus() {
			for _, name := range []string{"raw", "gzip6", "zstd_fast", "archive1", "archive6", "archive9"} {
				rows = append(rows, measure(s, name, trial, *count))
			}
		}
	}
	raw, err := json.MarshalIndent(rows, "", "  ")
	must(err)
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	_, err = file.Write(raw)
	must(err)
	must(file.Close())
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
