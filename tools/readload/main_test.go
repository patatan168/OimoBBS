// 負荷生成器が全要求を照合し、破損応答や外部URLを成功扱いしないことを検査する。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestReadLoadChecksEveryResponse(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("ETag", `"public"`)
		_, _ = w.Write([]byte("public"))
	}))
	defer server.Close()
	cert := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("public"))
	c := config{URL: server.URL, Certificate: cert, Status: 200, SHA256: hex.EncodeToString(digest[:]), BodyBytes: 6, Requests: 40, Workers: 4, ResponseHeaders: map[string]string{"ETag": `"public"`}}
	result, err := run(c)
	if err != nil || result.Errors != 0 || calls.Load() != 40 || result.BodyBytes != 240 {
		t.Fatal(result, err, calls.Load())
	}
	for _, field := range []string{"body", "status", "header", "length"} {
		bad := c
		switch field {
		case "body":
			bad.SHA256 = hex.EncodeToString(make([]byte, 32))
		case "status":
			bad.Status = 304
		case "header":
			bad.ResponseHeaders = map[string]string{"ETag": `"other"`}
		case "length":
			bad.BodyBytes = 3
		}
		result, err := run(bad)
		if err != nil || result.Errors != 40 {
			t.Fatal(field, result, err)
		}
	}
}

func TestReadLoadRejectsExternalTargets(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:443/", "https://example.com:443/", "https://user@127.0.0.1:443/", "https://127.0.0.1/"} {
		if _, err := run(config{URL: target, Requests: 1, Workers: 1}); err == nil {
			t.Fatal("external or ambiguous target accepted", target)
		}
	}
}
