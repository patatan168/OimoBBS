// 提出ZIPを、案件台帳や秘密鍵を開かず外部の信頼済み公開鍵で検証する。
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/disclosure"
	"os"
)

func runEvidence(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || args[0] != "verify-export" {
		return errors.New("usage: evidence verify-export --input <zip> --public-key <base64-public-key>")
	}
	flags := flag.NewFlagSet("evidence verify-export", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	input := flags.String("input", "", "提出ZIP")
	public := flags.String("public-key", "", "別途信頼したEd25519公開鍵のbase64")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || *input == "" || *public == "" {
		return errors.New("input and public-key are required")
	}
	key, e := base64.StdEncoding.Strict().DecodeString(*public)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	f, e := os.Open(*input)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	m, e := disclosure.VerifyZIP(f, info.Size(), ed25519.PublicKey(key))
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(map[string]any{"verified": true, "export_id": m.ID, "case_id": m.Case, "count": m.Count, "columns": m.Columns, "retention_until_ns": m.Until})
}
