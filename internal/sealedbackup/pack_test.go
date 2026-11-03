// Goによるtar作成と暗号化の境界を、復号した実tarと照合する。
package sealedbackup

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackGoArchiveAndVerification(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	name := "backup-" + strings.Repeat("a", 32)
	private, public, e := GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	for _, dir := range []string{"copies/" + name, "keys/" + name, "pairs", "encryption"} {
		if e := os.MkdirAll(filepath.Join(root, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	os.WriteFile(filepath.Join(root, "encryption/public.key"), public, 0600)
	want := map[string]string{"copies/" + name + "/state.json": `{"state":1}`, "keys/" + name + "/key.json": `{"key":1}`, "pairs/" + name + ".json": `{"pair":1}`}
	for p, v := range want {
		os.WriteFile(filepath.Join(root, p), []byte(v), 0600)
	}
	verified := false
	runner := func(_ context.Context, cmd string, args []string, _ io.Reader, out, diag io.Writer) error {
		if cmd != "oimobbs" || args[0] != "backup" || args[1] != "verify-with-keys" {
			t.Fatal(cmd, args)
		}
		verified = true
		return nil
	}
	var encrypted bytes.Buffer
	if e := Pack(context.Background(), root, name, &encrypted, runner); e != nil {
		t.Fatal(e)
	}
	if !verified {
		t.Fatal("verification skipped")
	}
	var opened bytes.Buffer
	if e := Open(&opened, &encrypted, private); e != nil {
		t.Fatal(e)
	}
	r := tar.NewReader(&opened)
	seen := 0
	for {
		header, e := r.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		raw, e := io.ReadAll(r)
		if e != nil || string(raw) != want[header.Name] {
			t.Fatal(header.Name, string(raw), e)
		}
		seen++
	}
	if seen != len(want) {
		t.Fatal(seen)
	}
	encrypted.Reset()
	failure := errors.New("invalid signed backup")
	if e := Pack(context.Background(), root, name, &encrypted, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error { return failure }); !errors.Is(e, failure) || encrypted.Len() != 0 {
		t.Fatal("unverified input encrypted", e)
	}
	os.Symlink(filepath.Join(root, "pairs", name+".json"), filepath.Join(root, "copies", name, "link"))
	if e := Pack(context.Background(), root, name, io.Discard, runner); e == nil {
		t.Fatal("symlink archived")
	}
}
