// 失敗した復号の部分出力と、既存出力・リンクされた鍵への誤操作を防ぐ。
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSealedBackupCLIExclusiveOutput(t *testing.T) {
	root := t.TempDir()
	identity := filepath.Join(root, "identity")
	if err := run([]string{"generate", "--output", identity}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "input")
	os.WriteFile(input, []byte("private test evidence"), 0600)
	archive := filepath.Join(root, "sealed")
	public := filepath.Join(identity, "public.key")
	private := filepath.Join(identity, "private.key")
	if err := run([]string{"seal", "--key", public, "--input", input, "--output", archive}); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "opened")
	if err := run([]string{"open", "--key", private, "--input", archive, "--output", output}); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(input)
	opened, _ := os.ReadFile(output)
	if !bytes.Equal(original, opened) {
		t.Fatal("CLI round trip")
	}
	if err := run([]string{"open", "--key", private, "--input", archive, "--output", output}); err == nil {
		t.Fatal("existing output overwritten")
	}
	b, _ := os.ReadFile(archive)
	b[len(b)-1] ^= 1
	os.WriteFile(archive, b, 0600)
	failed := filepath.Join(root, "failed")
	if err := run([]string{"open", "--key", private, "--input", archive, "--output", failed}); err == nil {
		t.Fatal("tamper accepted")
	}
	if _, err := os.Lstat(failed); !os.IsNotExist(err) {
		t.Fatal("unauthenticated output retained")
	}
	link := filepath.Join(root, "link")
	os.Symlink(private, link)
	if err := run([]string{"open", "--key", link, "--input", archive, "--output", failed}); err == nil {
		t.Fatal("linked private key accepted")
	}
}
