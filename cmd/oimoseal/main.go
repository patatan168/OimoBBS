// Command oimoseal は秘密鍵をアプリへ渡さず、退避tar等を暗号化・復号する。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"oimobbs/internal/sealedbackup"
	"os"
	"path/filepath"
	"syscall"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: oimoseal generate --output <new-directory> | seal/open --key <file> --input <file> --output <new-file>")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	output := f.String("output", "", "新規出力path")
	input := f.String("input", "", "入力file")
	key := f.String("key", "", "公開鍵/秘密鍵file")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || *output == "" {
		return errors.New("new output required")
	}
	if args[0] == "generate" {
		if err := os.Mkdir(*output, 0700); err != nil {
			return err
		}
		private, public, err := sealedbackup.GenerateKey()
		if err != nil {
			return err
		}
		defer clear(private)
		for _, v := range []struct {
			name string
			raw  []byte
		}{{"private.key", private}, {"public.key", public}} {
			if err := newFile(filepath.Join(*output, v.name), func(w io.Writer) error {
				n, e := w.Write(v.raw)
				if e == nil && n != len(v.raw) {
					return io.ErrShortWrite
				}
				return e
			}); err != nil {
				return err
			}
		}
		return nil
	}
	if (args[0] != "seal" && args[0] != "open") || *input == "" || *key == "" {
		return errors.New("seal/open require key and input")
	}
	info, err := os.Lstat(*key)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 32 {
		return errors.New("key requires owned regular 0600 32-byte file")
	}
	k, err := os.ReadFile(*key)
	if err != nil {
		return err
	}
	defer clear(k)
	src := os.Stdin
	if *input != "-" {
		src, err = os.Open(*input)
		if err != nil {
			return err
		}
		defer src.Close()
	}
	transform := func(w io.Writer) error {
		if args[0] == "seal" {
			return sealedbackup.Seal(w, src, k)
		}
		return sealedbackup.Open(w, src, k)
	}
	if *output == "-" {
		if args[0] != "seal" {
			return errors.New("decryption requires an exclusive output file")
		}
		return transform(os.Stdout)
	}
	return newFile(*output, transform)
}

// newFile は所有者限定で排他的に作成し、失敗時の部分出力を削除する。
func newFile(path string, write func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = write(f)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		os.Remove(path)
	}
	return err
}
