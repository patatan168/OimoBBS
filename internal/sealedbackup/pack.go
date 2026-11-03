// 検証済み本文・鍵束・ペア記録を、shellやtarコマンドを使わずGoで暗号化する。
package sealedbackup

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
)

// Pack は保存形式対応のoimobbsで検証後、公開鍵だけで固定三領域をtar暗号化する。
func Pack(ctx context.Context, root, name string, out io.Writer, runner CommandRunner) error {
	if !backupName.MatchString(name) || !filepath.IsAbs(root) {
		return errors.New("pack requires absolute source and backup name")
	}
	if runner == nil {
		runner = runCommand
	}
	diag := &cappedBuffer{limit: 2048}
	args := []string{"backup", "verify-with-keys", "--input", filepath.Join(root, "copies", name), "--keys", filepath.Join(root, "keys", name)}
	if e := runner(ctx, "oimobbs", args, nil, io.Discard, diag); e != nil {
		return commandFailure("backup verification", e, diag)
	}
	key, e := openPrivate(filepath.Join(root, "encryption", "public.key"))
	if e != nil {
		return e
	}
	public, e := io.ReadAll(io.LimitReader(key, 33))
	e = errors.Join(e, key.Close())
	if e != nil {
		return e
	}
	if len(public) != 32 {
		return errors.New("invalid backup encryption public key")
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { e := writeBackupTar(ctx, writer, root, name); writer.CloseWithError(e); done <- e }()
	e = Seal(out, reader, public)
	reader.CloseWithError(e)
	return errors.Join(e, <-done)
}

// writeBackupTar は固定三領域の通常ファイルだけを収録し、リンクを拒否する。
func writeBackupTar(ctx context.Context, out io.Writer, root, name string) (err error) {
	archive := tar.NewWriter(out)
	defer func() { err = errors.Join(err, archive.Close()) }()
	for _, relative := range []string{filepath.Join("copies", name), filepath.Join("keys", name), filepath.Join("pairs", name+".json")} {
		e := filepath.WalkDir(filepath.Join(root, relative), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if e := ctx.Err(); e != nil {
				return e
			}
			info, e := checkPrivate(path, entry.IsDir())
			if e != nil {
				return e
			}
			header, e := tar.FileInfoHeader(info, "")
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(root, path)
			if e != nil {
				return e
			}
			header.Name = filepath.ToSlash(rel)
			if e = archive.WriteHeader(header); e != nil {
				return e
			}
			if entry.IsDir() {
				return nil
			}
			f, e := openPrivate(path)
			if e != nil {
				return e
			}
			n, e := io.Copy(archive, f)
			if e == nil && n != info.Size() {
				e = io.ErrUnexpectedEOF
			}
			return errors.Join(e, f.Close())
		})
		if e != nil {
			return e
		}
	}
	return nil
}
