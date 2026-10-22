// 完全初回WALだけの補完と、不完全・異世代・不正参照の非変更拒否を検査する。
package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverThreadCreation(t *testing.T) {
	for _, scenario := range []string{"complete", "install", "short", "extra", "changed", "generation", "symlink", "bad_install", "existing"} {
		t.Run(scenario, func(t *testing.T) {
			owner, frame := fixtureCreate(t)
			parent := privateTemp(t)
			log, err := CreateThread(parent, owner, 1, frame)
			if err != nil {
				t.Fatal(err)
			}
			if err = log.Close(); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(parent, "1")
			currentPath := filepath.Join(dir, "current.json")
			current, err := os.ReadFile(currentPath)
			if err != nil {
				t.Fatal(err)
			}
			if scenario != "existing" {
				if err = os.Remove(currentPath); err != nil {
					t.Fatal(err)
				}
			}
			walPath := filepath.Join(dir, "delta-000001.wal")
			raw, err := os.ReadFile(walPath)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "short":
				raw = raw[:len(raw)-1]
			case "extra":
				raw = append(raw, 0)
			case "changed":
				raw[len(raw)-1] ^= 1
			case "generation":
				if err = os.WriteFile(filepath.Join(dir, "delta-000002.wal"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "install", "bad_install":
				temp := current[:len(current)/2]
				if scenario == "bad_install" {
					temp = []byte("changed")
				}
				if err = os.WriteFile(filepath.Join(dir, ".install-test"), temp, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.WriteFile(walPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if scenario == "symlink" {
				if err = os.Rename(walPath, walPath+".old"); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(walPath+".old", walPath); err != nil {
					t.Fatal(err)
				}
			}
			err = RecoverThreadCreation(parent, owner, 1, frame)
			if scenario == "complete" || scenario == "install" {
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(currentPath)
				if err != nil || !bytes.Equal(got, current) {
					t.Fatal("current differs", err)
				}
				opened, err := OpenThread(parent, owner, 1)
				if err != nil {
					t.Fatal(err)
				}
				defer opened.Close()
				if opened.State().After.PostCount != 1 {
					t.Fatal("create lost")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe recovery accepted")
				}
				if scenario != "existing" {
					if _, err = os.Lstat(currentPath); !os.IsNotExist(err) {
						t.Fatal("current installed on rejection", err)
					}
				}
			}
			got, err := os.ReadFile(walPath)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatal("WAL changed", err)
			}
		})
	}
}
