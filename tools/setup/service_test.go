// unitの引数解釈、既存物の保護、管理コマンド失敗時の停止を隔離先で検査する。
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceUnit(t *testing.T) {
	for _, validation := range []bool{false, true} {
		unit, err := serviceUnit("/srv/日本語 with spaces/bin/oimobbs", `/srv/a%h$HOME"\b/config.json`, validation, 1000, 1001)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"User=1000\nGroup=1001", "Type=exec", `ExecStart=:"/srv/日本語 with spaces/bin/oimobbs"`, `"/srv/a%%h$HOME\"\\b/config.json"`, "NoNewPrivileges=true", "TimeoutStopSec=35", "AmbientCapabilities=CAP_NET_BIND_SERVICE\n", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"} {
			if !strings.Contains(unit, want) {
				t.Fatalf("missing %q in:\n%s", want, unit)
			}
		}
		if strings.Contains(unit, "validation-serve") != validation || strings.Contains(unit, " --admin") != validation {
			t.Fatal("wrong HTTP/HTTPS command", unit)
		}
	}
}

func TestServiceUnitRejectsUnsafeInputs(t *testing.T) {
	for _, path := range []string{"relative", "/srv/a\nUser=root", "/srv/a\x00b"} {
		if _, err := serviceUnit("/bin/true", path, false, 1000, 1000); err == nil {
			t.Fatal("invalid path accepted", path)
		}
	}
	for _, ids := range [][2]int{{0, 1000}, {1000, 0}} {
		if _, err := serviceUnit("/bin/true", "/srv/config.json", false, ids[0], ids[1]); err == nil {
			t.Fatal("root accepted")
		}
	}
}

func TestServiceWriteDoesNotOverwrite(t *testing.T) {
	for _, kind := range []string{"new", "file", "symlink", "dangling"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path, target := filepath.Join(root, "oimobbs.service"), filepath.Join(root, "keep")
			if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "file":
				if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink", "dangling":
				link := target
				if kind == "dangling" {
					link += "-missing"
				}
				if err := os.Symlink(link, path); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("/bin/sh", "-c", serviceWriteScript, "test", path)
			command.Stdin = strings.NewReader("new-unit")
			err := command.Run()
			if (err == nil) != (kind == "new") {
				t.Fatal("unexpected write result", err)
			}
			got, err := os.ReadFile(target)
			if err != nil || string(got) != "existing" {
				t.Fatal("target changed", err)
			}
			if kind == "new" {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != "new-unit" {
					t.Fatal("unit not written", err)
				}
			}
		})
	}
}

func TestInstallServiceCommandOrderAndFailure(t *testing.T) {
	if os.Getuid() == 0 || os.Getgid() == 0 {
		t.Skip("サービスは一般ユーザーで登録する")
	}
	for _, fail := range []string{"", "write", "daemon-reload", "enable", "start"} {
		t.Run(fail, func(t *testing.T) {
			root := t.TempDir()
			log := filepath.Join(root, "calls")
			t.Setenv("SERVICE_TEST_LOG", log)
			t.Setenv("SERVICE_TEST_FAIL", fail)
			t.Setenv("PATH", root+":"+os.Getenv("PATH"))
			script := `#!/bin/sh
if [ "$2" = /bin/sh ]; then
  action=write
  cat > "$SERVICE_TEST_LOG.unit"
else
  action=$3
fi
printf '%s\n' "$action" >> "$SERVICE_TEST_LOG"
[ "$action" != "$SERVICE_TEST_FAIL" ]
`
			if err := os.WriteFile(filepath.Join(root, "sudo"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			err := installService("/bin/true", "/srv/config.json", false, true)
			if (err == nil) != (fail == "") {
				t.Fatal("failure ignored", err)
			}
			got, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			for _, action := range []string{"write", "daemon-reload", "enable", "start"} {
				want += action + "\n"
				if action == fail {
					break
				}
			}
			if string(got) != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestServiceUnitSystemdParser(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyzeなし")
	}
	root := t.TempDir()
	directory := filepath.Join(root, `作業 with spaces $HOME %h " back\slash`)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, `実行 with spaces %h`)
	if err := os.Symlink("/bin/true", binary); err != nil {
		t.Fatal(err)
	}
	for _, validation := range []bool{false, true} {
		unit, err := serviceUnit(binary, filepath.Join(directory, `設定 $HOME %h " \.json`), validation, 1000, 1000)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "oimobbs.service")
		if err := os.WriteFile(path, []byte(unit), 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command("systemd-analyze", "verify", path).CombinedOutput(); err != nil {
			t.Fatalf("unit rejected: %v\n%s\n%s", err, output, unit)
		}
	}
}
