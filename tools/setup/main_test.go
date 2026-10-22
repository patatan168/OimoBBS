// 新規設定の入力拒否と既存物の保護を、保存操作に進む前に検査する。
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) options {
	t.Helper()
	o, err := parse([]string{"--config", filepath.Join(t.TempDir(), "config.json"), "--url", "http://127.0.0.1", "--allow-http"})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestDefaultsUseOperationsBoardAndHTTPS(t *testing.T) {
	o, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.board != "operate" || o.boardName != "運営" || o.origin != "https://localhost" || o.allowHTTP {
		t.Fatal("unexpected defaults", o)
	}
	if _, err := publicConfig(o); err == nil {
		t.Fatal("HTTPS without certificates accepted")
	}
	o.cert, o.key = "fullchain.pem", "privkey.pem"
	c, err := publicConfig(o)
	if err != nil || c.Listen != "0.0.0.0:443" || c.BaseURL != "https://localhost" {
		t.Fatal("HTTPS default is not 443", c, err)
	}
	o.origin, o.cert, o.key = "http://127.0.0.1", "", ""
	if _, err := publicConfig(o); err == nil {
		t.Fatal("HTTP accepted without explicit opt-in")
	}
	o.allowHTTP = true
	c, err = publicConfig(o)
	if err != nil || c.Listen != "127.0.0.1:80" {
		t.Fatal("HTTP opt-in is not port 80", c, err)
	}
}

func TestHTTPSListenerUsesURLPort(t *testing.T) {
	o, _ := parse([]string{"--url", "https://bbs.example.com:9443", "--tls-cert", "cert.pem", "--tls-key", "key.pem"})
	c, err := publicConfig(o)
	if err != nil || c.Listen != "0.0.0.0:9443" {
		t.Fatal(c, err)
	}
	o.listen = "127.0.0.1:1443"
	c, err = publicConfig(o)
	if err != nil || c.Listen != o.listen {
		t.Fatal("explicit listener ignored", c, err)
	}
}

func TestConfigRefusesExistingDataAndSymlinks(t *testing.T) {
	for _, kind := range []string{"config", "data", "link", "parent-link"} {
		t.Run(kind, func(t *testing.T) {
			o := fixture(t)
			root := filepath.Dir(o.config)
			marker := filepath.Join(root, "keep")
			if err := os.WriteFile(marker, []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "config":
				o.config = marker
			case "data":
				o.data = root
			case "link":
				o.data = filepath.Join(root, "link")
				if err := os.Symlink(marker, o.data); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				link := filepath.Join(root, "link")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				o.data = filepath.Join(link, "site")
			}
			if _, _, err := configFor(o); err == nil {
				t.Fatal("existing path accepted")
			}
			got, err := os.ReadFile(marker)
			if err != nil || string(got) != "existing" {
				t.Fatal("existing content changed", err)
			}
		})
	}
}

func TestConfigRejectsInvalidOptions(t *testing.T) {
	cases := []func(*options){
		func(o *options) { o.origin = "http://example.com" },
		func(o *options) { o.origin = "https://example.com" },
		func(o *options) { o.origin = "http://127.0.0.1:9080/" },
		func(o *options) { o.cert = "unexpected.pem" },
		func(o *options) { o.board = "test" },
		func(o *options) { o.login = "UPPERCASE" },
		func(o *options) { o.publicAdmin = false; o.adminPort = 0 },
	}
	for i, change := range cases {
		o := fixture(t)
		change(&o)
		if _, _, err := configFor(o); err == nil {
			t.Fatalf("invalid case %d accepted", i)
		}
	}
}

func TestCustomHTTPListener(t *testing.T) {
	for _, address := range []string{"127.0.0.1:19080", "[::1]:19080"} {
		o := fixture(t)
		o.origin = "http://" + address
		_, c, err := configFor(o)
		if err != nil {
			t.Fatal(err)
		}
		if c.Public.Listen != address {
			t.Fatal(c.Public.Listen)
		}
		if c.Admin.Transport != "public_path" || c.Admin.Listen != "" || c.Admin.Origin != c.Public.BaseURL+"/admin/" {
			t.Fatal("new setup split the admin port", c.Admin)
		}
	}
}

func TestExistingBuildOutputPreserved(t *testing.T) {
	o := fixture(t)
	binary := filepath.Join(filepath.Dir(o.config), "bin", "oimobbs")
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("keep-binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := run(o, strings.NewReader("unused")); err == nil {
		t.Fatal("existing binary overwritten")
	}
	got, err := os.ReadFile(binary)
	if err != nil || string(got) != "keep-binary" {
		t.Fatal("binary changed", err)
	}
	if _, err = os.Stat(o.config); !os.IsNotExist(err) {
		t.Fatal("config created", err)
	}
}

func TestPasswordRejectsInvalidInput(t *testing.T) {
	for _, raw := range []string{"short\n", "valid-long-secret-2026\nsecond\n", "valid-long-secret-2026\x00", "valid-long-secret-2026\xff", strings.Repeat("x", 515)} {
		if _, err := password(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
	raw := []byte("valid-long-secret-2026\n")
	got, err := password(strings.NewReader(string(raw)))
	if err != nil || string(got) != string(raw) {
		t.Fatal("valid password rejected", err)
	}
	clear(got)
}
