// 各ページの資産指定を検証し、編集・認証・閲覧の専用コードを別画面へ配らない。
package webui

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestPageAssetIsolation(t *testing.T) {
	type flags struct{ Login, Reauth, Editing bool }
	for _, tt := range []struct {
		name string
		view flags
		want []string
	}{
		{"admin", flags{}, nil},
		{"admin", flags{Login: true}, []string{"admin-auth.css", "admin-auth.js"}},
		{"admin", flags{Reauth: true}, []string{"admin-auth.css", "admin-auth.js"}},
		{"boards", flags{}, []string{"list.css", "list.js"}},
		{"boards", flags{Editing: true}, []string{"admin-settings.css", "admin-board.css", "list.css", "countries.css", "countries.js", "list.js", "admin-board.js", "admin-settings.js"}},
		{"reading", flags{}, []string{"admin-settings.css", "protection.css", "admin-reading.css", "list.css", "countries.css", "countries.js", "list.js", "admin-settings.js"}},
		{"waf", flags{}, []string{"admin-settings.css", "protection.css", "admin-waf.css", "admin-waf.js", "admin-settings.js"}},
		{"audit", flags{}, []string{"admin-audit.css", "admin-audit.js", "dates.css", "dates.js"}},
		{"admin-accounts", flags{}, []string{"admin-access.css", "admin-access.js"}},
		{"manual", flags{}, []string{"admin-access.css"}},
		{"caps", flags{}, []string{"dates.css", "dates.js"}},
		{"evidence", flags{}, []string{"evidence.css", "dates.css", "dates.js"}},
		{"search", flags{}, []string{"dates.css", "dates.js"}},
		{"passkeys", flags{}, []string{"admin-auth.css", "admin-auth.js"}},
		{"networks", flags{}, []string{"admin-networks.css", "list.css", "list.js", "admin-networks.js"}},
		{"thread", flags{}, []string{"thread.css", "thread.js"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var body bytes.Buffer
			if err := AdminTemplate(tt.name, "/admin").ExecuteTemplate(&body, "page-assets", tt.view); err != nil {
				t.Fatal(err)
			}
			var got []string
			seen := map[string]bool{}
			for _, m := range regexp.MustCompile(`(?:href|src)="(/admin/web/assets/[a-f0-9]{64}/([^"/]+))"`).FindAllStringSubmatch(body.String(), -1) {
				got = append(got, m[2])
				if seen[m[2]] {
					t.Fatal("duplicate", m[2])
				}
				seen[m[2]] = true
				if _, ok := publicAssets[strings.TrimPrefix(m[1], "/admin")]; !ok {
					t.Fatal("unknown asset", m[1])
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllTemplatesParseWithPageAssets(t *testing.T) {
	entries, err := files.ReadDir("templates")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, entry := range entries {
		raw, err := files.ReadFile("templates/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range regexp.MustCompile(`{{template "(?:stylesheet|javascript|favicon)" "([^"]+)"}}`).FindAllStringSubmatch(string(raw), -1) {
			if _, ok := versionedAssetPaths[match[1]]; !ok {
				t.Fatal("unknown template asset", entry.Name(), match[1])
			}
			used[match[1]] = true
		}
		if entry.Name() != "common.html" {
			Template(strings.TrimSuffix(entry.Name(), ".html"))
		}
	}
	for name := range versionedAssetPaths {
		if !used[name] {
			t.Errorf("unreferenced asset: %s", name)
		}
	}
}

// TestPageAssetSizes は共通部品を含めた未圧縮の配信量を記録する。ネットワークの所要時間は測らない。
func TestPageAssetSizes(t *testing.T) {
	for _, tt := range []struct {
		name string
		view any
	}{
		{"admin", struct{ Login, Reauth bool }{}}, {"admin", struct{ Login, Reauth bool }{Login: true}},
		{"reading", nil}, {"waf", nil}, {"boards", struct{ Editing bool }{true}},
	} {
		var body bytes.Buffer
		if err := Template(tt.name).ExecuteTemplate(&body, "admin-assets", tt.view); err != nil {
			t.Fatal(err)
		}
		bytes := 0
		count := 0
		for _, match := range regexp.MustCompile(`(?:href|src)="(/web/assets/[a-f0-9]{64}/[^"]+)"`).FindAllStringSubmatch(body.String(), -1) {
			bytes += len(publicAssets[match[1]].DAT)
			count++
		}
		t.Logf("%s %v: %d files, %d identity bytes", tt.name, tt.view, count, bytes)
	}
}
