// 日時付き再開と304の最小メタデータを、公開形式の契約から検査する。
package compat

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIfRangeDateRequiresUniqueUnchangedVersion(t *testing.T) {
	modified := time.Unix(1800000000, 500000000)
	date := modified.UTC().Format(http.TimeFormat)
	for _, tc := range []struct {
		name, validator       string
		exact, safe, disabled bool
		status                int
	}{
		{"unchanged date", date, true, true, false, 206},
		{"changed date", modified.Add(-time.Second).UTC().Format(http.TimeFormat), true, true, false, 200},
		{"future date", modified.Add(time.Second).UTC().Format(http.TimeFormat), true, true, false, 200},
		{"same second versions", date, false, true, false, 200},
		{"clock regression", date, true, false, false, 200},
		{"redacted generation", date, true, true, true, 200},
		{"weak tag", `W/"i"`, true, true, false, 200},
		{"strong tag", `"i"`, false, false, true, 206},
		{"invalid date", "invalid", true, true, false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Range", "bytes=7-")
			r.Header.Set("If-Range", tc.validator)
			w := httptest.NewRecorder()
			ServeDAT(w, r, Representation{DAT: []byte("prefix\ntail\n"), ETagIdentity: `"i"`, Modified: modified, Now: modified.Add(2 * time.Second), DateExact: tc.exact, DateSafe: tc.safe, LegacyRangeDisabled: tc.disabled})
			want := "prefix\ntail\n"
			if tc.status == 206 {
				want = "tail\n"
			}
			if w.Code != tc.status || w.Body.String() != want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestNotModifiedOmitsBodyMetadata(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "gzip,identity;q=0")
	r.Header.Set("If-None-Match", `"g"`)
	w := httptest.NewRecorder()
	ServeDAT(w, r, Representation{DAT: []byte("text"), ETagIdentity: `"i"`, ETagGzip: `"g"`})
	if w.Code != 304 || w.Body.Len() != 0 {
		t.Fatal(w.Code)
	}
	for _, header := range []string{"Content-Type", "Content-Encoding", "Content-Length", "Accept-Ranges"} {
		if w.Header().Get(header) != "" {
			t.Fatal("unneeded 304 header", header)
		}
	}
	for _, header := range []string{"ETag", "Vary", "Cache-Control"} {
		if w.Header().Get(header) == "" {
			t.Fatal("missing validator metadata", header)
		}
	}
}
