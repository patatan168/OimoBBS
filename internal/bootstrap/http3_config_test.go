// HTTP/3の省略互換性、厳格な値検査、永続reader境界を検査する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/strictjson"
	"testing"
)

func TestHTTP3ConfigCompatibility(t *testing.T) {
	base := `"listen":"127.0.0.1:443","base_url":"https://localhost","tls_cert_file":"cert","tls_key_file":"key"`
	for _, tc := range []struct {
		suffix    string
		want, bad bool
	}{
		{"", false, false}, {`,"http3":false`, false, false}, {`,"http3":true`, true, false},
		{`,"http3_native":true`, false, true}, {`,"http3_native":null`, false, true}, {`,"http3":null`, false, true}, {`,"http3":"auto"`, false, true}, {`,"http3":true,"http3":false`, false, true}, {`,"unknown":false`, false, true},
	} {
		var c PublicConfig
		err := strictjson.Decode([]byte("{"+base+tc.suffix+"}"), &c)
		if (err != nil) != tc.bad || err == nil && c.HTTP3 != tc.want {
			t.Fatalf("%s: %+v %v", tc.suffix, c, err)
		}
	}
}

func TestEnableHTTP3ReaderBoundary(t *testing.T) {
	cfg, repo := adminFixture(t)
	if err := repo.EnableHTTP3(); err != nil {
		t.Fatal(err)
	}
	before := repo.site.State().Seq
	if err := repo.EnableHTTP3(); err != nil {
		t.Fatal(err)
	}
	if repo.site.State().Seq != before {
		t.Fatal("repeated activation persisted")
	}
	var site siteState
	if err := json.Unmarshal(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != http3Reader {
		t.Fatal(site, err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	if report, err := Check(cfg); err != nil || report.MinimumReader != http3Reader {
		t.Fatal(report, err)
	}
}
