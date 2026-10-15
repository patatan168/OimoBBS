// 申告した転送先を接続元と混同せず、許可ヘッダの元bytesと欠測理由を維持することを検査する。
package app

import (
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/evidence"
	"reflect"
	"testing"
)

func TestAcceptedClientDoesNotTrustReportedHeaders(t *testing.T) {
	obs := &evidence.HTTPObservation{Resolved: evidence.Endpoint{IP: "192.0.2.1", Port: 12345}, ClientSource: "direct", VerifiedProxyChain: []evidence.Endpoint{}, ReportedHeaders: []evidence.ObservedHeader{{Name: "X-Forwarded-For", Representation: "parser_value", Values: []evidence.HeaderValue{{Base64: base64.StdEncoding.EncodeToString([]byte("203.0.113.9")), Display: "203.0.113.9"}}}}, MissingFields: []evidence.MissingField{{Field: "proxy_profile_id", Reason: "direct_connection"}}}
	out := projectAcceptedClient(obs)
	if out["resolved_ip"] != obs.Resolved.IP || out["resolved_port"] != obs.Resolved.Port || out["source"] != "direct" {
		t.Fatal("reported client substituted for observed peer", out)
	}
	if out["reported_chain"] != nil || out["reported_headers_verified"] != false {
		t.Fatal("unverified headers promoted to trusted chain")
	}
	if !reflect.DeepEqual(out["reported_headers"], obs.ReportedHeaders) {
		t.Fatal("raw parser values lost")
	}
	missing := out["missing_fields"].([]evidence.MissingField)
	if len(missing) != 2 || missing[1].Reason != "direct_connection" {
		t.Fatal("proxy missing reason replaced")
	}
}

func TestAcceptedHTTPRequestPreservesHeaderBytesAndMissingAlias(t *testing.T) {
	rawHeader := []byte{0xff, 0xfe}
	obs := &evidence.HTTPObservation{Method: "POST", Route: "bbs_post", CanonicalHost: "example.test", BodyBytes: 42, HeaderCaptureStatus: "captured", SelectedHeaders: []evidence.ObservedHeader{{Name: "User-Agent", Representation: "parser_value", Values: []evidence.HeaderValue{{Base64: base64.StdEncoding.EncodeToString(rawHeader), Display: "表示"}}}}, MissingFields: []evidence.MissingField{{Field: "declared_charset", Reason: "not_declared"}}}
	out := projectAcceptedHTTPRequest(obs)
	if out["board_alias_used"] != nil || out["body_bytes"] != obs.BodyBytes || out["header_capture_status"] != "captured" {
		t.Fatal("request fields inferred or omitted")
	}
	if !reflect.DeepEqual(out["selected_headers"], obs.SelectedHeaders) {
		t.Fatal("non-UTF-8 parser value changed")
	}
	if len(out["missing_fields"].([]evidence.MissingField)) != 2 {
		t.Fatal("request gaps not explained")
	}
}

func TestAcceptedClientRequestRequireObservation(t *testing.T) {
	if projectAcceptedClient(nil) != nil || projectAcceptedHTTPRequest(nil) != nil {
		t.Fatal("missing observation inferred")
	}
	r, _ := acceptedContentFixture(t)
	out, e := r.Project(nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"client", "request"} {
		if _, found := out[key]; found {
			t.Fatal("unselected request data disclosed", key)
		}
	}
	selected, e := r.Project([]string{"connection"})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(selected)
	var decoded map[string]any
	if e = json.Unmarshal(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	if decoded["client"] != nil || decoded["request"] != nil {
		t.Fatal("legacy client/request data invented")
	}
}
