// HTTP観測成分を保存時・再読込時に同じ完全型で検証する。
package evidence

import (
	"crypto/tls"
	"net"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"reflect"
	"strconv"
	"strings"
)

// ValidateHTTPObservation は直結/単一認証edgeの観測成分を検証する。evidence-v1全体の検証器ではない。
func ValidateHTTPObservation(raw []byte) error {
	if len(raw) > 128<<10 {
		return ErrHTTPObservation
	}
	var v HTTPObservation
	if e := strictjson.Decode(raw, &v); e != nil {
		return e
	}
	if v.BodyCompleted == 0 {
		return ErrHTTPObservation
	}
	return validateObservation(v)
}
func validateObservation(v HTTPObservation) error {
	if v.BoardID == (domain.ID{}) {
		return ErrHTTPObservation
	}
	return validateConnectionObservation(v)
}
func validateConnectionObservation(v HTTPObservation) error {
	if v.Schema != "http-observation-v1" || v.SiteID == (domain.ID{}) || v.InstanceID == (domain.ID{}) || v.BootID == (domain.ID{}) || v.ConnectionID == (domain.ID{}) || v.RequestID == (domain.ID{}) {
		return ErrHTTPObservation
	}
	if !validEndpoint(v.Peer) || !validEndpoint(v.Local) || v.Transport != "tcp" {
		return ErrHTTPObservation
	}
	if v.HTTPVersion != "HTTP/1.0" && v.HTTPVersion != "HTTP/1.1" && v.HTTPVersion != "HTTP/2.0" {
		return ErrHTTPObservation
	}
	if !validateProxyObservation(v) {
		return ErrHTTPObservation
	}
	if v.Method != "POST" || !validRoute(v.Route) || !validAuthority(v.CanonicalHost) || !validLabel(v.ServerBuildID, 128) || v.BodyBytes > MaxObservedBodyBytes || v.HeaderCaptureStatus != "captured" || v.ParsedHeaderBytes > MaxObservedHeaderBytes {
		return ErrHTTPObservation
	}
	if v.ClockSource != "unconfigured" || v.ClockOffsetMS != nil || v.ClockObserved != nil || v.Received == 0 {
		return ErrHTTPObservation
	}
	status := "unknown"
	if v.BodyCompleted != 0 && v.BodyCompleted < v.Received {
		status = "degraded"
	}
	if v.ClockStatus != status {
		return ErrHTTPObservation
	}
	if e := validateTLS(v); e != nil {
		return e
	}
	size, e := validateHeaders(v.SelectedHeaders, selectedHeaderNames)
	if e != nil {
		return e
	}
	reported, e := validateHeaders(v.ReportedHeaders, reportedHeaderNames)
	if e != nil {
		return e
	}
	if domain.U64(size+reported) > v.ParsedHeaderBytes {
		return ErrHTTPObservation
	}
	charset, e := declaredCharset(v.SelectedHeaders)
	if e != nil || !reflect.DeepEqual(charset, v.DeclaredCharset) {
		return ErrHTTPObservation
	}
	if !reflect.DeepEqual(v.MissingFields, observationMissing(v)) {
		return ErrHTTPObservation
	}
	return nil
}
func validateTLS(v HTTPObservation) error {
	if v.TLSVersion == nil {
		if v.TLSCipherSuite != nil || v.SNI != nil {
			return ErrHTTPObservation
		}
		return nil
	}
	if *v.TLSVersion != tls.VersionTLS12 && *v.TLSVersion != tls.VersionTLS13 || v.TLSCipherSuite == nil || *v.TLSCipherSuite == 0 {
		return ErrHTTPObservation
	}
	if v.SNI != nil && (!validAuthority(strings.ToLower(*v.SNI)) || strings.ContainsAny(*v.SNI, "[]:")) {
		return ErrHTTPObservation
	}
	return nil
}
func observationMissing(v HTTPObservation) []MissingField {
	result := []MissingField{{"clock_offset_ms", "not_observed"}, {"clock_observed_at_ns", "not_observed"}, {"proxy_profile_id", "direct_connection"}, {"proxy_config_revision", "direct_connection"}, {"origin_endpoint", "not_configured"}}
	if v.ClientSource == "edge_endpoint_v1" {
		result = result[:2]
	}
	if v.DeclaredCharset == nil {
		result = append(result, MissingField{"declared_charset", "not_declared"})
	}
	if v.TLSVersion == nil {
		result = append(result, MissingField{"tls_version", "not_tls"}, MissingField{"tls_cipher_suite", "not_tls"})
	}
	if v.SNI == nil {
		reason := "not_sent"
		if v.TLSVersion == nil {
			reason = "not_tls"
		}
		result = append(result, MissingField{"sni", reason})
	}
	return result
}
func socketEndpoint(address net.Addr) (Endpoint, error) {
	if address == nil || address.Network() != "tcp" {
		return Endpoint{}, ErrHTTPObservation
	}
	parsed, e := netip.ParseAddrPort(address.String())
	if e != nil || parsed.Addr().Zone() != "" || parsed.Port() == 0 {
		return Endpoint{}, ErrHTTPObservation
	}
	result := Endpoint{parsed.Addr().Unmap().String(), parsed.Port()}
	if !validEndpoint(result) {
		return Endpoint{}, ErrHTTPObservation
	}
	return result, nil
}
func validEndpoint(v Endpoint) bool {
	ip, e := netip.ParseAddr(v.IP)
	return e == nil && v.Port != 0 && ip.Zone() == "" && !ip.IsUnspecified() && ip.Unmap().String() == v.IP
}
func validRoute(route string) bool {
	return route == "bbs_post" || route == "web_create" || route == "web_reply"
}
func validLabel(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, c := range []byte(value) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func validAuthority(host string) bool {
	if !validLabel(host, 253) || host != strings.ToLower(host) {
		return false
	}
	u, e := url.Parse("http://" + host)
	if e != nil || u.User != nil || u.Host != host || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
		return false
	}
	if strings.HasSuffix(host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return false
		}
	}
	hostname := u.Hostname()
	if ip, e := netip.ParseAddr(hostname); e == nil {
		return ip.Zone() == ""
	}
	for _, c := range []byte(hostname) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
