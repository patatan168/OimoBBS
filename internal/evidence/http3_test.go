// HTTP/3の記録にUDPとTLS1.3が揃うことと、従来TCPの検証境界を検査する。
package evidence

import (
	"crypto/tls"

	"testing"
)

func TestHTTP3ObservationTransportBinding(t *testing.T) {
	base := decodedObservationFixture(t)
	for _, tc := range []struct {
		transport, version string
		tls                uint16
		good               bool
	}{
		{"udp", "HTTP/3.0", tls.VersionTLS13, true},
		{"udp", "HTTP/3.0", tls.VersionTLS12, false},
		{"udp", "HTTP/2.0", tls.VersionTLS13, false},
		{"tcp", "HTTP/3.0", tls.VersionTLS13, false},
		{"tcp", "HTTP/2.0", tls.VersionTLS13, true},
	} {
		value := base
		value.Transport = tc.transport
		value.HTTPVersion = tc.version
		version, cipher := tc.tls, uint16(tls.TLS_AES_128_GCM_SHA256)
		value.TLSVersion = &version
		value.TLSCipherSuite = &cipher
		value.MissingFields = observationMissing(value)
		if err := ValidateHTTPObservationValue(value); (err == nil) != tc.good {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}
