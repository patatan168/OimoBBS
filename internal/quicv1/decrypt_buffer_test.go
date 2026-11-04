// 復号領域の再利用時も暗号文と再構成済み本文を保持し、別の鍵で再試行できることを確認する。
package quicv1

import (
	"bytes"
	"crypto/tls"
	"testing"
)

func TestPacketDecryptionBufferReuse(t *testing.T) {
	for _, suite := range []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256} {
		t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
			secretSize := 32
			if suite == tls.TLS_AES_256_GCM_SHA384 {
				secretSize = 48
			}
			key, err := trafficKeys(bytes.Repeat([]byte{1}, secretSize), suite)
			if err != nil {
				t.Fatal(err)
			}
			wrong, err := key.next()
			if err != nil {
				t.Fatal(err)
			}
			body := bytes.Repeat([]byte("response"), 100)
			header, offset := appendPacketHeader(nil, spaceApplication, []byte("test-CID"), nil, 7, len(body), false, 2)
			packet, err := key.sealPacket(header, body, 7, offset)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(packet)
			var scratch [1500]byte
			if _, _, _, err = wrong.openPacketInto(scratch[:0], packet, offset, 7); err == nil {
				t.Fatal("wrong packet key accepted")
			}
			payload, pn, _, err := key.openPacketInto(scratch[:0], packet, offset, 7)
			if err != nil || pn != 7 || !bytes.Equal(payload, body) || &payload[0] != &scratch[0] {
				t.Fatalf("decryption did not reuse valid storage: pn=%d error=%v", pn, err)
			}
			if !bytes.Equal(packet, original) {
				t.Fatal("key retry changed ciphertext")
			}
			rx := reassembly{limit: 1500}
			if _, err = rx.insert(0, payload, true); err != nil {
				t.Fatal(err)
			}
			clear(scratch[:])
			if !bytes.Equal(rx.pop(), body) {
				t.Fatal("reused decryption buffer changed retained stream data")
			}
		})
	}
}
