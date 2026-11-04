// RFC9001のInitial秘密値、packet/header protection、鍵更新を標準暗号へ接続する。
package quicv1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

var initialSalt = mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
var retryKey = mustHex("be0c690b9f66575a1d766b54e368c84e")
var retryNonce = mustHex("461599d35d632bf2239825bb")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// expandLabel はTLS1.3 HKDF-Expand-Labelを実装し、用途ごとに秘密値を分離する。
func expandLabel(secret []byte, label string, length int, h func() hash.Hash) ([]byte, error) {
	label = "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(label)))
	info = append(info, label...)
	info = append(info, 0)
	return hkdf.Expand(h, secret, string(info), length)
}

type packetKeys struct {
	aead       cipher.AEAD
	hp         cipher.Block
	chachaHP   []byte
	iv, secret []byte
	suite      uint16
	// 暗号処理は接続actor内で直列実行する。入力は複製し、作業領域を外部へ渡さない。
	nonceBuffer [12]byte
	maskBuffer  [16]byte
	header      [256]byte
}

// initialKeys はDCIDからclient/serverのInitial用鍵を別々に導出する。
func initialKeys(dcid []byte) (client, server *packetKeys, err error) {
	secret, err := hkdf.Extract(sha256.New, dcid, initialSalt)
	if err != nil {
		return nil, nil, err
	}
	c, err := expandLabel(secret, "client in", 32, sha256.New)
	if err != nil {
		return nil, nil, err
	}
	s, err := expandLabel(secret, "server in", 32, sha256.New)
	if err != nil {
		return nil, nil, err
	}
	client, err = trafficKeys(c, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		return nil, nil, err
	}
	server, err = trafficKeys(s, tls.TLS_AES_128_GCM_SHA256)
	return
}

func trafficKeys(secret []byte, suite uint16) (*packetKeys, error) {
	h := sha256.New
	size := 16
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
	case tls.TLS_AES_256_GCM_SHA384:
		h = sha512.New384
		size = 32
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		size = 32
	default:
		return nil, errors.New("unsupported QUIC TLS cipher")
	}
	key, err := expandLabel(secret, "quic key", size, h)
	if err != nil {
		return nil, err
	}
	iv, err := expandLabel(secret, "quic iv", 12, h)
	if err != nil {
		return nil, err
	}
	hp, err := expandLabel(secret, "quic hp", size, h)
	if err != nil {
		return nil, err
	}
	result := &packetKeys{iv: iv, secret: append([]byte(nil), secret...), suite: suite}
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		result.aead, err = chacha20poly1305.New(key)
		result.chachaHP = hp
		return result, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	result.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	result.hp, err = aes.NewCipher(hp)
	return result, err
}

func (k *packetKeys) next() (*packetKeys, error) {
	h := sha256.New
	if k.suite == tls.TLS_AES_256_GCM_SHA384 {
		h = sha512.New384
	}
	secret, err := expandLabel(k.secret, "quic ku", h().Size(), h)
	if err != nil {
		return nil, err
	}
	next, err := trafficKeys(secret, k.suite)
	if err != nil {
		return nil, err
	}
	// RFC9001 6節: key updateでもheader protection keyは変更しない。
	next.hp = k.hp
	next.chachaHP = k.chachaHP
	return next, nil
}
func (k *packetKeys) nonce(pn uint64) []byte {
	nonce := k.nonceBuffer[:]
	copy(nonce, k.iv)
	v := binary.BigEndian.Uint64(nonce[4:]) ^ pn
	binary.BigEndian.PutUint64(nonce[4:], v)
	return nonce
}
func (k *packetKeys) mask(sample []byte) ([5]byte, error) {
	var out [5]byte
	if len(sample) < 16 {
		return out, errWire
	}
	if k.hp != nil {
		k.hp.Encrypt(k.maskBuffer[:], sample[:16])
		copy(out[:], k.maskBuffer[:5])
		return out, nil
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(k.chachaHP, sample[4:16])
	if err != nil {
		return out, err
	}
	cipher.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
	cipher.XORKeyStream(out[:], out[:])
	return out, nil
}

// sealPacket はpacket番号を含むheaderを認証し、最後にheader protectionを適用する。
func (k *packetKeys) sealPacket(header, payload []byte, pn uint64, pnOffset int) ([]byte, error) {
	return k.sealPacketInto(nil, header, payload, pn, pnOffset)
}

// sealPacketInto は呼出元が所有するbufferを再使用し、平文・AADを変更しない。
func (k *packetKeys) sealPacketInto(dst, header, payload []byte, pn uint64, pnOffset int) ([]byte, error) {
	out := append(dst, header...)
	out = k.aead.Seal(out, k.nonce(pn), payload, header)
	mask, err := k.mask(out[pnOffset+4:])
	if err != nil {
		return nil, err
	}
	bits := byte(0x1f)
	if out[0]&0x80 != 0 {
		bits = 0x0f
	}
	out[0] ^= mask[0] & bits
	n := int(header[0]&3) + 1
	for i := 0; i < n; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out, nil
}

// openPacket は受信bufferを変更せず、復元したheader・packet番号をAEADで検証する。
func (k *packetKeys) openPacket(packet []byte, pnOffset int, expected uint64) (payload []byte, pn uint64, first byte, err error) {
	return k.openPacketInto(nil, packet, pnOffset, expected)
}

// openPacketInto はactor専有の復号領域を再利用し、鍵の再試行に必要な暗号文は保持する。
// 返す平文は次の呼出し前に処理し終え、stream等へ残す場合は別途コピーする。
func (k *packetKeys) openPacketInto(dst, packet []byte, pnOffset int, expected uint64) (payload []byte, pn uint64, first byte, err error) {
	if pnOffset < 1 || pnOffset > len(packet)-20 {
		return nil, 0, 0, errWire
	}
	mask, err := k.mask(packet[pnOffset+4:])
	if err != nil {
		return nil, 0, 0, err
	}
	first = packet[0]
	bits := byte(0x1f)
	if first&0x80 != 0 {
		bits = 0x0f
	}
	first ^= mask[0] & bits
	n := int(first&3) + 1
	header := append(k.header[:0], packet[:pnOffset+n]...)
	header[0] = first
	var truncated uint64
	for i := 0; i < n; i++ {
		header[pnOffset+i] ^= mask[i+1]
		truncated = truncated<<8 | uint64(header[pnOffset+i])
	}
	pn = packetNumber(truncated, n, expected)
	payload, err = k.aead.Open(dst, k.nonce(pn), packet[pnOffset+n:], header)
	if err != nil {
		return nil, 0, 0, err
	}
	reserved := byte(0x18)
	if first&0x80 != 0 {
		reserved = 0x0c
	}
	if first&reserved != 0 {
		return nil, 0, 0, protocolError(0xa, 0, "reserved packet bits")
	}
	return payload, pn, first, nil
}

// retryIntegrity はRFC9001で固定された鍵によるRetryの認証tagを返す。
func retryIntegrity(odcid, retry []byte) []byte {
	block, _ := aes.NewCipher(retryKey)
	aead, _ := cipher.NewGCM(block)
	pseudo := append([]byte{byte(len(odcid))}, odcid...)
	pseudo = append(pseudo, retry...)
	return aead.Seal(nil, retryNonce, nil, pseudo)
}
