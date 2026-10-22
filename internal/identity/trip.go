// Package identity は公開用識別子を生成し、秘密入力を結果へ含めない。
package identity

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"oimobbs/internal/textcodec"
	"strings"
)

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Trip は10/12文字・生鍵の互換トリップを計算する。秘密は保存しない。
func Trip(secret string) (string, error) {
	if strings.IndexByte(secret, 0) >= 0 {
		return "", errors.New("NUL in trip")
	}
	b, e := textcodec.Encode(secret, false)
	if e != nil {
		return "", e
	}
	if len(b) > 1024 {
		return "", errors.New("trip too long")
	}
	if len(b) == 0 {
		return "", nil
	}
	if len(b) < 12 {
		return desCrypt(b, shortSalt(b))[3:], nil
	}
	if b[0] == '$' {
		return "???", nil
	}
	if b[0] == '#' {
		return rawTrip(b), nil
	}
	sum := sha1.Sum(b)
	return strings.ReplaceAll(base64.StdEncoding.EncodeToString(sum[:])[:12], "+", "."), nil
}
func shortSalt(b []byte) string {
	s := []byte{}
	for i := 1; i < len(b) && i < 3; i++ {
		c := b[i]
		if c < '.' || c > 'z' {
			c = '.'
		}
		if c >= ':' && c <= '@' {
			c += 'A' - ':'
		}
		if c >= '[' && c <= '`' {
			c += 'a' - '['
		}
		s = append(s, c)
	}
	return (string(s) + "H.")[:2]
}
func rawTrip(b []byte) string {
	if len(b) < 17 || len(b) > 19 {
		return "???"
	}
	key, e := hex.DecodeString(string(b[1:17]))
	if e != nil {
		return "???"
	}
	salt := string(b[17:])
	for _, c := range salt {
		if !strings.ContainsRune(cryptAlphabet, c) {
			return "???"
		}
	}
	if n := strings.IndexByte(string(key), 0); n >= 0 {
		key = key[:n]
	}
	return desCrypt(key, (salt + "..")[:2])[3:]
}
func permute(x uint64, table []byte) uint64 {
	var out uint64
	for _, bit := range table {
		out = out<<1 | (x>>bit)&1
	}
	return out
}
func desKeys(key []byte) [16]uint64 {
	var k uint64
	for i := 0; i < 8; i++ {
		k <<= 8
		if i < len(key) {
			k |= uint64((key[i] & 127) << 1)
		}
	}
	v := permute(k, permutedChoice1[:])
	c, d := uint32(v>>28), uint32(v)&0xfffffff
	var keys [16]uint64
	for i, r := range ksRotations {
		c = (c<<r | c>>(28-r)) & 0xfffffff
		d = (d<<r | d>>(28-r)) & 0xfffffff
		keys[i] = permute(uint64(c)<<28|uint64(d), permutedChoice2[:])
	}
	return keys
}
func desCrypt(key []byte, salt string) string {
	keys := desKeys(key)
	expand := expansionFunction
	v := strings.IndexByte(cryptAlphabet, salt[0]) | strings.IndexByte(cryptAlphabet, salt[1])<<6
	for i := 0; i < 12; i++ {
		if v&(1<<i) != 0 {
			expand[i], expand[i+24] = expand[i+24], expand[i]
		}
	}
	var block uint64
	for iter := 0; iter < 25; iter++ {
		x := permute(block, initialPermutation[:])
		l, r := uint32(x>>32), uint32(x)
		for _, k := range keys {
			e := permute(uint64(r), expand[:]) ^ k
			var s uint32
			for i := 0; i < 8; i++ {
				n := byte(e>>uint(42-6*i)) & 63
				row := (n>>4)&2 | n&1
				col := (n >> 1) & 15
				s = s<<4 | uint32(sBoxes[i][row][col])
			}
			l, r = r, l^uint32(permute(uint64(s), permutationFunction[:]))
		}
		block = permute(uint64(r)<<32|uint64(l), finalPermutation[:])
	}
	out := []byte(salt)
	for i := 0; i < 11; i++ {
		var n byte
		for j := 0; j < 6; j++ {
			n <<= 1
			bit := i*6 + j
			if bit < 64 {
				n |= byte(block>>uint(63-bit)) & 1
			}
		}
		out = append(out, cryptAlphabet[n])
	}
	return string(out)
}
