// Package sealedbackup は外部保管用コピーを標準GoのX25519・HKDF・AES-GCMで認証暗号化する。
package sealedbackup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const chunkSize = 64 << 10

var errArchive = errors.New("invalid authenticated backup archive")
var magic = []byte("OIMOSEAL1")

// GenerateKey は独立保管するX25519秘密鍵と、暗号化専用の公開鍵を作る。
func GenerateKey() (private, public []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// archiveCipher は共有秘密を用途・headerへ束縛し、コピーごとの暗号鍵を導出する。
func archiveCipher(shared, header []byte) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, shared, header, "OimoBBS sealed backup v1", 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func nonce(seq uint64) []byte { var n [12]byte; binary.BigEndian.PutUint64(n[4:], seq); return n[:] }
func associated(header []byte, seq uint64) []byte {
	return append(append([]byte{}, header...), nonce(seq)...)
}

// Seal は公開鍵だけで有界chunkを暗号化する。認証された終了chunkで切詰めを検出する。
func Seal(dst io.Writer, src io.Reader, public []byte) error {
	recipient, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return errArchive
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return errArchive
	}
	defer clear(shared)
	header := append(append([]byte{}, magic...), ephemeral.PublicKey().Bytes()...)
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return err
	}
	header = append(header, salt...)
	aead, err := archiveCipher(shared, header)
	if err != nil {
		return err
	}
	if err = writeAll(dst, header); err != nil {
		return err
	}
	buf := make([]byte, chunkSize)
	defer clear(buf)
	for seq := uint64(0); ; seq++ {
		n, readErr := io.ReadFull(src, buf)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
		sealed := aead.Seal(nil, nonce(seq), buf[:n], associated(header, seq))
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(sealed)))
		if err = writeAll(dst, size[:]); err != nil {
			return err
		}
		if err = writeAll(dst, sealed); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if seq == ^uint64(0) {
			return errArchive
		}
	}
}

// Open は全chunkと終端を認証する。不正・切詰め・余分な末尾・違う鍵を成功にしない。
// 呼出元は失敗時の部分出力を公開せず、削除する責務を持つ。
func Open(dst io.Writer, src io.Reader, private []byte) error {
	header := make([]byte, len(magic)+32+16)
	if _, err := io.ReadFull(src, header); err != nil || !bytes.Equal(header[:len(magic)], magic) {
		return errArchive
	}
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return errArchive
	}
	peer, err := ecdh.X25519().NewPublicKey(header[len(magic) : len(magic)+32])
	if err != nil {
		return errArchive
	}
	shared, err := k.ECDH(peer)
	if err != nil {
		return errArchive
	}
	defer clear(shared)
	aead, err := archiveCipher(shared, header)
	if err != nil {
		return err
	}
	for seq := uint64(0); ; seq++ {
		var size [4]byte
		if _, err = io.ReadFull(src, size[:]); err != nil {
			return errArchive
		}
		n := binary.BigEndian.Uint32(size[:])
		if n < uint32(aead.Overhead()) || n > chunkSize+uint32(aead.Overhead()) {
			return errArchive
		}
		sealed := make([]byte, n)
		if _, err = io.ReadFull(src, sealed); err != nil {
			return errArchive
		}
		plain, err := aead.Open(nil, nonce(seq), sealed, associated(header, seq))
		if err != nil {
			return errArchive
		}
		if len(plain) == 0 {
			var tail [1]byte
			n, err := src.Read(tail[:])
			if n != 0 || err != io.EOF {
				return errArchive
			}
			return nil
		}
		err = writeAll(dst, plain)
		clear(plain)
		if err != nil {
			return err
		}
		if seq == ^uint64(0) {
			return errArchive
		}
	}
}

func writeAll(dst io.Writer, b []byte) error {
	n, err := dst.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
