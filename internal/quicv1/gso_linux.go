//go:build linux

// LinuxのUDP segmentationを使用し、暗号化済みの独立packetを一つのsyscallへまとめる。
package quicv1

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/sys/unix"
)

func gsoControl(size int) []byte {
	h := unix.Cmsghdr{Level: unix.SOL_UDP, Type: unix.UDP_SEGMENT}
	h.SetLen(unix.CmsgLen(2))
	var b bytes.Buffer
	_ = binary.Write(&b, binary.NativeEndian, h)
	out := make([]byte, unix.CmsgSpace(2))
	copy(out, b.Bytes())
	binary.NativeEndian.PutUint16(out[unix.CmsgLen(0):], uint16(size))
	return out
}
