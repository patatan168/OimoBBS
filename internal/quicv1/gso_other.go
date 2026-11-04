//go:build !linux

// UDP segmentation非対応OSでは通常の独立datagram送信を使用する。
package quicv1

func gsoControl(int) []byte { return nil }
