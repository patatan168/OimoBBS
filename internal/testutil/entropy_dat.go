// サイズ・文字種・乱数系列の異なる高エントロピーDATを検証用に生成する。稼働データは読まない。
package testutil

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// EntropyDATFixture はmaxBytes以下で完結するASCIIのDATを作る。各本文は512文字。
// kindはhex/hex-fields/base64/ascii。maxBytesが一行未満か、kindが不正ならpanicする。
func EntropyDATFixture(kind string, maxBytes int, seed uint64) []byte {
	alphabet := entropyDATAlphabet(kind)
	rng := rand.New(rand.NewPCG(seed, seed+23))
	var out strings.Builder
	for i := 1; ; i++ {
		var body [512]byte
		for j := range body {
			if kind == "hex-fields" && j%65 == 64 {
				body[j] = ' '
			} else {
				body[j] = alphabet[rng.IntN(len(alphabet))]
			}
		}
		title := ""
		if i == 1 {
			title = "entropy fixture"
		}
		line := fmt.Sprintf("user%d<>sage<>2026/11/01(Sun) 09:%02d:%02d ID:%08x<>%s<>%s\n", i%31, i/60%60, i%60, rng.Uint32(), body[:], title)
		if out.Len()+len(line) > maxBytes {
			break
		}
		out.WriteString(line)
	}
	if out.Len() == 0 {
		panic("entropy DAT size too small")
	}
	return []byte(out.String())
}

// entropyDATAlphabet はDATの区切り・改行と衝突しない本文用の文字集合を返す。
func entropyDATAlphabet(kind string) string {
	switch kind {
	case "hex", "hex-fields":
		return "0123456789abcdef"
	case "base64":
		return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	case "ascii":
		var out strings.Builder
		for i := byte(33); i <= 126; i++ {
			if i != '<' && i != '>' {
				out.WriteByte(i)
			}
		}
		return out.String()
	default:
		panic("unknown entropy DAT kind")
	}
}
