// QRの境界長・余白・画像形式と、任意の独立した読み取り処理による復号を検証する。
package adminauth

import (
	"bytes"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEnrollmentQR(t *testing.T) {
	for _, length := range []int{1, 213, 214, 412, 413, 666, 667, 997} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			text := strings.Repeat("a", length)
			encoded, err := EnrollmentQR(text)
			if err != nil {
				t.Fatal(err)
			}
			img, err := png.Decode(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			side := 260
			if length > 213 {
				side = 340
			}
			if length > 412 {
				side = 420
			}
			if length > 666 {
				side = 500
			}
			if img.Bounds().Dx() != side || img.Bounds().Dy() != side {
				t.Fatalf("unexpected size %v", img.Bounds())
			}
			for y := 0; y < side; y++ {
				for x := 0; x < side; x++ {
					if x >= 16 && y >= 16 && x < side-16 && y < side-16 {
						continue
					}
					r, g, b, _ := img.At(x, y).RGBA()
					if r != 65535 || g != 65535 || b != 65535 {
						t.Fatal("quiet zone is not white")
					}
				}
			}
		})
	}
	for _, text := range []string{"", strings.Repeat("x", 998)} {
		if _, err := EnrollmentQR(text); err == nil {
			t.Fatal("accepted unsupported length")
		}
	}
}

// TestEnrollmentQRIndependentDecoder は製品依存に含めない読み取り専用ツールとの往復を検査する。
func TestEnrollmentQRIndependentDecoder(t *testing.T) {
	node, decoder := os.Getenv("OIMO_BROWSER_NODE"), os.Getenv("OIMO_QR_DECODER")
	if node == "" || decoder == "" {
		t.Skip("independent QR decoder not configured")
	}
	for _, length := range []int{1, 213, 214, 412, 413, 666, 667, 997} {
		text := strings.Repeat("abcXYZ123%&", 100)[:length]
		encoded, err := EnrollmentQR(text)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "qr.png")
		if err = os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(node, decoder, path)
		decoded, err := command.Output()
		if err != nil {
			t.Fatalf("length %d: %v", length, err)
		}
		if string(decoded) != text {
			t.Fatalf("QR decode mismatch for length %d", length)
		}
	}
}
