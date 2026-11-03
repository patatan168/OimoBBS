// 暗号化コピーの固定メタデータとSSH転送の要求・完了応答を厳密に検査する。
package sealedbackup

import (
	"errors"
	"fmt"
	"oimobbs/internal/strictjson"
	"path"
	"regexp"
	"strings"
)

const metadataLimit = 8192

var backupName = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)
var hashName = regexp.MustCompile(`^[0-9a-f]{64}$`)
var generationName = regexp.MustCompile(`^backup-[0-9a-f]{32}-[0-9a-f]{64}$`)
var unfinishedName = regexp.MustCompile(`^\.(incoming|expired)-backup-[0-9a-f]{32}-[0-9a-f]{64}-[0-9a-f]{32}$`)
var destinationName = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_.-]*):(/[A-Za-z0-9_./-]+)$`)

// Manifest は暗号文のhashと元の期限だけを持つ。受信側へ復号秘密鍵は渡さない。
type Manifest struct {
	Name         string `json:"name"`
	SHA256       string `json:"sha256"`
	ExpiresAtNS  int64  `json:"expires_at_ns"`
	RestoreReady bool   `json:"restore_ready"`
}

// Validate は名前・hash・期限の型検査後の値域を確認する。期限の延長は行わない。
func (m Manifest) Validate() error {
	if !backupName.MatchString(m.Name) || !hashName.MatchString(m.SHA256) || m.ExpiresAtNS <= 0 {
		return errors.New("invalid sealed backup manifest")
	}
	return nil
}

// Generation は既存の世代を置換しない固定長の保存名を返す。
func (m Manifest) Generation() string { return m.Name + "-" + m.SHA256 }

// Header は暗号文の長さと固定メタデータを結合する転送要求。
type Header struct {
	Protocol int      `json:"protocol"`
	Manifest Manifest `json:"manifest"`
	Size     int64    `json:"size"`
}

// ParseHeader は未知・欠落・重複キー・型違い・過大JSONを受信前に拒否する。
func ParseHeader(raw []byte) (Header, error) {
	var h Header
	e := strictjson.DecodeLimit(raw, &h, metadataLimit)
	if e != nil {
		return h, e
	}
	if h.Protocol != 1 || h.Size <= 0 {
		return h, errors.New("invalid backup transfer protocol or size")
	}
	return h, h.Manifest.Validate()
}

// Acknowledgement は親directoryの同期後だけ返す設置結果。
type Acknowledgement struct {
	Protocol   int    `json:"protocol"`
	Status     string `json:"status"`
	Generation string `json:"generation"`
	SHA256     string `json:"sha256"`
}

func acknowledgement(m Manifest, status string) Acknowledgement {
	return Acknowledgement{1, status, m.Generation(), m.SHA256}
}

// ParseDestination はOpenSSHのaliasと正規の絶対保存先を返す。オプション混入とshell構文を拒否する。
func ParseDestination(value string) (string, string, error) {
	m := destinationName.FindStringSubmatch(value)
	if m == nil || strings.Contains(m[2], "//") {
		return "", "", errors.New("destination requires SSH alias and canonical absolute directory")
	}
	for _, p := range strings.Split(m[2], "/") {
		if p == "." || p == ".." {
			return "", "", fmt.Errorf("invalid destination path")
		}
	}
	return m[1], path.Clean(m[2]), nil
}
