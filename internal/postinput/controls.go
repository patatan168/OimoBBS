// 入力由来の識別命令を生文字だけから解析し、表示の弱化と実体参照からの命令化を防ぐ。
package postinput

import (
	"oimobbs/internal/domain"
	"slices"
	"strings"
)

// Controls は名前欄の公開表示追加、またはスレ作成時の!extend。秘密は含まない。
type Controls struct {
	ID     string `json:"id"`
	Slip   string `json:"slip"`
	Thread bool   `json:"thread"`
}

func validSlip(s string) bool {
	return slices.Contains([]string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"}, s)
}

func parseControls(name, body string, create bool) (string, string, *Controls, error) {
	c := Controls{}
	kept := []string{}
	found := false
	for _, token := range strings.Fields(name) {
		switch {
		case strings.HasPrefix(token, "!id:"):
			if c.ID != "" || token != "!id:on" && token != "!id:none" && token != "!id:ignore" {
				return "", "", nil, ErrInput
			}
			// 非表示の名前欄命令は有料資格が必要。未実装の資格で許可しない。
			if token != "!id:on" {
				return "", "", nil, ErrUnsupported
			}
			c.ID = strings.TrimPrefix(token, "!id:")
			found = true
		case strings.HasPrefix(token, "!slip:"):
			mode := strings.TrimPrefix(token, "!slip:")
			if c.Slip != "" || !validSlip(mode) {
				return "", "", nil, ErrInput
			}
			c.Slip = mode
			found = true
		default:
			kept = append(kept, token)
		}
	}
	if found {
		name = strings.Join(kept, " ")
	}
	if create && strings.HasPrefix(body, "!extend:") {
		lines := strings.Split(body, "\n")
		for i := 0; i < len(lines) && i < 5 && strings.HasPrefix(lines[i], "!extend:"); i++ {
			parts := strings.Split(lines[i], ":")
			if len(parts) != 5 || parts[1] != "checked" && parts[1] != "none" && parts[1] != "default" && parts[1] != "" || !validSlip(parts[2]) && parts[2] != "default" && parts[2] != "" {
				return "", "", nil, ErrInput
			}
			if parts[3] != "" || parts[4] != "" {
				return "", "", nil, ErrUnsupported
			}
			if i == 0 {
				if found {
					return "", "", nil, ErrInput
				}
				c.Thread = true
				if parts[2] != "default" {
					c.Slip = parts[2]
				}
				if parts[1] == "checked" {
					c.ID = "on"
				}
				if parts[1] == "none" {
					c.ID = "off"
				}
			}
		}
		body = strings.Join(lines[1:], "\n")
		found = true
	}
	if found {
		return name, body, &c, nil
	}
	return name, body, nil, nil
}

// DisplayPolicy は保存済み条件を弱めない表示追加を検査する。Thread=trueは作成時だけ使用する。
func DisplayPolicy(p domain.Policy, c *Controls, allowed bool) (domain.Policy, error) {
	if c == nil {
		return p, nil
	}
	if !allowed || c.ID != "" && c.ID != "on" && c.ID != "off" || c.Slip != "" && !validSlip(c.Slip) {
		return p, ErrInput
	}
	if c.ID == "off" {
		if !c.Thread {
			return p, ErrUnsupported
		}
		if p.IDMode == "required" || p.RequireID {
			return p, ErrInput
		}
		p.IDMode = "hidden"
	}
	if c.ID == "on" {
		p.IDMode = "required"
	}
	if c.Slip != "" {
		next := p
		next.SlipMode = c.Slip
		if slipRank(c.Slip) < slipRank(p.SlipMode) {
			return p, ErrInput
		}
		p = next
	}
	return p, nil
}

// slipRank は公開資料の表示順で弱化を判定し、詳細末尾から簡易末尾への逆行も防ぐ。
func slipRank(mode string) int {
	return slices.Index([]string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"}, mode)
}

// HasPublicIP は必須bitか表示方式が完全IPを公開することを返す。
func HasPublicIP(p domain.Policy) bool {
	return p.RequirePublicIP || p.SlipMode == "vvvv" || p.SlipMode == "vvvvvv"
}

// HasSlipHash は必須bitか表示方式が週hashを公開することを返す。
func HasSlipHash(p domain.Policy) bool {
	return p.RequireSlipHash || p.SlipMode == "vvvvv" || p.SlipMode == "vvvvvv"
}
