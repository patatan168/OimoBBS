// 保存済みスレッド条件から公開ID・SLIPを生成し、生IPは明示公開モードだけへ渡す。
package postinput

import (
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"strings"
)

// setDisplay は上位で確定した回線分類と分離鍵を使い、過去レスを再生成しない。
func setDisplay(post *domain.Post, input Input, policy domain.Policy, c BuildContext) error {
	ip, e := netip.ParseAddr(c.SourceIP)
	if e != nil || ip.Zone() != "" {
		return ErrInput
	}
	ip = ip.Unmap()
	if policy.IDMode == "required" || policy.RequireID || policy.IDMode == "optional" && input.Mail == "" {
		post.Identity.ID, e = identity.DailyID(c.PublicKey[:], c.Board, c.Now, ip)
		if e != nil {
			return e
		}
	} else if policy.IDMode == "optional" {
		post.Identity.ID = "???"
	}
	line := c.Network
	if line.Label == "" {
		line = identity.ClassifyNetwork(nil, ip)
	}
	if policy.SlipMode != "none" {
		post.Identity.Suffix = line.Suffix
		if policy.SlipMode == "checked" {
			post.Identity.Suffix = "0"
			if strings.Contains("OQo", line.Suffix) && line.Suffix != "" {
				post.Identity.Suffix = line.Suffix
			}
		}
		if policy.SlipMode == "feature" && strings.Contains("daprxeED", line.Suffix) {
			post.Identity.Suffix = "S"
		}
	}
	showName := strings.HasPrefix(policy.SlipMode, "vvv") || policy.RequireSlipHash || policy.RequirePublicIP
	hash := policy.SlipMode == "vvvvv" || policy.SlipMode == "vvvvvv" || policy.RequireSlipHash
	publicIP := policy.SlipMode == "vvvv" || policy.SlipMode == "vvvvvv" || policy.RequirePublicIP
	parts := []string{line.Label}
	if line.Kind == "fixed" {
		parts[0] = "ﾜｯﾁｮｲ"
	}
	if hash {
		if c.SlipNetKey == (domain.Hash{}) || c.SlipUAKey == (domain.Hash{}) {
			return ErrInput
		}
		value, e := identity.Slip(c.SlipNetKey[:], c.SlipUAKey[:], c.Board, c.Now, ip, line.Provider, c.AnonymousID, c.UserAgent)
		if e != nil {
			return e
		}
		parts = append(parts, value)
	}
	if showName {
		post.Identity.Slip = "(" + strings.Join(parts, " ") + ")"
	}
	if publicIP {
		post.Identity.PublicIP = ip.String()
	}
	return nil
}
