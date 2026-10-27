// 板の識別表示と回線分類表を稼働中の設定変更へ接続する。
package bootstrap

import (
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"slices"
	"strings"
)

// AdminIdentitySettings は新規スレッドの表示既定と、投稿時の回線分類表。
type AdminIdentitySettings struct {
	Access          *NetworkAccessSettings  `json:"network_access"`
	IDMode          string                  `json:"id_mode"`
	SlipMode        string                  `json:"slip_mode"`
	RequireIP       bool                    `json:"require_public_ip"`
	DisplayCommands *[]string               `json:"display_commands,omitempty"`
	AllowStrengthen bool                    `json:"allow_thread_strengthen"`
	Networks        []identity.NetworkClass `json:"networks"`
}

func (v AdminIdentitySettings) validate() error {
	if !slices.Contains([]string{"required", "optional", "hidden"}, v.IDMode) || !slices.Contains([]string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"}, v.SlipMode) || v.Networks == nil {
		return store.ErrCorrupt
	}
	if v.DisplayCommands != nil && postinput.ValidateDisplayCommands(*v.DisplayCommands) != nil {
		return store.ErrCorrupt
	}
	if e := v.Access.validate(); e != nil {
		return e
	}
	return identity.ValidateNetworks(v.Networks)
}
func identityEdit(v boardIdentity) AdminIdentitySettings {
	return AdminIdentitySettings{Access: v.Access, IDMode: v.IDMode, SlipMode: v.SlipMode, RequireIP: v.RequireIP, AllowStrengthen: v.AllowStrengthen, DisplayCommands: cloneDisplayCommands(v.DisplayCommands), Networks: append([]identity.NetworkClass{}, v.Networks...)}
}
func (v AdminBoardEdit) identitySettings() AdminIdentitySettings {
	if v.Identity != nil {
		return *v.Identity
	}
	return identityEdit(defaultBoardSettings().Identity)
}
func (v AdminIdentitySettings) saved() boardIdentity {
	return boardIdentity{Access: v.Access, IDMode: v.IDMode, SlipMode: v.SlipMode, RequireIP: v.RequireIP, AllowStrengthen: v.AllowStrengthen, DisplayCommands: cloneDisplayCommands(v.DisplayCommands), Networks: append([]identity.NetworkClass(nil), v.Networks...)}
}
func nondefaultIdentity(v boardIdentity) bool {
	return !reflect.DeepEqual(v, defaultBoardSettings().Identity)
}

// networkClass は板所有列で現在の分類表を読み、外部通信なしで接続元だけを照合する。
func (b *postingBoard) networkClass(ipString string) (identity.NetworkClass, error) {
	var v boardValue
	if e := strictjson.Decode(b.control.State().Rows["board:state"].Value, &v); e != nil {
		return identity.NetworkClass{}, e
	}
	ip, e := netip.ParseAddr(ipString)
	if e != nil {
		return identity.NetworkClass{}, e
	}
	return b.classifyNetwork(v.Settings.Identity.Networks, ip), nil
}
func validateIdentityReader(site siteState, board boardValue) error {
	if (specialNetworkRows(board.Settings.Identity.Networks) || specialNetworkAccess(board.Settings.Identity.Access)) && site.MinimumReader < specialNetworkReader {
		return store.ErrCorrupt
	}
	if (mixedNetworkRows(board.Settings.Identity.Networks) || mixedNetworkAccess(board.Settings.Identity.Access)) && site.MinimumReader < mixedNetworkReader {
		return store.ErrCorrupt
	}
	if board.Settings.Posting.AutoReports != nil && site.MinimumReader < 84 {
		return store.ErrCorrupt
	}
	if board.Settings.Presentation.Hidden != nil && site.MinimumReader < 76 {
		return store.ErrCorrupt
	}
	if board.Settings.Presentation.NoReprint != nil && site.MinimumReader < 75 {
		return store.ErrCorrupt
	}
	if board.Settings.Identity.DisplayCommands != nil && site.MinimumReader < 74 {
		return store.ErrCorrupt
	}
	if board.Settings.Identity.Access != nil && board.Settings.Identity.Access.DenyUnresolvedHost != nil && site.MinimumReader < 37 {
		return store.ErrCorrupt
	}
	if board.Settings.Identity.Access.extended() && site.MinimumReader < 34 {
		return store.ErrCorrupt
	}
	if (board.Settings.Identity.Access != nil || networkRowsRequire32(board.Settings.Identity.Networks)) && site.MinimumReader < 32 {
		return store.ErrCorrupt
	}
	for _, row := range board.Settings.Identity.Networks {
		if row.Provider != "" && site.MinimumReader < 70 {
			return store.ErrCorrupt
		}
	}
	if nondefaultIdentity(board.Settings.Identity) && site.MinimumReader < 29 {
		return store.ErrCorrupt
	}
	return nil
}

// observedUserAgent は観測済みの値を順序通り使う。自己申告UAは回線分類には使わない。
func observedUserAgent(headers []evidence.ObservedHeader) string {
	values := []string{}
	for _, h := range headers {
		if h.Name == "User-Agent" {
			for _, v := range h.Values {
				values = append(values, v.Display)
			}
		}
	}
	return strings.Join(values, " ")
}

// exemptCapConnectionRules は認証済み資格にだけ回線条件の拒否を外し、本文や追加枠を維持する。
func exemptCapConnectionRules(matched map[domain.ID]denialRule) {
	for id, r := range matched {
		if r.Effect.Type != "deny" && r.Effect.Type != "require_token" {
			continue
		}
		pure := true
		for _, c := range r.Conditions {
			if c.Field != "ip" && c.Field != "network" && c.Field != "line" {
				pure = false
				break
			}
		}
		if pure {
			delete(matched, id)
		}
	}
}

func ruleHasLine(rows []denialCondition) bool {
	for _, c := range rows {
		if c.Field == "line" {
			return true
		}
	}
	return false
}

// decodeNetworkClasses は表の各行にも重複・未知キー検査を適用する。
func decodeNetworkClasses(raw string, out *[]identity.NetworkClass) error {
	var value struct {
		Rows []identity.NetworkClass `json:"networks"`
	}
	if e := strictjson.Decode([]byte(`{"networks":`+raw+`}`), &value); e != nil {
		return e
	}
	*out = value.Rows
	return nil
}

// classifyNetwork は板の上書きを共通上書き・自動表より優先する。通信や状態変更はしない。
func (b *postingBoard) classifyNetwork(rows []identity.NetworkClass, ip netip.Addr) identity.NetworkClass {
	var classifier *identity.NetworkClassifier
	if b.liveNetworks != nil {
		classifier = b.liveNetworks.Load()
	}
	return classifier.Classify(rows, ip)
}

// cloneDisplayCommands は空一覧と未設定を区別したまま、設定の参照共有を避ける。
func cloneDisplayCommands(v *[]string) *[]string {
	if v == nil {
		return nil
	}
	out := append([]string{}, (*v)...)
	return &out
}

// UnmarshalJSON は旧API・receiptの識別設定を保持し、新規項目だけ省略を許可する。
func (v *AdminIdentitySettings) UnmarshalJSON(raw []byte) error {
	type plain AdminIdentitySettings
	normalized, err := withLegacyDisplayCommands(raw)
	if err != nil {
		return err
	}
	var next plain
	if err := strictjson.Decode(normalized, &next); err != nil {
		return err
	}
	*v = AdminIdentitySettings(next)
	return nil
}

// extendCommandEnabled はスレッド作成コマンドを一つ以上許可する板だけを公開する。
func (v boardIdentity) extendCommandEnabled() bool {
	if !v.AllowStrengthen {
		return false
	}
	if v.DisplayCommands == nil {
		return true
	}
	for _, name := range *v.DisplayCommands {
		if strings.HasPrefix(name, "!extend:") {
			return true
		}
	}
	return false
}
