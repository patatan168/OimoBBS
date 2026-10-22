// 事業者別表示の選択肢。ASNの企業名とサービス固有の分類を混同しない。
package bootstrap

import (
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// networkPreset は管理画面とサーバー側で共用する表示・取得の既定値。
type networkPreset struct {
	ID, Name, Kind, Label, Suffix string
	ASN                           uint32
}

var networkSourcePresets = append([]networkPreset{
	{"ocn", "OCN（AS4713・固定/MVNO混在）", "mixed", "ﾜｯﾁｮｲ", "0", 4713},
	{"docomo", "docomo（AS9605・携帯推定）", "mobile", "ｽﾌﾟｯｯ", "d", 9605},
	{"rakuten", "楽天モバイル（AS138384・携帯推定）", "mobile", "ﾃﾃﾝﾃﾝﾃﾝ", "M", 138384},
	{"kddi", "KDDI（AS2516・固定/携帯混在）", "mixed", "KDDI", "0", 2516},
	{"softbank", "SoftBank（AS17676・固定/携帯混在）", "mixed", "SoftBank", "0", 17676},
	{"iij", "IIJ（AS2497・用途混在）", "unknown", "IIJ", "0", 2497},
	{"optage", "OPTAGE（AS17511・固定/MVNO混在）", "mixed", "OPTAGE", "0", 17511},
}, append(append(domesticNetworkPresets, vpnProviderPresets...), specialNetworkPresets...)...)

// defaultNetworkSources は無料の共通ASNデータをそのまま使える標準取得元を返す。
// 固定・携帯の混在が確認済みのASNはmixed、用途未確定はunknownを使う。
func defaultNetworkSources() []NetworkSource {
	rows := make([]NetworkSource, 0, len(networkSourcePresets))
	for _, p := range networkSourcePresets {
		rows = append(rows, NetworkSource{Name: p.Name, Type: "asn", ASN: p.ASN, Kind: p.Kind, Label: p.Label, Suffix: p.Suffix, Provider: presetProvider(p.ID)})
	}
	return append(rows, defaultAccessSources()...)
}

var networkDisplayPresets = []networkPreset{
	{"fixed", "固定回線", "fixed", "ﾜｯﾁｮｲ", "0", 0},
	{"docomo", "docomo", "mobile", "ｽﾌﾟｯｯ", "d", 0},
	{"mopera", "docomo mopera", "mobile", "ﾍﾟﾗﾍﾟﾗ", "D", 0},
	{"au", "au / WiMAX2+", "mobile", "ｱｳｱｳ", "a", 0},
	{"softbank-iphone", "SoftBank iPhone（確認済み範囲用）", "mobile", "ｻｻｸｯﾃﾛ", "p", 0},
	{"softbank-android", "SoftBank Android（確認済み範囲用）", "mobile", "ｵｯﾍﾟｹ", "r", 0},
	{"softbank-access", "SoftBank accessinternet", "mobile", "ｱ-ｸｾ-", "x", 0},
	{"ymobile-emb", "Y!mobile emb", "mobile", "ｲﾓｲﾓ", "e", 0},
	{"ymobile-emnet", "Y!mobile EMNet", "mobile", "ｴ-ｲﾓ", "E", 0},
	{"iijmio", "IIJmio", "mvno", "ﾌﾞｰｲﾓ", "M", 0},
	{"bmobile", "日本通信 / b-mobile", "mvno", "ﾍﾞｰｲﾓ", "M", 0},
	{"mineo", "mineo", "mvno", "ｵｲｺﾗﾐﾈｵ", "M", 0},
	{"ocn-mobile", "OCN モバイル ONE系", "mvno", "ﾜﾝﾄﾝｷﾝ", "M", 0},
	{"ocn-mvno", "OCN回線の他社MVNO", "mvno", "ﾊﾞｯﾄﾝｷﾝ", "M", 0},
	{"uq-mobile", "UQ mobile（MVNO用）", "mvno", "ｱｳｱｳｸｰ", "M", 0},
	{"biglobe-mobile", "BIGLOBE モバイル", "mvno", "ﾄﾞｺｸﾞﾛ", "M", 0},
	{"rakuten-mvno", "楽天モバイル MVNO", "mvno", "ﾗｸｯﾍﾟﾍﾟ", "M", 0},
	{"rakuten-mno", "楽天モバイル MNO", "mobile", "ﾃﾃﾝﾃﾝﾃﾝ", "M", 0},
	{"docomo-wifi", "docomo Wi-Fi", "wifi", "ｴﾑｿﾞﾈ", "F", 0},
	{"au-wifi", "au Wi-Fi", "wifi", "ｱｳｳｨﾌ", "F", 0},
	{"wi2", "Wi2", "wifi", "ﾜｲﾜｲ", "F", 0},
	{"foreign", "国外IP（登録情報による推定）", "foreign", "ZZ", "X", 0},
	{"vpn", "既知VPN", "vpn", "ｺﾝﾆﾁﾜ", "8", 0},
	{"ocn-fixed", "OCN 固定回線", "fixed", "ﾜｯﾁｮｲ", "0", 0},
	{"kddi-fixed", "KDDI 固定回線", "fixed", "ﾜｯﾁｮｲ", "0", 0},
	{"softbank-fixed", "SoftBank 固定回線", "fixed", "ﾜｯﾁｮｲ", "0", 0},
	{"iij-fixed", "IIJ 固定回線", "fixed", "ﾜｯﾁｮｲ", "0", 0},
	{"optage-fixed", "OPTAGE 固定回線", "fixed", "ﾜｯﾁｮｲ", "0", 0},
	{"mixed", "固定・携帯混在", "mixed", "ﾜｯﾁｮｲ", "0", 0},
	{"academic", "大学・学術網", "academic", "ｶﾞｯｸｼ", "6", 0},
	{"school", "学校", "school", "ﾎﾞﾝﾎﾞﾝ", "7", 0},
	{"government", "官公庁", "government", "ｺﾑｲｰﾝ", "G", 0},
	{"business", "企業内回線", "business", "ｼｬﾁｰｸ", "C", 0},
	{"hosting", "クラウド・VPS", "hosting", "ｸﾓﾉｳｴ", "V", 0},
	{"satellite", "衛星回線", "satellite", "ｳﾁｭｰ", "U", 0},
	{"nifmo", "NifMo（確認済み範囲用）", "mvno", "ﾆｬﾌﾆｬ", "M", 0},
	{"libmo", "LIBMO（確認済み範囲用）", "mvno", "ﾌﾞﾓｰ", "M", 0},
	{"linksmate", "LinksMate（確認済み範囲用）", "mvno", "ｸｽﾏﾃ", "M", 0},
	{"soracom", "SORACOM（確認済み範囲用）", "mvno", "ｿﾗﾉｲﾛ", "M", 0},
	{"tone", "トーンモバイル（確認済み範囲用）", "mvno", "ﾄﾝﾓｰ", "M", 0},
	{"wirelessgate", "ワイヤレスゲート（確認済み範囲用）", "mvno", "ﾜｷｹﾞｰ", "M", 0},
	{"mobilekun", "＠モバイルくん。（確認済み範囲用）", "mvno", "ｲﾙｸﾝ", "M", 0},
	{"mvnonet", "mvno.net（確認済み範囲用）", "mvno", "ｱﾒ", "M", 0},
	{"freemobile", "FreeMobile（確認済み範囲用）", "wifi", "ﾌﾘﾓﾊﾞ", "F", 0},
	{"freespot", "FREESPOT（確認済み範囲用）", "wifi", "ﾌﾘｽﾎﾟ", "F", 0},
	{"fon", "FON（確認済み範囲用）", "wifi", "ﾌｫﾝﾌｫﾝ", "F", 0},
	{"nttbp", "NTT BP（確認済み範囲用）", "wifi", "ﾐｶｶｳｨﾌｨ", "F", 0},
	{"flets-spot", "FLET'S SPOT（確認済み範囲用）", "wifi", "ﾌﾟﾗｳｨﾌｨ", "F", 0},
	{"inflight", "機内Wi-Fi（確認済み範囲用）", "wifi", "ｱﾅﾌｧｰｲ", "A", 0},
	{"maritime", "船舶用衛星通信 SafeComNet（確認済み範囲用）", "satellite", "ﾀﾆｯｸ", "S", 0},
}

// NetworkCategory はワッチョイ表示を基準に追加できるカテゴリー。回線区分は規制との対応を表す。
type NetworkCategory struct {
	Provider    string `json:"provider"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Suffix      string `json:"suffix"`
	Description string `json:"description"`
}

// validNetworkDescription は改行可能な管理用メモを有界にし、制御文字を拒否する。
func validNetworkDescription(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 1024 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

var networkCategoryID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

func defaultNetworkCategories() []NetworkCategory {
	rows := make([]NetworkCategory, 0, len(networkDisplayPresets))
	for _, p := range networkDisplayPresets {
		description := p.Label + " は「" + p.Name + "」を表す呼び名です。"
		if specialNetworkKind(p.Kind) {
			description += " 接続者の所属・所在地の証明には使えません。"
		}
		if p.Kind == "hosting" || p.ID == "satellite" {
			description += " OimoBBS独自の5ch風呼称です。クラウドはID末尾V、衛星はUです。"
		}
		if p.ID == "foreign" {
			description = "国外はUS・DEなど英字2文字の登録国・地域コードを自動表示します。ZZは国コード不明。ID末尾はXです。"
		}
		if p.ID == "vpn" {
			description = "ｺﾝﾆﾁﾜ はVPNと判定された回線を表します。ID末尾は8です。"
		}
		rows = append(rows, NetworkCategory{ID: p.ID, Name: p.Name, Kind: p.Kind, Label: p.Label, Suffix: p.Suffix, Description: description, Provider: categoryProvider(p.ID)})
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.Provider] = true
	}
	for _, preset := range networkSourcePresets {
		provider := presetProvider(preset.ID)
		if seen[provider] {
			continue
		}
		seen[provider] = true
		name, _, _ := strings.Cut(preset.Name, "（AS")
		rows = append(rows, NetworkCategory{ID: provider, Provider: provider, Name: name, Kind: preset.Kind, Label: preset.Label, Suffix: preset.Suffix, Description: "事業者のASNから取得する推定です。共有する上流回線やIPoEでは契約サービスまで区別できない場合があります。"})
	}
	return rows
}

// presetProvider は同一事業者の複数ASNを同じプロバイダ識別キーへ束ねる。
func presetProvider(id string) string {
	index := strings.LastIndex(id, "-as")
	if index >= 0 {
		if _, err := strconv.ParseUint(id[index+3:], 10, 32); err == nil {
			return id[:index]
		}
	}
	return id
}

func validateNetworkCategories(rows []NetworkCategory) error {
	if rows == nil || len(rows) > networkCategoryLimit {
		return store.ErrCorrupt
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if !networkCategoryID.MatchString(row.ID) || row.ID == "custom" || seen[row.ID] || !validName(row.Name) || !validNetworkDescription(row.Description) || identity.ValidateNetworks([]identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: row.Kind, Label: row.Label, Suffix: row.Suffix, Provider: row.Provider}}) != nil {
			return store.ErrCorrupt
		}
		seen[row.ID] = true
	}
	return nil
}

func (p networksPage) SourcePresets() []networkPreset    { return networkSourcePresets }
func (p networksPage) DisplayPresets() []NetworkCategory { return p.View.Config.Categories }

// OriginalDisplayPresets は管理者の編集後も初期表示の元の意味を参照できるようにする。
func (p networksPage) OriginalDisplayPresets() []networkPreset { return networkDisplayPresets }

// applyDisplayPreset は保存済みカテゴリーの表示を確定する。customは手入力を維持する。
func applyDisplayPreset(rows []NetworkCategory, id string, kind, label, suffix *string) error {
	if id == "" || id == "custom" {
		return nil
	}
	for _, preset := range rows {
		if preset.ID == id {
			*kind, *label, *suffix = preset.Kind, preset.Label, preset.Suffix
			return nil
		}
	}
	return errNetworkData
}

// CategoryForm は保存に失敗した編集入力を保持する。
func (p networksPage) CategoryForm(index int, row NetworkCategory) networkRowForm {
	fields := url.Values{"index": {strconv.Itoa(index)}, "category_id": {row.ID}, "name": {row.Name}, "kind": {row.Kind}, "label": {row.Label}, "suffix": {row.Suffix}, "description": {row.Description}, "provider": {row.Provider}}
	if p.Fields.Get("action") == "category_save" && p.Fields.Get("index") == strconv.Itoa(index) {
		fields = p.Fields
	}
	return networkRowForm{Page: p, Fields: fields}
}
func (p networksPage) NewCategoryForm() networkRowForm {
	return p.CategoryForm(-1, NetworkCategory{Kind: "unknown", Suffix: "0"})
}

// categoryProvider は標準カテゴリーの表示名と独立したプロバイダキーを返す。
func categoryProvider(id string) string {
	switch id {
	case "fixed", "mixed", "foreign", "vpn", "academic", "school", "government", "business", "hosting", "satellite":
		return ""
	case "mopera", "docomo-wifi":
		return "docomo"
	case "softbank-iphone", "softbank-android", "softbank-access", "ymobile-emb", "ymobile-emnet":
		return "softbank"
	case "au", "au-wifi", "uq-mobile":
		return "kddi"
	case "iijmio":
		return "iij"
	case "mineo":
		return "optage"
	case "ocn-mobile", "ocn-mvno":
		return "ocn"
	case "rakuten-mno", "rakuten-mvno":
		return "rakuten"
	}
	return strings.TrimSuffix(id, "-fixed")
}

// applyProviderPreset は同一表示名の固定回線でもカテゴリーごとの識別キーを採用する。
func applyProviderPreset(rows []NetworkCategory, id string, provider *string) {
	if *provider != "" || id == "" || id == "custom" {
		return
	}
	for _, row := range rows {
		if row.ID == id {
			*provider = row.Provider
			return
		}
	}
}

// SummaryName は回線一覧でAS番号・推定注記を重複させず、編集時には元の名前を保持する。
func (s NetworkSource) SummaryName() string {
	name, _, _ := strings.Cut(s.Name, "（AS")
	return name
}
