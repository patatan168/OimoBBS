// 設計16の板設定を、省略キーのない固定型で保存する。編集範囲は管理接続側で制限する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
)

type boardSettings struct {
	Version      domain.U64        `json:"version"`
	Input        boardInput        `json:"input"`
	Identity     boardIdentity     `json:"identity"`
	Posting      boardPosting      `json:"posting"`
	Thread       boardThread       `json:"thread"`
	Retention    boardRetention    `json:"retention"`
	Presentation boardPresentation `json:"presentation"`
	Extensions   boardExtensions   `json:"extensions"`
}
type boardInput struct {
	NameBytes    uint32 `json:"name_bytes"`
	MailBytes    uint32 `json:"mail_bytes"`
	TitleBytes   uint32 `json:"title_bytes"`
	BodyBytes    uint32 `json:"body_bytes"`
	BodyLines    uint32 `json:"body_lines"`
	Noname       string `json:"noname"`
	NameRequired bool   `json:"name_required"`
	ForceNoname  bool   `json:"force_noname"`
	HideMail     bool   `json:"hide_mail"`
}
type boardIdentity struct {
	Access          *NetworkAccessSettings  `json:"network_access"`
	Networks        []identity.NetworkClass `json:"networks"`
	IDMode          string                  `json:"id_mode"`
	SlipMode        string                  `json:"slip_mode"`
	RequireIP       bool                    `json:"require_public_ip"`
	DisplayCommands *[]string               `json:"display_commands,omitempty"`
	AllowStrengthen bool                    `json:"allow_thread_strengthen"`
	AllowFusianasan bool                    `json:"allow_fusianasan"`
	Classifier      *domain.ID              `json:"classifier_version"`
}
type boardPosting struct {
	AutoReports *boardAutoReportSettings `json:"auto_reports,omitempty"`
	Create      string                   `json:"create_policy"`
	Reply       string                   `json:"reply_policy"`
	Cookie      string                   `json:"cookie_mode"`
	TokenWait   uint32                   `json:"token_wait_seconds"`
	Commands    []string                 `json:"commands"`
	ForceAge    bool                     `json:"force_age"`
	AllowSoko   bool                     `json:"allow_soko"`
}
type boardThread struct {
	PostLimit   uint32     `json:"user_post_limit"`
	DATLimit    domain.U64 `json:"dat_user_limit"`
	StopGrace   uint32     `json:"stop_grace_seconds"`
	EndMessage  string     `json:"end_message"`
	AutoNext    bool       `json:"auto_next"`
	AllowPinned bool       `json:"allow_pinned"`
}
type boardRetention struct {
	Target         uint32 `json:"active_target"`
	Trigger        uint32 `json:"active_trigger"`
	InfantSeconds  uint32 `json:"infant_seconds"`
	InfantMinUsers uint32 `json:"infant_min_users"`
	IdleSeconds    uint32 `json:"idle_seconds"`
	AgeSeconds     uint32 `json:"age_seconds"`
}
type boardColors struct {
	Title       string `json:"title"`
	Background  string `json:"background"`
	Form        string `json:"form"`
	Menu        string `json:"menu"`
	Thread      string `json:"thread"`
	Text        string `json:"text"`
	Name        string `json:"name"`
	Subject     string `json:"subject"`
	Link        string `json:"link"`
	ActiveLink  string `json:"active_link"`
	VisitedLink string `json:"visited_link"`
}
type ruleParagraph struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}
type boardPresentation struct {
	Hidden        *bool           `json:"hidden,omitempty"`
	NoReprint     *bool           `json:"no_reprint,omitempty"`
	TopThreads    uint32          `json:"top_threads"`
	TopResponses  uint32          `json:"top_responses"`
	MenuThreads   uint32          `json:"menu_threads"`
	ShowMsec      bool            `json:"show_msec"`
	Weekdays      []string        `json:"weekday_labels"`
	Colors        boardColors     `json:"colors"`
	BannerURL     *string         `json:"banner_url"`
	BannerLink    *string         `json:"banner_link"`
	BackgroundURL *string         `json:"background_url"`
	Rules         []ruleParagraph `json:"rules"`
}
type boardExtensions struct {
	Enabled            []string   `json:"enabled"`
	DictionaryRevision domain.U64 `json:"dictionary_revision"`
}

func defaultBoardSettings() boardSettings {
	return boardSettings{
		Version:      1,
		Input:        boardInput{NameBytes: 96, MailBytes: 64, TitleBytes: 128, BodyBytes: 4096, BodyLines: 60, Noname: "名無しさん"},
		Identity:     boardIdentity{IDMode: "required", SlipMode: "none", AllowStrengthen: true},
		Posting:      boardPosting{Create: "anyone", Reply: "anyone", Cookie: "required", Commands: []string{"extend", "id", "slip", "status", "chkbbx"}},
		Thread:       boardThread{PostLimit: 1000, DATLimit: 524288, StopGrace: 3600, EndMessage: "このスレッドは終了しました。"},
		Retention:    boardRetention{Target: 700, Trigger: 735},
		Presentation: boardPresentation{TopThreads: 20, TopResponses: 5, MenuThreads: 50, ShowMsec: true, Weekdays: []string{"日", "月", "火", "水", "木", "金", "土"}, Colors: boardColors{Title: "#000000", Background: "#FFFFFF", Form: "#FFFFFF", Menu: "#FFFFFF", Thread: "#FFFFFF", Text: "#000000", Name: "#008000", Subject: "#000000", Link: "#0000EE", ActiveLink: "#FF0000", VisitedLink: "#551A8B"}, Rules: []ruleParagraph{}},
		Extensions:   boardExtensions{Enabled: []string{}, DictionaryRevision: 1},
	}
}
