// 初回管理者とパスワード再設定の停止中CLI。秘密は標準入力からだけ読む。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"strconv"
	"strings"
)

func runAdmin(args []string, input io.Reader, out, diagnostics io.Writer) error {
	if len(args) > 0 && args[0] == "reset-reading-access" {
		return runAdminReadingReset(args[1:], out, diagnostics)
	}
	if len(args) == 0 || (args[0] != "init" && args[0] != "reset-password" && args[0] != "create" && args[0] != "set-access") {
		return errors.New("usage: oimobbs admin init|reset-password|create|set-access|reset-reading-access --config <path> (account commands require --login)")
	}
	flags := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定JSON")
	login := flags.String("login", "", "管理ログイン名")
	display := flags.String("display", "", "管理者表示名（省略時はログイン名）")
	role := flags.String("role", "", "管理役割: moderator/board_admin/site_admin")
	boards := flags.String("boards", "", "担当板UUIDのカンマ区切り（空は担当なし）")
	permissions := flags.String("extra-permissions", "", "非公開情報の許可（private_reports.read/evidence.manage）のカンマ区切り")
	enabled := flags.Bool("enabled", true, "アカウントを有効にする")
	stdin := flags.Bool("password-stdin", false, "パスワード1行を標準入力から取得する")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if args[0] == "set-access" && *stdin {
		return errors.New("set-access does not accept password input")
	}
	if args[0] == "init" || args[0] == "reset-password" {
		invalidAccessFlag := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "role" || f.Name == "boards" || f.Name == "extra-permissions" || f.Name == "enabled" {
				invalidAccessFlag = true
			}
		})
		if invalidAccessFlag {
			return errors.New("access flags require create or set-access")
		}
	}
	if flags.NArg() != 0 || (!*stdin && args[0] != "set-access") || *login == "" {
		return errors.New("login and --password-stdin are required")
	}
	var raw []byte
	var e error
	if args[0] != "set-access" {
		raw, e = io.ReadAll(io.LimitReader(input, 515))
	}
	if e != nil {
		return e
	}
	defer clear(raw)
	secret := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(raw) > 514 || strings.ContainsAny(secret, "\r\n") {
		return errors.New("password input must be one line, at most 512 bytes")
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	repo, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		return e
	}
	if *display == "" {
		*display = *login
	}
	var result bootstrap.AdministratorInfo
	if args[0] == "create" || args[0] == "set-access" {
		access, err := parseAdministratorAccess(*role, *boards, *permissions, *enabled)
		if err != nil {
			return errors.Join(err, repo.Close())
		}
		if args[0] == "create" {
			result, e = repo.CreateAdministrator(*login, *display, secret, access)
		} else {
			result, e = repo.SetAdministratorAccess(*login, access)
		}
	} else {
		result, e = repo.ConfigureAdministrator(*login, *display, secret, args[0] == "reset-password")
	}
	e = errors.Join(e, repo.Close())
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}

// parseAdministratorAccess はCLIの担当集合をUUIDへ変換し、秘密と区別して扱う。
func parseAdministratorAccess(role, boards, permissions string, enabled bool) (bootstrap.AdministratorAccess, error) {
	v := bootstrap.AdministratorAccess{Role: role, Boards: []domain.ID{}, Permissions: []string{}, Enabled: enabled}
	if boards != "" {
		for _, raw := range strings.Split(boards, ",") {
			var id domain.ID
			if e := json.Unmarshal([]byte(strconv.Quote(raw)), &id); e != nil {
				return v, e
			}
			v.Boards = append(v.Boards, id)
		}
	}
	if permissions != "" {
		v.Permissions = strings.Split(permissions, ",")
	}
	return v, nil
}

// runAdminReadingReset はサイト排他を取得し、停止中の管理画面の接続制限を解除する。
func runAdminReadingReset(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("admin reset-reading-access", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	cfg, err := bootstrap.LoadConfig(*config)
	if err != nil {
		return err
	}
	repo, err := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		return err
	}
	err = errors.Join(repo.ResetAdminReadingAccess(), repo.Close())
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"status": "admin_reading_access_disabled"})
}
