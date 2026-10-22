// systemdへの新規登録を行う。設定・バイナリは利用者所有のまま、unitの保存だけsudoで行う。
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"oimobbs/internal/bootstrap"
)

const serviceName = "oimobbs.service"
const servicePath = "/etc/systemd/system/" + serviceName
const serviceWriteScript = `set -euC; umask 022; cat > "$1"`

// servicePreflight は初期化前にOS・既存サービス・sudoの使用可否を確認する。
func servicePreflight() error {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return errors.New("サービス登録はsystemdのあるLinuxで、sudoを使える一般ユーザーから実行してください")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemdが起動していません。--install-serviceを外して実行してください")
	}
	state, err := exec.Command("systemctl", "show", "--property=LoadState", "--value", serviceName).Output()
	if err != nil {
		return fmt.Errorf("既存サービスを確認できません: %w", err)
	}
	if strings.TrimSpace(string(state)) != "not-found" {
		return errors.New("oimobbs.serviceは登録済みです。既存サービスを上書きしません")
	}
	if _, err := os.Lstat(servicePath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("既存のunitファイルは上書きしません: " + servicePath)
	}
	fmt.Println("systemdへの登録権限を確認しています（sudo）。")
	return serviceCommand(nil, "sudo", "-v")
}

// unitQuote はunitの引用・specifierを保護する。ExecStartでは環境変数展開も無効化する。
func unitQuote(value string) (string, error) {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("サービスのパスに制御文字は使えません")
	}
	value = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(value)
	return `"` + value + `"`, nil
}

// serviceUnit は現在のUID/GIDで動くunitを生成する。HTTPは検証用起動を使う。
func serviceUnit(binary, config string, validation bool, uid, gid int) (string, error) {
	if uid <= 0 || gid <= 0 {
		return "", errors.New("rootのUID/GIDではサービスを登録できません")
	}
	if strings.ContainsAny(binary, "\\\"'`$*?<>|&;") {
		return "", errors.New("サービスのバイナリパスには引用符やシェルの特殊文字を使えません")
	}
	values := []string{binary, config}
	for i, value := range values {
		if !filepath.IsAbs(value) {
			return "", errors.New("サービスには絶対パスが必要です")
		}
		quoted, err := unitQuote(value)
		if err != nil {
			return "", err
		}
		values[i] = quoted
	}
	// WorkingDirectoryはExecStartとは異なり、引用符をパスの一部として扱う。
	directory := filepath.Dir(config)
	if strings.TrimSpace(directory) != directory {
		return "", errors.New("サービスの作業ディレクトリの末尾に空白は使えません")
	}
	directory = strings.ReplaceAll(directory, "%", "%%")
	mode, admin := "serve", ""
	if validation {
		mode, admin = "validation-serve", " --admin"
	}
	return fmt.Sprintf(`[Unit]
Description=OimoBBS
After=network.target

[Service]
Type=exec
User=%d
Group=%d
WorkingDirectory=%s
ExecStart=:%s %s --config %s%s
Restart=on-failure
RestartSec=5
TimeoutStopSec=35
UMask=0077
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, uid, gid, directory, values[0], mode, values[1], admin), nil
}

// serviceCommand はパスワードを渡さずに管理コマンドを実行し、失敗を呼出元へ返す。
func serviceCommand(input *strings.Reader, name string, args ...string) error {
	command := exec.Command(name, args...)
	if input != nil {
		command.Stdin = input
	}
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

// installService は新規unitを保存・有効化し、指定時だけsystemd経由で起動する。
// 失敗時は設定とunitを残し、表示したコマンドで復旧できるようにする。
func installService(binary, config string, validation, start bool) error {
	unit, err := serviceUnit(binary, config, validation, os.Getuid(), os.Getgid())
	if err != nil {
		return err
	}
	// noclobberで既存ファイル・シンボリックリンクへの書込みを拒否する。
	// コマンド文字列は固定し、unit本文は標準入力、保存先は引数だけで渡す。
	err = serviceCommand(strings.NewReader(unit), "sudo", "--", "/bin/sh", "-c",
		serviceWriteScript, "oimobbs-install", servicePath)
	if err != nil {
		return fmt.Errorf("unitの新規保存に失敗しました: %w", err)
	}
	fmt.Println("unit保存先:", servicePath)
	fmt.Println("登録の再開: sudo systemctl daemon-reload && sudo systemctl enable oimobbs.service")
	for _, args := range [][]string{{"daemon-reload"}, {"enable", serviceName}} {
		if err = serviceCommand(nil, "sudo", append([]string{"--", "systemctl"}, args...)...); err != nil {
			return err
		}
	}
	fmt.Println("自動起動を有効にしました。実行UID:", os.Getuid())
	fmt.Println("起動: sudo systemctl start oimobbs.service")
	fmt.Println("状態: systemctl status oimobbs.service --no-pager")
	fmt.Println("ログ: sudo journalctl -u oimobbs.service -n 50 --no-pager")
	if start {
		return serviceCommand(nil, "sudo", "--", "systemctl", "start", serviceName)
	}
	return nil
}

// existingService は作成済み設定を読み、初期化を繰り返さずサービス登録だけを行う。
func existingService(o options) error {
	path, err := filepath.Abs(o.config)
	if err != nil {
		return err
	}
	c, err := bootstrap.LoadConfig(path)
	if err != nil {
		return err
	}
	if strings.HasPrefix(c.Public.BaseURL, "http://") && !o.allowHTTP {
		return errors.New("HTTPのサービス登録には、ローカル検証用の --allow-http が必要です")
	}
	if o.binary == "" {
		o.binary = filepath.Join(filepath.Dir(path), "bin", "oimobbs")
	}
	binary, err := binaryFor(o, path)
	if err != nil {
		return err
	}
	if err = servicePreflight(); err != nil {
		return err
	}
	return installService(binary, path, strings.HasPrefix(c.Public.BaseURL, "http://"), o.start)
}
