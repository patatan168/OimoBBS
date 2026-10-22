// Command setup はシェルから渡された新規サイト設定を安全に保存し、既存CLIで初期登録する。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/bootstrap"
)

type options struct {
	config, data, origin, listen, cert, key, binary, source, name, board, boardName, login string
	adminPort                                                                              int
	publicAdmin, start, passwordStdin                                                      bool
	installService, serviceOnly                                                            bool
	allowHTTP                                                                              bool
}

// parse はシェルと直接実行で共通のセットアップ引数を読み取る。
func parse(args []string) (options, error) {
	var o options
	f := flag.NewFlagSet("setup.sh", flag.ContinueOnError)
	f.StringVar(&o.config, "config", "config.json", "新規設定先")
	f.StringVar(&o.data, "data-dir", "var/site", "設定ファイル基準の新規保存先")
	f.StringVar(&o.origin, "url", "https://localhost", "公開HTTPS Origin。HTTPは--allow-httpでloopback検証のみ")
	f.StringVar(&o.listen, "listen", "", "公開待受。HTTPSは0.0.0.0とURLのポート（省略時443）")
	f.StringVar(&o.cert, "tls-cert", "", "PEM証明書チェーン")
	f.StringVar(&o.key, "tls-key", "", "PEM秘密鍵")
	f.StringVar(&o.binary, "binary", "", "指定した既存バイナリを使う")
	f.StringVar(&o.source, "source-root", ".", "ソースの場所（シェルが指定）")
	f.StringVar(&o.name, "name", "OimoBBS", "サイト名")
	f.StringVar(&o.board, "board-key", "operate", "最初の板キー")
	f.StringVar(&o.boardName, "board-name", "運営", "最初の板名")
	f.StringVar(&o.login, "login", "owner", "管理ログイン名")
	f.IntVar(&o.adminPort, "admin-port", 9081, "loopback管理ポート")
	f.BoolVar(&o.publicAdmin, "public-admin", true, "公開と同じ待受で管理（既定）。falseは旧loopback別待受")
	f.BoolVar(&o.passwordStdin, "password-stdin", false, "管理パスワード1行を標準入力から読む")
	f.BoolVar(&o.start, "start", false, "準備後にサーバーを起動")
	f.BoolVar(&o.installService, "install-service", false, "sudoでsystemdへ登録し、OS起動時の自動起動を有効化")
	f.BoolVar(&o.serviceOnly, "service-only", false, "既存設定のsystemd登録だけを行う（初期化・パスワード入力なし）")
	f.BoolVar(&o.allowHTTP, "allow-http", false, "loopbackでの平文HTTP検証を明示的に許可")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if f.NArg() != 0 {
		return o, errors.New("unexpected arguments")
	}
	return o, nil
}

// newPath は既存物と親のリンクを拒否し、元の設定や保存先を保護する。
func newPath(path string) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("既に存在するか検査できません。上書きしません: %s", path)
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err == nil && !info.IsDir() {
			return fmt.Errorf("親が通常のディレクトリではありません: %s", parent)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return nil
}

// displayName は初期化より前に、表示名の長さと制御文字を検査する。
func displayName(value string) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != "" && utf8.RuneCountInString(value) <= 128 && strings.IndexFunc(value, unicode.IsControl) < 0
}

// settings は投稿先・管理者の初期値について、保存前に形式を検査する。
func settings(o options) error {
	if !displayName(o.name) || !displayName(o.boardName) {
		return errors.New("サイト名・板名は制御文字を含まない1〜128文字です")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`).MatchString(o.board) || o.board == "test" || o.board == "web" {
		return errors.New("板キーは小文字英字で始まる32文字以内の英数字・_です（test/webは予約済み）")
	}
	if !regexp.MustCompile(`^[a-z0-9_.-]{3,64}$`).MatchString(o.login) {
		return errors.New("管理ログイン名は3〜64文字の小文字英数字・_・.・-です")
	}
	if !o.publicAdmin && (o.adminPort < 1 || o.adminPort > 65535) {
		return errors.New("管理ポートは1〜65535です")
	}
	return nil
}

// publicConfig は直結HTTP(S)の設定を生成し、平文の外部公開を拒否する。
func publicConfig(o options) (bootstrap.PublicConfig, error) {
	var p bootstrap.PublicConfig
	u, err := url.Parse(o.origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(o.origin, "#") || u.Scheme != "http" && u.Scheme != "https" {
		return p, errors.New("--url はパス・末尾の / を含まないHTTP(S) Originです")
	}
	p.BaseURL = o.origin
	p.Listen = o.listen
	if u.Scheme == "https" {
		if o.cert == "" || o.key == "" {
			return p, errors.New("HTTPSには --tls-cert と --tls-key が必要です")
		}
		if p.Listen == "" {
			port := u.Port()
			if port == "" {
				port = "443"
			}
			p.Listen = net.JoinHostPort("0.0.0.0", port)
		}
		p.TLSCert, err = filepath.Abs(o.cert)
		if err != nil {
			return p, err
		}
		p.TLSKey, err = filepath.Abs(o.key)
		return p, err
	}
	if !o.allowHTTP {
		return p, errors.New("HTTPは既定で無効です。HTTPS証明書を指定するか、ローカル検証に限り --allow-http を指定してください")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) || o.cert != "" || o.key != "" {
		return p, errors.New("HTTPはloopback検証専用です。外部公開にはHTTPSを指定してください")
	}
	if p.Listen == "" {
		port := u.Port()
		if port == "" {
			port = "80"
		}
		p.Listen = net.JoinHostPort(u.Hostname(), port)
	}
	return p, nil
}

// configFor は絶対パスと用途別の起動設定を組み立てる。既存物には書き込まない。
func configFor(o options) (string, bootstrap.Config, error) {
	var c bootstrap.Config
	path, err := filepath.Abs(o.config)
	if err != nil {
		return path, c, err
	}
	if err = newPath(path); err != nil {
		return path, c, err
	}
	data := o.data
	if !filepath.IsAbs(data) {
		data = filepath.Join(filepath.Dir(path), data)
	}
	data, err = filepath.Abs(data)
	if err != nil {
		return path, c, err
	}
	if err = newPath(data); err != nil {
		return path, c, err
	}
	if data == path || strings.HasPrefix(path, data+string(os.PathSeparator)) || strings.HasPrefix(data, path+string(os.PathSeparator)) {
		return path, c, errors.New("設定ファイルと保存先は別の場所を指定してください")
	}
	if err = settings(o); err != nil {
		return path, c, err
	}
	public, err := publicConfig(o)
	if err != nil {
		return path, c, err
	}
	adminAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(o.adminPort))
	c = bootstrap.Config{Schema: 1, DataDir: data, Public: public, Admin: bootstrap.AdminConfig{Listen: adminAddress, Transport: "loopback_tunnel", Origin: "http://" + adminAddress}, TrustedProxies: []string{}, EgressBits: 80000000}
	if o.publicAdmin {
		c.Admin.Listen = ""
		c.Admin.Transport = "public_path"
		c.Admin.Origin = o.origin + "/admin/"
	}
	return path, c, nil
}

// password は秘密を引数・ファイルへ出さずに読み、初期化前に製品の資格条件を検査する。
func password(input io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(input, 515))
	if err != nil {
		return nil, err
	}
	secret := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(raw) > 514 || strings.ContainsAny(secret, "\r\n") {
		clear(raw)
		return nil, errors.New("パスワードは1行で入力してください")
	}
	if _, err = adminauth.NewPassword(secret); err != nil {
		clear(raw)
		return nil, errors.New("管理パスワードは15〜128文字です")
	}
	return raw, nil
}

// binaryFor は新しい出力だけをビルドする。--binaryの指定先は変更しない。
func binaryFor(o options, path string) (string, error) {
	if o.binary != "" {
		binary, err := filepath.Abs(o.binary)
		if err != nil {
			return "", err
		}
		info, err := os.Stat(binary)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return "", errors.New("実行可能なバイナリを指定してください")
		}
		return binary, nil
	}
	binary := filepath.Join(filepath.Dir(path), "bin", "oimobbs")
	if err := newPath(binary); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(filepath.Dir(binary), ".oimobbs-")
	if err != nil {
		return "", err
	}
	temporary.Close()
	defer os.Remove(temporary.Name())
	fmt.Println("バイナリをビルドしています。")
	command := exec.Command("go", "build", "-trimpath", "-o", temporary.Name(), "./cmd/oimobbs")
	command.Dir = o.source
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err = command.Run(); err != nil {
		return "", err
	}
	if err = os.Chmod(temporary.Name(), 0755); err != nil {
		return "", err
	}
	return binary, os.Link(temporary.Name(), binary)
}

// writeConfig は0600・新規作成専用で設定を耐久保存する。途中成果は削除しない。
func writeConfig(path string, c bootstrap.Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.DataDir), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(c)
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

// step は既存CLIで一工程を実行し、失敗時は以降の操作を止める。
func step(binary, path, title string, args []string, secret []byte) error {
	fmt.Println(title)
	command := exec.Command(binary, append(args, "--config", path)...)
	command.Stdin = strings.NewReader(string(secret))
	command.Stdout = io.Discard
	command.Stderr = os.Stderr
	return command.Run()
}

// initialize は製品CLIの順序で登録・規制・保存検査を進め、既存物を消さない。
func initialize(o options, binary, path string, secret []byte) error {
	steps := []struct {
		title    string
		args     []string
		password []byte
	}{
		{"サイトを作成しています。", []string{"init", "--name", o.name}, nil},
		{"板を作成しています。", []string{"board", "create", "--validation", "--key", o.board, "--name", o.boardName}, nil},
		{"管理者を登録しています。", []string{"admin", "init", "--login", o.login, "--password-stdin"}, secret},
		{"投稿規制を有効にしています。", []string{"admission", "enable"}, nil},
		{"匿名Cookieを有効にしています。", []string{"anonymous", "enable", "--mode", "required"}, nil},
		{"保存状態を検査しています。", []string{"board", "list", "--validation"}, nil},
	}
	for _, s := range steps {
		if err := step(binary, path, s.title, s.args, s.password); err != nil {
			return err
		}
	}
	return nil
}

// shellQuote は表示する起動コマンドの引数をbashで安全に引用する。
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

// run は新規設定を作成し、明示指定時だけ同じプロセスでサーバーへ移る。
func run(o options, input io.Reader) error {
	if o.serviceOnly {
		return existingService(o)
	}
	path, c, err := configFor(o)
	if err != nil {
		return err
	}
	if o.installService {
		binary := o.binary
		if binary == "" {
			binary = filepath.Join(filepath.Dir(path), "bin", "oimobbs")
		}
		binary, err = filepath.Abs(binary)
		if err != nil {
			return err
		}
		if _, err = serviceUnit(binary, path, false, os.Getuid(), os.Getgid()); err != nil {
			return err
		}
		if err = servicePreflight(); err != nil {
			return err
		}
	}
	if o.binary == "" {
		if err = newPath(filepath.Join(filepath.Dir(path), "bin", "oimobbs")); err != nil {
			return err
		}
	}
	secret, err := password(input)
	if err != nil {
		return err
	}
	defer clear(secret)
	binary, err := binaryFor(o, path)
	if err != nil {
		return err
	}
	if err = newPath(c.DataDir); err != nil {
		return err
	}
	if err = writeConfig(path, c); err != nil {
		return err
	}
	if err = initialize(o, binary, path, secret); err != nil {
		return err
	}
	clear(secret)
	args := []string{binary, "serve", "--config", path}
	if strings.HasPrefix(o.origin, "http://") {
		args[1] = "validation-serve"
		args = append(args, "--admin")
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	fmt.Printf("セットアップ完了。設定: %s\n公開URL: %s\n管理URL: %s\nログイン名: %s\n起動: %s\n", path, o.origin, c.Admin.Origin, o.login, strings.Join(quoted, " "))
	if o.installService {
		return installService(binary, path, strings.HasPrefix(o.origin, "http://"), o.start)
	}
	if o.start {
		return syscall.Exec(binary, args, os.Environ())
	}
	return nil
}

func main() {
	o, err := parse(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err == nil {
		err = run(o, os.Stdin)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "セットアップ失敗:", err, "\n作成済みの設定・データは保持しています。")
		os.Exit(1)
	}
}
