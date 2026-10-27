// Unix socketだけで更新指示と状態を渡す。更新用のホスト権限を掲示板プロセスへ持たせない。
package selfupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"oimobbs/internal/strictjson"
)

// LoadConfig はホスト所有者だけが編集できるJSONを読み、任意URLや相対コマンドを拒否する。
func LoadConfig(path string) (Config, error) {
	var c Config
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 32<<10 {
		return c, errors.New("更新設定は所有者専用の通常ファイル（0600）が必要です")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return c, errors.New("更新設定の所有者が実行ユーザーと一致しません")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := strictjson.Decode(raw, &c); err != nil {
		return c, err
	}
	if !filepath.IsAbs(c.Socket) || len(c.Socket) > 100 || !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir || c.StateDir == "/" || !revisionPattern.MatchString(c.CurrentRevision) {
		return c, errors.New("更新socket・保存先・初期コミットを確認してください")
	}
	for _, args := range [][]string{c.PrepareCommand, c.ApplyCommand} {
		if len(args) == 0 || len(args) > 32 || !filepath.IsAbs(args[0]) || strings.ContainsAny(args[0], "{}\x00") {
			return c, errors.New("更新コマンドには固定実行ファイルの絶対パスと引数配列が必要です")
		}
	}
	return c, nil
}

// Serve は単一ホスト更新器を起動する。socketのグループだけに接続を許可し、処理終了まで待つ。
func Serve(ctx context.Context, c Config) error {
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(c.StateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("更新保存先には専用の0700ディレクトリが必要です")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("更新保存先の所有者が実行ユーザーと一致しません")
	}
	lock, err := os.OpenFile(filepath.Join(c.StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("更新器はすでに起動しています")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	m, err := newManager(ctx, c, gitWorker{config: c})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Socket), 0750); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(c.Socket))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return errors.New("更新socketのディレクトリにはグループ・他ユーザーの書込みを許可できません")
	}
	if stat, ok := parent.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("更新socketのディレクトリの所有者が実行ユーザーと一致しません")
	}
	if info, err := os.Lstat(c.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("更新socketの場所に別のファイルがあります")
		}
		conn, err := net.DialTimeout("unix", c.Socket, time.Second)
		if err == nil {
			conn.Close()
			return errors.New("更新socketは使用中です")
		}
		if err := os.Remove(c.Socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", c.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(c.Socket, 0660); err != nil {
		return err
	}
	server := &http.Server{Handler: m.handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-finished:
		}
	}()
	err = server.Serve(listener)
	// contextの終了後は新規ジョブを受けず、受付中のAddが終わってから完了を待つ。
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.wg.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type applyRequest struct {
	Token    string `json:"token"`
	Revision string `json:"revision"`
}

func (m *Manager) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != "updater" || r.Header.Get("Origin") != "" || r.URL.RawQuery != "" {
			http.Error(w, "request rejected", 403)
			return
		}
		var state State
		var err error
		switch {
		case r.Method == "GET" && r.URL.Path == "/status":
			state = m.Snapshot()
		case r.Method == "POST" && r.URL.Path == "/check":
			raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
			if readErr != nil || strictjson.Decode(raw, &struct{}{}) != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			state, err = m.Check()
		case r.Method == "POST" && r.URL.Path == "/apply":
			raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
			var in applyRequest
			if readErr != nil || strictjson.Decode(raw, &in) != nil || len(in.Token) != 64 || !revisionPattern.MatchString(in.Revision) {
				http.Error(w, "invalid request", 400)
				return
			}
			state, err = m.Apply(in.Token, in.Revision)
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			status := 503
			if errors.Is(err, ErrConflict) {
				status = 409
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		_ = json.NewEncoder(w).Encode(state)
	})
}

// Client は固定のUnix socketへだけ接続する。HTTPプロキシやリダイレクトは使用しない。
type Client struct{ http *http.Client }

// NewClient は設定済みの更新器に接続するクライアントを作る。未設定なら呼出元で無効表示する。
func NewClient(socket string) (*Client, error) {
	if !filepath.IsAbs(socket) || len(socket) > 100 || strings.ContainsRune(socket, 0) {
		return nil, errors.New("更新socketには絶対パスが必要です")
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Request は状態取得・確認・確認済みコミットの更新だけを送信する。
func (c *Client) Request(ctx context.Context, action, token, revision string) (State, error) {
	method, body := "POST", []byte("{}")
	switch action {
	case "status":
		method = "GET"
	case "check":
	case "apply":
		body, _ = json.Marshal(applyRequest{token, revision})
	default:
		return State{}, errors.New("unknown update action")
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://updater/"+action, bytes.NewReader(body))
	if err != nil {
		return State{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return State{}, err
	}
	defer res.Body.Close()
	if res.StatusCode == 409 {
		return State{}, ErrConflict
	}
	if res.StatusCode != 200 {
		return State{}, fmt.Errorf("update agent returned %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<10))
	if err != nil {
		return State{}, err
	}
	var state State
	if err := strictjson.Decode(raw, &state); err != nil {
		return State{}, err
	}
	return state, nil
}
