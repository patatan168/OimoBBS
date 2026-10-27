// Package selfupdate は管理画面と、掲示板の外で動く更新専用プロセスを接続する。
package selfupdate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"oimobbs/internal/strictjson"
)

// RepositoryURL はWebやホスト設定から変更できない公式更新元。
const RepositoryURL = "https://github.com/patatan168/OimoBBS.git"

var revisionPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

// Config はホスト所有の設定。コマンドは引数の配列とし、Webから変更させない。
// {source}・{revision}・{job}だけを引数内で置換する。
type Config struct {
	Socket          string   `json:"socket"`
	StateDir        string   `json:"state_dir"`
	CurrentRevision string   `json:"current_revision"`
	PrepareCommand  []string `json:"prepare_command"`
	ApplyCommand    []string `json:"apply_command"`
}

// State は再起動後も確認できる更新状況。実行ログやホストの秘密は含めない。
type State struct {
	Phase           string    `json:"phase"`
	CurrentRevision string    `json:"current_revision"`
	LatestRevision  string    `json:"latest_revision"`
	Token           string    `json:"token"`
	Job             string    `json:"job"`
	Expires         time.Time `json:"expires"`
	Updated         time.Time `json:"updated"`
	Message         string    `json:"message"`
}

// Busy は確認・検証・再起動中の二重実行を防ぐ。
func (s State) Busy() bool {
	return s.Phase == "checking" || s.Phase == "preparing" || s.Phase == "applying"
}

type worker interface {
	latest(context.Context, string) (string, error)
	prepare(context.Context, State) error
	apply(context.Context, State) error
}

// Manager は処理を一件に制限し、確認したコミットにだけ一度更新を許可する。
type Manager struct {
	mu     sync.Mutex
	state  State
	config Config
	worker worker
	ctx    context.Context
	wg     sync.WaitGroup
	closed bool
}

// ErrConflict は期限切れ・確認対象の変化・処理中の競合を表す。
var ErrConflict = errors.New("更新状態が変わったか、確認の有効期限が切れました。もう一度最新版を確認してください。")

func newManager(ctx context.Context, c Config, w worker) (*Manager, error) {
	m := &Manager{config: c, worker: w, ctx: ctx}
	m.state = State{Phase: "idle", CurrentRevision: c.CurrentRevision, Message: "最新版の確認から始めてください。"}
	raw, err := os.ReadFile(filepath.Join(c.StateDir, "state.json"))
	if err == nil {
		if err := strictjson.Decode(raw, &m.state); err != nil || !validState(m.state) {
			return nil, errors.New("更新状態を読み取れません")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if m.state.Busy() || m.closed {
		m.state.Phase, m.state.Token = "failed", ""
		m.state.Message = "更新処理が中断されました。ホストのログと稼働状態を確認してください。自動では再実行しません。"
		if err := m.saveLocked(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// validState は壊れた状態を初期状態として扱わず、稼働コミットの暗黙の巻戻りを防ぐ。
func validState(s State) bool {
	switch s.Phase {
	case "idle", "checking", "ready", "current", "preparing", "applying", "complete", "failed":
	default:
		return false
	}
	if !revisionPattern.MatchString(s.CurrentRevision) || s.LatestRevision != "" && !revisionPattern.MatchString(s.LatestRevision) {
		return false
	}
	return s.Phase != "ready" || len(s.Token) == 64 && s.LatestRevision != "" && !s.Expires.IsZero()
}

// Snapshot は処理中の内部状態を共有せずに返す。
func (m *Manager) Snapshot() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Check は明示操作時だけGitを確認する。GETではネットワーク取得を始めない。
func (m *Manager) Check() (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Busy() {
		return m.state, ErrConflict
	}
	if err := m.ctx.Err(); err != nil {
		return m.state, err
	}
	previous := m.state
	m.state.Phase, m.state.Token, m.state.LatestRevision, m.state.Job = "checking", "", "", ""
	m.state.Expires = time.Time{}
	m.state.Message = "GitHubのmainブランチを確認しています。掲示板は稼働したままです。"
	if err := m.saveLocked(); err != nil {
		m.state = previous
		return m.state, err
	}
	m.wg.Add(1)
	go m.check()
	return m.state, nil
}

func (m *Manager) check() {
	defer m.wg.Done()
	ctx, cancel := context.WithTimeout(m.ctx, 2*time.Minute)
	defer cancel()
	current := m.Snapshot().CurrentRevision
	latest, err := m.worker.latest(ctx, current)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		slog.Error("software_update_check_failed", "error", err)
		m.finishLocked("failed", "最新版を確認できません。Gitの接続・現在のコミットと更新ログを確認してください。")
		return
	}
	m.state.LatestRevision = latest
	if latest == current {
		m.finishLocked("current", "現在のコミットはmainブランチの最新版です。")
		return
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		m.finishLocked("failed", "更新確認の発行に失敗しました。")
		return
	}
	m.state.Token = hex.EncodeToString(token[:])
	m.state.Expires = time.Now().Add(30 * time.Minute).UTC()
	m.finishLocked("ready", "更新できます。対象を確認してから実行してください。確認は30分間有効です。")
}

// Apply は確認時のトークンとコミットが一致した場合だけ開始する。同じ確認の再送は再実行しない。
func (m *Manager) Apply(token, revision string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || token == "" || token != m.state.Token || revision != m.state.LatestRevision {
		return m.state, ErrConflict
	}
	if m.state.Phase == "preparing" || m.state.Phase == "applying" || m.state.Phase == "complete" {
		return m.state, nil
	}
	if m.state.Phase != "ready" || !time.Now().Before(m.state.Expires) {
		return m.state, ErrConflict
	}
	if err := m.ctx.Err(); err != nil {
		return m.state, err
	}
	previous := m.state
	m.state.Phase, m.state.Job = "preparing", token[:24]
	m.state.Message = "確認したコミットを取得し、停止前にビルドと検証を行っています。"
	if err := m.saveLocked(); err != nil {
		m.state = previous
		return m.state, err
	}
	state := m.state
	m.wg.Add(1)
	go m.apply(state)
	return m.state, nil
}

func (m *Manager) apply(state State) {
	defer m.wg.Done()
	ctx, cancel := context.WithTimeout(m.ctx, 45*time.Minute)
	defer cancel()
	if err := m.worker.prepare(ctx, state); err != nil {
		slog.Error("software_update_prepare_failed", "job", state.Job, "error", err)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.finishLocked("failed", "ビルドまたは検証に失敗しました。更新による掲示板の停止・置換は行っていません。")
		return
	}
	m.mu.Lock()
	m.state.Phase, m.state.Message = "applying", "バックアップを保存して更新・再起動しています。一時的に接続できなくなります。"
	err := m.saveLocked()
	m.mu.Unlock()
	if err == nil {
		err = m.worker.apply(ctx, state)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		slog.Error("software_update_apply_failed", "job", state.Job, "error", err)
		m.finishLocked("failed", "更新を完了できませんでした。ホストの更新ログ・バックアップ・稼働状態を確認してください。自動では再実行しません。")
		return
	}
	m.state.CurrentRevision = state.LatestRevision
	m.finishLocked("complete", "更新と再起動が完了し、ヘルスチェックに成功しました。")
}

func (m *Manager) finishLocked(phase, message string) {
	m.state.Phase, m.state.Message = phase, message
	if err := m.saveLocked(); err != nil {
		m.state.Phase, m.state.Token = "failed", ""
		m.state.Message = "更新結果の保存に失敗しました。ホストの稼働状態と保存領域を確認してください。"
	}
}

func (m *Manager) saveLocked() error {
	m.state.Updated = time.Now().UTC()
	raw, err := json.Marshal(m.state)
	if err != nil {
		return err
	}
	return saveFile(filepath.Join(m.config.StateDir, "state.json"), raw)
}

// saveFile は同じディレクトリで書込み・同期・置換し、中断したJSONを公開しない。
func saveFile(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".update-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
