// 起動前検査を通った直結HTTPSの公開サーバー。検証サーバーと資源・保守基盤を共有する。
package bootstrap

import (
	"errors"
	"net/http"
	"oimobbs/internal/strictjson"
	"strings"
	"time"
)

// PublicHTTPServer はTLS・受理規制・耐久期限掃除・管理者の存在を確認してから公開受付を構築する。
// Listen/保守/Shutdown/CloseはCLIの所有者が行う。認証edgeは単一mTLS終端だけを許可する。
func (repo *Repository) PublicHTTPServer() (*http.Server, error) {
	if err := repo.ValidatePublicPrerequisites(); err != nil {
		return nil, err
	}
	if err := repo.EnableSlip(); err != nil {
		return nil, err
	}
	repo.mu.Lock()
	err := repo.validatePublicStartup()
	repo.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return repo.publicHTTPServer("production", "public-v1")
}

// ValidatePublicPrerequisites は起動で耐久設定を変更する前にTLS・規制・管理者を検査する。
func (repo *Repository) ValidatePublicPrerequisites() error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	return repo.validatePublicPrerequisites()
}

func (repo *Repository) validatePublicStartup() error {
	if err := repo.validatePublicPrerequisites(); err != nil {
		return err
	}
	var site siteState
	if strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site) != nil || site.MinimumReader < 28 {
		return errors.New("enable persistent retention, public body reclamation and control expiry before public serve")
	}
	for _, board := range repo.posting {
		if !board.retentionEnabled || !board.bodyReclaimEnabled || !board.carryEnabled {
			return errors.New("thread retention is not active")
		}
	}
	return nil
}

func (repo *Repository) validatePublicPrerequisites() error {
	if err := repo.available(); err != nil {
		return err
	}
	if err := repo.cfg.validate(); err != nil {
		return err
	}
	if !strings.HasPrefix(repo.cfg.Public.BaseURL, "https://") {
		return errors.New("public serve requires HTTPS")
	}
	if err := repo.cfg.checkTLS(time.Now()); err != nil {
		return err
	}
	if repo.admission == nil {
		return errors.New("enable posting admission before public serve")
	}
	accounts, err := repo.administrators()
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return errors.New("initialize an administrator before public serve")
	}
	return nil
}
