// 板設定の共有が更新・同revisionの改変・破損・欠落を隠さないことを検査する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/store"
	"testing"
)

func TestPostingFormSettingsFollowOriginalBytes(t *testing.T) {
	_, repo, info := postingRepositoryFixture(t)
	defer repo.Close()
	b := repo.posting[info.ID]
	_, err := b.worker.Submit(t.Context(), func() (any, error) {
		first, err := b.postingFormSettings()
		if err != nil {
			return nil, err
		}
		cache := b.formSettings
		if _, err = b.postingFormSettings(); err != nil || b.formSettings != cache {
			return nil, errors.New("unchanged settings decoded")
		}
		rows := b.control.State().Rows
		original := rows["board:state"]
		defer func() { rows["board:state"] = original }()
		changed := first
		changed.Name = "変更後"
		raw, err := json.Marshal(changed)
		if err != nil {
			return nil, err
		}
		rows["board:state"] = store.ControlRow{Revision: original.Revision, Value: raw}
		got, err := b.postingFormSettings()
		if err != nil || got.Name != "変更後" || b.formSettings == cache {
			return nil, errors.New("same-revision byte change hidden")
		}
		raw[0] = '!'
		if bytes.Equal(b.formSettings.raw, raw) {
			return nil, errors.New("cached bytes alias input")
		}
		if _, err = b.postingFormSettings(); err == nil {
			return nil, errors.New("corrupt settings hidden")
		}
		delete(rows, "board:state")
		if _, err = b.postingFormSettings(); err == nil {
			return nil, errors.New("missing settings hidden")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
