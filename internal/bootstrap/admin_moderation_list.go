// 削除履歴と対応するコピー進捗を、認証済み共通cursorの同じ窓へ収める。
package bootstrap

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type moderationHTTPRead struct {
	Revision     domain.U64             `json:"revision"`
	Deletions    []deletionHTTPView     `json:"deletions"`
	Tasks        []deletionTaskHTTPView `json:"copy_tasks"`
	Window       adminListWindow        `json:"-"`
	ListRevision string                 `json:"-"`
}

func deletionHistory(log *store.ControlLog) ([]DeletionRecord, []DeletionCopyTask, error) {
	records, tasks := []DeletionRecord{}, []DeletionCopyTask{}
	if log == nil {
		return records, tasks, nil
	}
	for name, row := range log.State().Rows {
		if strings.HasPrefix(name, "deletion:") {
			var v DeletionRecord
			if err := strictjson.Decode(row.Value, &v); err != nil {
				return nil, nil, err
			}
			records = append(records, v)
		} else if strings.HasPrefix(name, "copy_task:") {
			var v DeletionCopyTask
			if err := strictjson.Decode(row.Value, &v); err != nil {
				return nil, nil, err
			}
			tasks = append(tasks, v)
		}
	}
	return records, tasks, nil
}

func moderationHistoryWindow(r *http.Request, s adminauth.Session, records []DeletionRecord, tasks []DeletionCopyTask) ([]DeletionRecord, []DeletionCopyTask, adminListWindow, string, error) {
	sort.Slice(records, func(i, j int) bool { return records[i].ID.String() < records[j].ID.String() })
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID.String() < tasks[j].ID.String() })
	revision, err := adminListRevision(struct {
		Records []DeletionRecord
		Tasks   []DeletionCopyTask
	}{records, tasks})
	if err != nil {
		return nil, nil, adminListWindow{}, "", err
	}
	keys := make([]string, len(records))
	for i, v := range records {
		keys[i] = v.ID.String()
	}
	window, err := adminListSlice(r, s, revision, keys, time.Now())
	if err != nil {
		return nil, nil, window, "", err
	}
	records = records[window.Start:window.End]
	selected := map[domain.ID]bool{}
	for _, v := range records {
		selected[v.ID] = true
	}
	visibleTasks := []DeletionCopyTask{}
	for _, v := range tasks {
		if selected[v.Deletion] {
			visibleTasks = append(visibleTasks, v)
		}
	}
	return records, visibleTasks, window, revision, nil
}
