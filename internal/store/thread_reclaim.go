// 検証済みcurrentから参照されない旧投稿世代だけを、停止中に回収する。
package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

// ThreadReclaimReport は削除対象の論理byte数。実ディスクの空き容量増分ではない。
type ThreadReclaimReport struct {
	Files   int   `json:"files"`
	Bytes   int64 `json:"bytes"`
	Applied bool  `json:"applied"`
}

// ReclaimOldFiles は検証済みpack世代の旧ファイルを列挙し、apply時だけ除去する。
// 所有ワーカー・プロセス排他が前提。中断しても残りを同じ規則で再列挙できる。
func (t *ThreadLog) ReclaimOldFiles(apply bool) (ThreadReclaimReport, error) {
	return t.reclaimOldFiles(apply, func(string) error { return nil })
}
func (t *ThreadLog) reclaimOldFiles(apply bool, boundary func(string) error) (ThreadReclaimReport, error) {
	fail := func(e error) (ThreadReclaimReport, error) { return ThreadReclaimReport{}, e }
	if t.writer.stopped || t.base == nil {
		return fail(errors.New("verified pack required for reclamation"))
	}
	m, _, e := InspectThreadFiles(t.dir)
	if e != nil {
		return fail(e)
	}
	if !reflect.DeepEqual(m, t.manifest) {
		return fail(ErrCorrupt)
	}
	files, e := os.ReadDir(t.dir)
	if e != nil {
		return fail(e)
	}
	var names []string
	report := ThreadReclaimReport{}
	for _, file := range files {
		name := file.Name()
		if !strings.HasPrefix(name, "delta-") && !strings.HasPrefix(name, "base-") {
			continue
		}
		part := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(name, "base-"), "delta-"), ".pack"), ".wal")
		generation, e := strconv.ParseUint(part, 10, 64)
		if e != nil {
			return fail(e)
		}
		if generation >= uint64(m.Generation) {
			continue
		}
		info, e := os.Lstat(filepath.Join(t.dir, name))
		if e != nil {
			return fail(e)
		}
		if info.Size() > int64(^uint64(0)>>1)-report.Bytes {
			return fail(ErrCorrupt)
		}
		report.Files++
		report.Bytes += info.Size()
		names = append(names, name)
	}
	if !apply {
		return report, nil
	}
	for _, name := range names {
		if e = os.Remove(filepath.Join(t.dir, name)); e != nil {
			t.writer.stopped = true
			return fail(e)
		}
		if e = boundary("old_file_removed"); e != nil {
			t.writer.stopped = true
			return fail(e)
		}
	}
	if e = SyncDirectory(t.dir); e != nil {
		t.writer.stopped = true
		return fail(e)
	}
	report.Applied = true
	return report, nil
}
