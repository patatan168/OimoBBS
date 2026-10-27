// writerが直前に同期保存した時間帯だけ、完全一致するファイルの復号結果を再利用する。
package securitylog

import (
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"
)

const maxBucketBytes = 8 << 20
const maxCachedRows = maxSamples * 2

// bucketRows は単一writer専用。一bucket・512行・保存JSON8MiB以内だけを保持する。
// 表示側へmapを渡さず、保存失敗・ファイルの変更・保持期限で破棄する。
type bucketRows struct {
	name    string
	rows    map[string]Row
	info    os.FileInfo
	expires time.Time
}

// load は読み取り権限と開いたfileのinode・mode・長さ・更新時刻を照合する。
// 別bucket・削除・置換・変更は従来の完全読込へ戻し、読み取り失敗を隠さない。
func (c *bucketRows) load(dir, name string) (map[string]Row, error) {
	path := filepath.Join(dir, name+".json")
	if name == c.name && c.info != nil && c.matches(path) {
		return c.rows, nil
	}
	c.clear()
	return load(path)
}

func (c *bucketRows) matches(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	info, err := f.Stat()
	_ = f.Close()
	return err == nil && os.SameFile(info, c.info) && info.Mode() == c.info.Mode() && info.Size() == c.info.Size() && info.ModTime().Equal(c.info.ModTime())
}

// remember は保存・directory Syncの成功後だけ、同じbatchの新しい時間帯を保持する。
// 上限を超える既存ログを拒否せず、従来どおり毎回読み込む経路へ戻す。
func (c *bucketRows) remember(name string, rows map[string]Row, info os.FileInfo) {
	if name < c.name {
		return
	}
	c.clear()
	if info == nil || info.Size() > maxBucketBytes || len(rows) > maxCachedRows || !canonicalRows(rows) {
		return
	}
	at, err := time.Parse("20060102T15", name)
	if err != nil {
		return
	}
	c.name, c.rows, c.info, c.expires = name, rows, info, at.Add(time.Hour+retention)
}

// canonicalRows は標準JSONが置換する不正UTF-8を保持せず、次回の再読込と同じ値を保つ。
func canonicalRows(rows map[string]Row) bool {
	for key, row := range rows {
		for _, s := range []string{key, row.ID, row.Operation, row.MatchOperation, row.Source, row.Reason, row.Board, row.Path, row.Body, row.MatchBody, row.MatchBoard} {
			if !utf8.ValidString(s) {
				return false
			}
		}
	}
	return true
}

func (c *bucketRows) expire(now time.Time) {
	if !c.expires.IsZero() && !now.Before(c.expires) {
		c.clear()
	}
}

func (c *bucketRows) clear() { *c = bucketRows{} }
