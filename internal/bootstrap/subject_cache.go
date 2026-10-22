// 専ブラの一覧本文を、順序・タイトル・件数が一致する公開集合で共有する。
package bootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
)

// subjectBody は公開判定済みの行から有界cacheのキーを作る。リースは呼出元が毎回取得する。
func (repo *Repository) subjectBody(r *http.Request, owner domain.ID, rows []publicThread) ([]byte, error) {
	key := subjectCacheKey(owner, rows)
	return repo.feedCompression.Render(r.Context(), key, func() ([]byte, error) {
		entries := make([]compat.SubjectEntry, len(rows))
		for i, row := range rows {
			entries[i] = compat.SubjectEntry{Key: row.Key, Title: row.Title, Count: row.Count}
		}
		return compat.Subject(entries)
	})
}

// subjectCacheKey は可変長タイトルを長さ付きで区切り、公開順位も含めてSHA-256へ固定する。
func subjectCacheKey(owner domain.ID, rows []publicThread) string {
	h := sha256.New()
	_, _ = h.Write(owner[:])
	var fields [20]byte
	var titleBytes [256]byte
	for _, row := range rows {
		binary.BigEndian.PutUint64(fields[:8], row.Key)
		binary.BigEndian.PutUint32(fields[8:12], row.Count)
		binary.BigEndian.PutUint64(fields[12:], uint64(len(row.Title)))
		_, _ = h.Write(fields[:])
		// hashへのstring変換で一行ごとの配列を確保しない。
		for title := row.Title; len(title) > 0; {
			n := copy(titleBytes[:], title)
			_, _ = h.Write(titleBytes[:n])
			title = title[n:]
		}
	}
	return "subject-v1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
