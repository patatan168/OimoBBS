// 提出ZIPのbytesへ署名し、期限付き一回取得を監査する。
package disclosure

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

// zipSignatureReadme は実提出ZIPに共通する検証方法と記録の範囲を説明する。
const zipSignatureReadme = `
署名の確認
records.csv・readme.txt・public-keys.jsonのハッシュをmanifest.jsonに記載しています。
manifest.sigはmanifest.jsonの元バイトのSHA-256に対するEd25519署名（64バイト）です。
public-keys.jsonの公開鍵は、別途信頼済みの公開鍵と照合してください。
原本参照のsource_event_sha256は元記録との対応付け用です。
このZIPの署名は出力ファイルを検証するもので、CSVに原本署名が付くわけではありません。
HTTP送信完了・相手先の受領は証明しません。ZIPは暗号化されません。
`

type exportFile struct {
	Name  string      `json:"name"`
	Bytes domain.U64  `json:"bytes"`
	SHA   domain.Hash `json:"sha256"`
}

// Manifest は選択列の元bytesを署名する提出物の検証契約。
type Manifest struct {
	Schema       string        `json:"schema"`
	ID           domain.ID     `json:"export_id"`
	Case         domain.ID     `json:"case_id"`
	Actor        domain.ID     `json:"actor_id"`
	Generated    string        `json:"generated_at"`
	Until        domain.Time   `json:"retention_until_ns"`
	Scope        Scope         `json:"scope"`
	Columns      []string      `json:"columns"`
	Count        uint32        `json:"count"`
	Sources      []domain.Hash `json:"source_event_sha256"`
	Missing      []domain.ID   `json:"missing_record_ids"`
	Files        []exportFile  `json:"files"`
	KeyID        uint32        `json:"signing_key_id"`
	Completeness string        `json:"completeness"`
	RecordKind   string        `json:"record_kind"`
}

func (s *Store) exportPath(id, export domain.ID) string {
	return filepath.Join(s.artifactDir(id, "exports"), export.String()+".zip")
}

// Generate は固定集合・選択列・期限をintentへ記録し、fileへstream生成する。
func (s *Store) Generate(id, actor domain.ID, etag, key, purpose string, columns []string, now time.Time) (Case, Export, error) {
	return s.GeneratePrepared(id, actor, etag, key, purpose, columns, now, nil)
}

// GeneratePrepared は認可版と再送を検査後、関連原本の保全を済ませて提出対象を固定する。
// prepareは最新案件を返す。要求の再送照合には保全前のetagを維持する。
func (s *Store) GeneratePrepared(id, actor domain.ID, etag, key, purpose string, columns []string, now time.Time, prepare func(Case) (Case, error)) (Case, Export, error) {
	input := struct {
		Purpose string   `json:"purpose"`
		Columns []string `json:"columns"`
	}{purpose, columns}
	if !ValidColumns(columns) {
		return Case{}, Export{}, ErrInvalid
	}
	c, replay, e := s.Replay(id, actor, "export_intent", etag, key, input)
	if e != nil {
		return c, Export{}, e
	}
	if !replay {
		c, e = s.AuthorizeState(id, etag, now)
		if e != nil {
			return c, Export{}, e
		}
		if c.State != "active" && c.State != "partial" || len(c.Exports) >= 100 {
			return c, Export{}, ErrLimit
		}
		if c.HTTP != nil && c.HTTP.Unbound && !app.ValidRejectedColumns(columns) {
			return c, Export{}, ErrInvalid
		}
		if prepare != nil {
			c, e = prepare(c)
			if e != nil {
				return c, Export{}, e
			}
			now = time.Now()
			c, e = s.AuthorizeState(id, c.ETag(), now)
			if e != nil {
				return c, Export{}, e
			}
		}
		v := Export{ID: s.IDFor(actor, "export:"+key), Created: domain.Time(now.UnixNano()), Until: min(c.Until, domain.Time(now.Add(24*time.Hour).UnixNano())), Columns: append([]string{}, columns...), State: "preparing"}
		if c.HTTP != nil && (c.HTTP.Unbound || slices.Contains(columns, "connection")) {
			if c.HTTP.State != "active" && c.HTTP.State != "partial" {
				return c, Export{}, ErrConflict
			}
			raw, err := json.Marshal(c.HTTP)
			if err != nil {
				return c, Export{}, err
			}
			v.HTTPSelection = sha256.Sum256(raw)
			if c.HTTP.Unbound {
				v.Kind = "http_observation"
			}
		}
		c.Exports = append(c.Exports, v)
		c, e = s.append(c, actor, "export_intent", purpose, columns, etag, key, input, now)
		if e != nil {
			return c, Export{}, e
		}
	}
	if !replay {
		if e = s.after("export:intent"); e != nil {
			return c, Export{}, e
		}
	}
	current, e := s.Get(id)
	if e != nil {
		return c, Export{}, e
	}
	c = current
	exportID := s.IDFor(actor, "export:"+key)
	index := -1
	for i, v := range c.Exports {
		if v.ID == exportID {
			index = i
		}
	}
	if index < 0 {
		return c, Export{}, ErrConflict
	}
	return s.generateExisting(c, index, actor, purpose, now)
}

// ResumeExport は途中の提出物を固定対象・元の24時間期限で再開する。
func (s *Store) ResumeExport(id, export, actor domain.ID, etag, key, purpose string, now time.Time) (Case, Export, error) {
	input := struct {
		ID      domain.ID `json:"export_id"`
		Purpose string    `json:"purpose"`
	}{export, purpose}
	c, replay, e := s.Replay(id, actor, "export_resume", etag, key, input)
	if e != nil {
		return c, Export{}, e
	}
	if !replay {
		c, e = s.AuthorizeState(id, etag, now)
		if e != nil {
			return c, Export{}, e
		}
	}
	current, e := s.Get(id)
	if e != nil {
		return current, Export{}, e
	}
	c = current
	index := -1
	for i, v := range c.Exports {
		if v.ID == export {
			index = i
		}
	}
	if index < 0 {
		return c, Export{}, ErrInvalid
	}
	v := c.Exports[index]
	if v.Kind != "" && v.Kind != "http_observation" {
		return c, v, ErrInvalid
	}
	if v.State != "preparing" {
		return c, v, nil
	}
	if !replay {
		c, e = s.append(c, actor, "export_resume", purpose, v.Columns, etag, key, input, now)
		if e != nil {
			return c, v, e
		}
	}
	return s.generateExisting(c, index, actor, purpose, now)
}
func (s *Store) generateExisting(c Case, index int, actor domain.ID, purpose string, now time.Time) (Case, Export, error) {
	v := c.Exports[index]
	if v.Kind != "" && v.Kind != "http_observation" {
		return c, v, ErrInvalid
	}
	var e error
	if domain.Time(now.UnixNano()) >= v.Until || domain.Time(now.UnixNano()) >= c.Until || c.State == "closed" || c.State == "releasing" {
		return c, v, ErrExpired
	}
	if v.State != "preparing" {
		return c, v, nil
	}
	if e := s.requireCapacity(MaxArtifactBytes); e != nil {
		return c, v, e
	}
	var rows []app.AcceptedEvidence
	if v.Kind == "" {
		rows, e = s.Records(c, now)
		if e != nil {
			return c, v, e
		}
	}
	if e = prepareDir(s.artifactDir(c.ID, "exports")); e != nil {
		return c, v, e
	}
	if e = s.validateHTTPExportSelection(c, v); e != nil {
		return c, v, e
	}
	if e = s.writeZIP(c, v, actor, rows, now); e != nil {
		return c, v, e
	}
	if e = s.after("export:file"); e != nil {
		return c, v, e
	}
	finished := time.Now()
	if finished.Before(now) || domain.Time(finished.UnixNano()) >= v.Until || domain.Time(finished.UnixNano()) >= c.Until {
		return c, v, ErrExpired
	}
	digest, size, e := hashArtifact(s.exportPath(c.ID, v.ID))
	if e != nil {
		return c, v, e
	}
	v.SHA = digest
	v.Bytes = domain.U64(size)
	v.State = "ready"
	c.Exports[index] = v
	c, e = s.append(c, actor, "export_ready", purpose, v.Columns, "", "", nil, now)
	return c, v, e
}
func (s *Store) writeZIP(c Case, v Export, actor domain.ID, rows []app.AcceptedEvidence, now time.Time) error {
	if v.Kind == "http_observation" {
		return s.writeHTTPObservationZIP(c, v, actor, now)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Thread != b.Thread {
			return a.Thread < b.Thread
		}
		if a.Post != b.Post {
			return a.Post < b.Post
		}
		return a.RecordID.String() < b.RecordID.String()
	})
	m := Manifest{Schema: "evidence-export-v1", ID: v.ID, Case: c.ID, Actor: actor, Generated: now.In(domain.JST).Format(time.RFC3339Nano), Until: v.Until, Scope: c.Scope, Columns: v.Columns, Count: uint32(len(rows)), Sources: []domain.Hash{}, Missing: []domain.ID{}, Files: []exportFile{}, KeyID: 10, Completeness: "partial"}
	for _, item := range c.Items {
		if item.State != "held" {
			m.Missing = append(m.Missing, item.Record)
		}
	}
	projected := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		data, err := row.Project(v.Columns)
		if err != nil {
			return err
		}
		projected = append(projected, data)
	}
	if v.HTTPSelection != (domain.Hash{}) {
		if e := s.projectHTTP(c, projected, now); e != nil {
			return e
		}
		for _, item := range c.HTTP.Items {
			if item.State != "held" {
				m.Missing = append(m.Missing, item.Record)
			}
		}
	}
	for i, row := range rows {
		data := projected[i]
		result, _ := data["result"].(map[string]any)
		if response, ok := result["response"].(map[string]any); ok {
			if source, ok := response["source_event_sha256"].(domain.Hash); ok {
				m.Sources = append(m.Sources, source)
			}
		}
		data["committed_at_jst"] = time.Unix(0, int64(row.Committed)).In(domain.JST).Format(time.RFC3339Nano)
		data["held_until_ns"] = c.Until
		m.Sources = append(m.Sources, row.Proposal.Event.EventSHA)
	}
	readme := []byte(`OimoBBS 投稿ログ

提出可能な全項目を含む、投稿・接続の部分記録です。
本人の投稿と受理時の公開表示を収め、終了案内などの自動投稿は含めません。
接続元は保存時に観測・解決された値、User-Agentは未検証の申告値です。
秘密入力は収集時に除去しています。欠落対象はmanifestに記載します。
関連HTTPの案件コピーは保全期限まで保持し、原本の7日の保持期限は変更しません。
HTTP観測は保全済みでもpartial_observationです。
` + zipSignatureReadme)
	return s.writeProjectedZIP(c, v, m, projected, readme)
}

// writeProjectedZIP は選択済みの行とmanifestを既存の64MiB/同期保存/署名形式で出力する。
func (s *Store) writeProjectedZIP(c Case, v Export, m Manifest, projected []map[string]any, readme []byte) error {
	explanation, e := s.explainLogs(c.Scope)
	if e != nil {
		return e
	}
	table, e := prepareExportCSV(projected)
	if e != nil {
		return e
	}
	m.Count = uint32(len(table.rows))
	readme = append(readme, table.readme()...)
	readme = append(readme, explanation...)
	path := s.exportPath(c.ID, v.ID)
	temp := path + ".tmp"
	if e := os.Remove(temp); e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	budget := &limitedWriter{writer: f, remaining: MaxArtifactBytes}
	z := zip.NewWriter(budget)
	add := func(name string, raw []byte) error {
		w, err := z.Create(name)
		if err != nil {
			return err
		}
		if _, err = w.Write(raw); err != nil {
			return err
		}
		m.Files = append(m.Files, exportFile{name, domain.U64(len(raw)), sha256.Sum256(raw)})
		return nil
	}
	rw, e := z.Create("records.csv")
	if e != nil {
		return e
	}
	hash := sha256.New()
	counter := &countWriter{writer: io.MultiWriter(rw, hash)}
	if e = table.write(&limitedWriter{writer: counter, remaining: MaxArtifactBytes - (1 << 20)}); e != nil {
		return e
	}
	var recordsHash domain.Hash
	copy(recordsHash[:], hash.Sum(nil))
	m.Files = append(m.Files, exportFile{"records.csv", domain.U64(counter.bytes), recordsHash})
	keys, _ := json.Marshal(map[string]any{"signing_key_id": 10, "algorithm": "Ed25519", "public_key_base64": base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))})
	if e = add("public-keys.json", keys); e != nil {
		return e
	}

	if e = add("readme.txt", readme); e != nil {
		return e
	}
	manifest, e := json.Marshal(m)
	if e != nil {
		return e
	}
	w, e := z.Create("manifest.json")
	if e != nil {
		return e
	}
	if _, e = w.Write(manifest); e != nil {
		return e
	}
	digest := sha256.Sum256(manifest)
	sig := ed25519.Sign(s.key, digest[:])
	w, e = z.Create("manifest.sig")
	if e != nil {
		return e
	}
	if _, e = w.Write(sig); e != nil {
		return e
	}
	if e = z.Close(); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(temp, path); e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}

type limitedWriter struct {
	writer    io.Writer
	remaining int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, ErrLimit
	}
	n, e := w.writer.Write(p)
	w.remaining -= n
	return n, e
}

type countWriter struct {
	writer io.Writer
	bytes  int
}

func (w *countWriter) Write(p []byte) (int, error) {
	n, e := w.writer.Write(p)
	w.bytes += n
	return n, e
}

// Download は開始監査と消費を先にSyncする。切断後も同じ許可を再利用できない。
func (s *Store) Download(id, export, actor domain.ID, etag, key, purpose string, now time.Time) (Case, *os.File, Export, error) {
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, nil, Export{}, e
	}
	i := -1
	for index, v := range c.Exports {
		if v.ID == export {
			i = index
		}
	}
	if i < 0 {
		return c, nil, Export{}, os.ErrNotExist
	}
	v := c.Exports[i]
	if v.State != "ready" || domain.Time(now.UnixNano()) >= v.Until {
		return c, nil, v, ErrExpired
	}
	// 原本hashを確認してからfileを開く。返却後もHTTP境界で期限・担当を再検査する。
	digest, size, e := hashArtifact(s.exportPath(id, export))
	if e != nil || digest != v.SHA || domain.U64(size) != v.Bytes {
		if e == nil {
			e = ErrInvalid
		}
		return c, nil, v, e
	}
	f, e := os.Open(s.exportPath(id, export))
	if e != nil {
		return c, nil, v, e
	}
	c.Exports[i].State = "consumed"
	c, e = s.append(c, actor, "download", purpose, v.Columns, etag, key, export, now)
	if e != nil {
		f.Close()
		return c, nil, v, e
	}
	return c, f, v, nil
}

// VerifyZIP は外部で信頼した公開鍵で提出物の署名・全ファイルhashと固定構成を検証する。
func VerifyZIP(reader io.ReaderAt, size int64, key ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if size < 0 || size > MaxArtifactBytes || len(key) != ed25519.PublicKeySize {
		return m, ErrInvalid
	}
	z, e := zip.NewReader(reader, size)
	if e != nil {
		return m, e
	}
	files := map[string][]byte{}
	total := int64(0)
	for _, f := range z.File {
		if f.Name != "manifest.json" && f.Name != "manifest.sig" && f.Name != "records.csv" && f.Name != "public-keys.json" && f.Name != "readme.txt" || files[f.Name] != nil {
			return m, ErrInvalid
		}
		r, err := f.Open()
		if err != nil {
			return m, err
		}
		raw, err := io.ReadAll(io.LimitReader(r, int64(MaxArtifactBytes)-total+1))
		r.Close()
		if err != nil {
			return m, err
		}
		total += int64(len(raw))
		if total > MaxArtifactBytes {
			return m, ErrLimit
		}
		files[f.Name] = raw
	}
	if len(files) != 5 || strictjson.Decode(files["manifest.json"], &m) != nil || m.Schema != "evidence-export-v1" || len(m.Files) != 3 || !validManifestColumns(m) {
		return m, ErrInvalid
	}
	var public struct {
		KeyID     uint32 `json:"signing_key_id"`
		Algorithm string `json:"algorithm"`
		Key       string `json:"public_key_base64"`
	}
	if strictjson.Decode(files["public-keys.json"], &public) != nil || public.KeyID != m.KeyID || public.KeyID != 10 || public.Algorithm != "Ed25519" || public.Key != base64.StdEncoding.EncodeToString(key) {
		return m, ErrInvalid
	}
	digest := sha256.Sum256(files["manifest.json"])
	if !ed25519.Verify(key, digest[:], files["manifest.sig"]) {
		return m, ErrInvalid
	}
	seen := map[string]bool{}
	for _, v := range m.Files {
		if seen[v.Name] || v.Name == "manifest.json" || v.Name == "manifest.sig" || files[v.Name] == nil || domain.U64(len(files[v.Name])) != v.Bytes || sha256.Sum256(files[v.Name]) != v.SHA {
			return m, ErrInvalid
		}
		seen[v.Name] = true
	}
	count, e := countCSVRecords(files["records.csv"])
	if e != nil {
		return m, e
	}
	if count != m.Count {
		return m, fmt.Errorf("export count mismatch")
	}
	return m, nil
}

// validManifestColumns は未受理の提出物から本文・投稿資格の列を排除する。
func validManifestColumns(m Manifest) bool {
	switch m.RecordKind {
	case "":
		return ValidColumns(m.Columns)
	case rejectedExportKind, "http_observation":
		return app.ValidRejectedColumns(m.Columns)
	default:
		return false
	}
}
