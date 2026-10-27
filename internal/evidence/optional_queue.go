// 非必須の試行・応答・閲覧記録を有界で保存し、欠測を主体情報なしの集計へ残す。
package evidence

import (
	"context"
	"errors"
	"math"
	"net/http"
	"oimobbs/internal/domain"
	"slices"
	"strings"
	"sync"
	"time"
)

// 短い集中到着を件数上限だけで落とさず、予約byte上限16MiBは別に維持する。
const MaxOptionalRecords = 4096
const MaxOptionalBytes = 16 << 20
const MaxOptionalRecordBytes = 64 << 10
const OptionalRetention = 7 * 24 * time.Hour

// optionalBatchWindow は非必須ログの低密度な到着をまとめる最大待ち時間。
// 必須投稿のSyncには使わず、256件到達・終了・取消では直ちに待ちを止める。
const optionalBatchWindow = 20 * time.Millisecond

// optionalBatchInterval は非必須保存の完了後、次の保存開始まで空ける最小間隔。
// 滞留が少ない間に適用し、集中到着・終了・取消では待機を解除する。
const optionalBatchInterval = 100 * time.Millisecond

// optionalBacklogThreshold は受付上限の手前で保存を再開する滞留件数。
// 一回の保存は256件・元JSON4MiB以内に保ち、投稿側のI/O優先判定を毎回通す。
const optionalBacklogThreshold = 4 * MaxOptionalBatch

// OptionalRecord は本文・Cookie・query・認証値を受け取らない非公開HTTP記録。
// Route/Outcomeは固定分類で、自由文のエラーや生URLを代入しない。Boardは未解決時にnull。
type OptionalRecord struct {
	Schema      string       `json:"schema"`
	ID          domain.ID    `json:"id"`
	Site        domain.ID    `json:"site_id"`
	Board       *domain.ID   `json:"board_id"`
	Boot        domain.ID    `json:"process_boot_id"`
	Connection  domain.ID    `json:"connection_id"`
	Request     domain.ID    `json:"request_id"`
	Operation   *domain.ID   `json:"accepted_operation_id"`
	Received    domain.Time  `json:"received_at_ns"`
	Finished    domain.Time  `json:"finished_at_ns"`
	Elapsed     domain.U64   `json:"monotonic_elapsed_ns"`
	Until       domain.Time  `json:"retention_until_ns"`
	Peer        Endpoint     `json:"peer"`
	Local       Endpoint     `json:"local"`
	TLSVersion  *uint16      `json:"tls_version"`
	TLSCipher   *uint16      `json:"tls_cipher_suite"`
	Method      string       `json:"method"`
	Route       string       `json:"route"`
	Kind        string       `json:"kind"`
	Outcome     string       `json:"outcome"`
	Status      int          `json:"http_status"`
	Bytes       domain.U64   `json:"written_bytes"`
	WriteFailed bool         `json:"write_failed"`
	Canceled    bool         `json:"request_canceled"`
	UAStatus    string       `json:"user_agent_capture_status"`
	FinishStage string       `json:"finish_stage"`
	HTTPVersion string       `json:"http_version"`
	UserAgent   *HeaderValue `json:"user_agent"`
}

// Validate は非必須記録の固定型・期限・値域を検査し、秘密を含む自由形式の分類を拒否する。
func (r OptionalRecord) Validate() error {
	if r.Schema != "optional-http-v1" || r.ID == (domain.ID{}) || r.Site == (domain.ID{}) || r.Boot == (domain.ID{}) || r.Connection == (domain.ID{}) || r.Request == (domain.ID{}) || r.Received <= 0 || r.Finished <= 0 || r.Received > domain.Time(math.MaxInt64-int64(OptionalRetention)) || r.Until != r.Received+domain.Time(OptionalRetention) || !validEndpoint(r.Peer) || !validEndpoint(r.Local) {
		return ErrHTTPObservation
	}
	if !slices.Contains([]string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodPatch, http.MethodConnect, http.MethodTrace, "OTHER"}, r.Method) || !slices.Contains([]string{"home", "board", "thread", "dat", "settings", "bbsmenu", "search", "asset", "legacy_post", "web_post", "other"}, r.Route) || !slices.Contains([]string{"attempt", "response", "access"}, r.Kind) || !slices.Contains([]string{"accepted", "duplicate", "confirmation", "rejected", "uncertain", "served", "interrupted"}, r.Outcome) || r.Status != 0 && (r.Status < 100 || r.Status > 599) || !slices.Contains([]string{"HTTP/1.0", "HTTP/1.1", "HTTP/2.0"}, r.HTTPVersion) {
		return ErrHTTPObservation
	}
	if r.Board != nil && *r.Board == (domain.ID{}) || r.Operation != nil && (*r.Operation == (domain.ID{}) || !slices.Contains([]string{"accepted", "duplicate", "interrupted"}, r.Outcome)) || (r.TLSVersion == nil) != (r.TLSCipher == nil) {
		return ErrHTTPObservation
	}
	if r.UserAgent != nil {
		raw, e := decodeHeaderValue(*r.UserAgent)
		if e != nil || len(raw) > MaxObservedHeaderBytes {
			return ErrHTTPObservation
		}
	}
	if !slices.Contains([]string{"captured", "truncated", "unavailable"}, r.UAStatus) {
		return ErrHTTPObservation
	}
	if r.FinishStage != "handler_return" {
		return ErrHTTPObservation
	}
	return nil
}

// OptionalStatus は欠測件数と発生期間。IP・本文・失敗errorの自由文を含めない。
type OptionalStatus struct {
	Accepted        uint64      `json:"accepted"`
	Saved           uint64      `json:"saved"`
	Failed          uint64      `json:"failed"`
	DroppedCapacity uint64      `json:"dropped_capacity"`
	DroppedInvalid  uint64      `json:"dropped_invalid"`
	DroppedClosed   uint64      `json:"dropped_closed"`
	DroppedShutdown uint64      `json:"dropped_shutdown"`
	LossStarted     domain.Time `json:"loss_started_at_ns"`
	LossFinished    domain.Time `json:"loss_finished_at_ns"`
	Pending         int         `json:"pending"`
	PendingBytes    int         `json:"pending_bytes"`
	Closed          bool        `json:"closed"`
}

// OptionalQueue は保存中の予約も上限に含めるキュー。必須投稿の保存には使用しない。
// writeは渡した値を耐久保存する。終了取消に従い、長時間の外部通信を行わないこと。
type OptionalQueue struct {
	mu            sync.Mutex
	status        OptionalStatus
	queue         chan *optionalQueuedRecord
	done          chan struct{}
	cancel        context.CancelFunc
	write         func(context.Context, OptionalRecord) error
	batchWrite    func(context.Context, []OptionalRecord) []error
	batchWait     time.Duration
	batchInterval time.Duration
	closing       chan struct{}
	backlog       chan struct{}
}

// NewOptionalQueue は二つの保存workerを起動する。CloseとDoneで終了を管理する。
func NewOptionalQueue(write func(context.Context, OptionalRecord) error) (*OptionalQueue, error) {
	if write == nil {
		return nil, errors.New("optional log writer required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &OptionalQueue{queue: make(chan *optionalQueuedRecord, MaxOptionalRecords), done: make(chan struct{}), closing: make(chan struct{}), cancel: cancel, write: write}
	var workers sync.WaitGroup
	workers.Add(2)
	for i := 0; i < 2; i++ {
		go func() { defer workers.Done(); q.run(ctx) }()
	}
	go func() { workers.Wait(); cancel(); close(q.done) }()
	return q, nil
}

// NewOptionalBatchQueueは一つの保存workerで最大20ms・256件をまとめる。
// 通常は保存完了後100ms以上空け、1,024件以上の滞留では待機を解除する。
// 終了時は待たず保存し、保存中の行も件数・bytes上限へ含める。
// writeは入力と同じ長さの結果を返し、nilの行は耐久保存済みとする。
func NewOptionalBatchQueue(write func(context.Context, []OptionalRecord) []error) (*OptionalQueue, error) {
	if write == nil {
		return nil, errors.New("optional batch writer required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &OptionalQueue{queue: make(chan *optionalQueuedRecord, MaxOptionalRecords), done: make(chan struct{}), closing: make(chan struct{}), backlog: make(chan struct{}, 1), cancel: cancel, batchWrite: write, batchWait: optionalBatchWindow, batchInterval: optionalBatchInterval}
	go func() { defer close(q.done); defer cancel(); q.run(ctx) }()
	return q, nil
}

// Enqueue はJSONサイズを上限へ予約し、独立した型付き値を保存workerへ渡す。
// 保存待ちをせず返る。falseは集計済みの欠測。
func (q *OptionalQueue) Enqueue(record OptionalRecord) bool {
	if e := record.Validate(); e != nil {
		q.invalid()
		return false
	}
	raw, e := MarshalOptionalRecord(record)
	if e != nil || len(raw) > MaxOptionalRecordBytes {
		q.invalid()
		return false
	}
	size := len(raw)
	clear(raw)
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.status.Closed {
		q.status.DroppedClosed++
		q.loss()
		return false
	}
	if q.status.Pending >= MaxOptionalRecords || size > MaxOptionalBytes-q.status.PendingBytes {
		q.status.DroppedCapacity++
		q.loss()
		return false
	}
	q.status.Accepted++
	q.status.Pending++
	q.status.PendingBytes += size
	q.queue <- &optionalQueuedRecord{record: cloneOptionalRecord(record), bytes: size}
	if q.status.Pending >= optionalBacklogThreshold || q.status.PendingBytes >= MaxOptionalBytes/2 {
		select {
		case q.backlog <- struct{}{}:
		default:
		}
	}
	return true
}

// BacklogPressure は受付列が集中到着または予約byteの半分に達したことを返す。
// 保存中の行も含む既存上限を変えず、所有側が保存の飢餓を防ぐ判断に使う。
func (q *OptionalQueue) BacklogPressure() bool {
	status := q.Status()
	return status.Pending >= optionalBacklogThreshold || status.PendingBytes >= MaxOptionalBytes/2
}

// BacklogSignal は唯一のbatch保存workerに渡す再判定通知。通知後もPressureの再確認が必要。
func (q *OptionalQueue) BacklogSignal() <-chan struct{} { return q.backlog }

func (q *OptionalQueue) invalid() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.status.DroppedInvalid++
	q.loss()
}

// loss は欠測期間の先頭と末尾を更新する。q.muを保持して呼ぶ。
func (q *OptionalQueue) loss() {
	now := domain.Time(time.Now().UnixNano())
	if q.status.LossStarted == 0 {
		q.status.LossStarted = now
	}
	q.status.LossFinished = now
}

// run は保存結果が確定してからメモリ予約を返す。取消後の未開始行は欠測として数える。
func (q *OptionalQueue) run(ctx context.Context) {
	var nextBatch time.Time
	var carry []*optionalQueuedRecord
	for {
		var first *optionalQueuedRecord
		if len(carry) > 0 {
			first, carry = carry[0], carry[1:]
		} else {
			var ok bool
			first, ok = <-q.queue
			if !ok {
				break
			}
		}
		batch := []*optionalQueuedRecord{first}
		if q.batchWrite != nil {
			q.waitBatch(ctx, nextBatch)
			batch, carry = q.gatherOptionalBatch(ctx, first, carry)
		}
		abandoned := ctx.Err() != nil
		results := make([]error, len(batch))
		if !abandoned {
			if q.batchWrite != nil {
				records := make([]OptionalRecord, len(batch))
				for i, entry := range batch {
					records[i] = entry.record
				}
				results = q.batchWrite(ctx, records)
				nextBatch = time.Now().Add(q.batchInterval)
				if len(results) != len(batch) {
					results = make([]error, len(batch))
					for i := range results {
						results[i] = errors.New("optional batch result mismatch")
					}
				}
			} else {
				results[0] = q.write(ctx, first.record)
			}
		}
		q.mu.Lock()
		for i, entry := range batch {
			q.status.Pending--
			q.status.PendingBytes -= entry.bytes
			switch {
			case abandoned:
				q.status.DroppedShutdown++
				q.loss()
			case results[i] != nil:
				q.status.Failed++
				q.loss()
			default:
				q.status.Saved++
			}
			*entry = optionalQueuedRecord{}
		}
		q.mu.Unlock()
	}

}

// waitBatch は低密度な非必須I/Oを間引き、集中到着・停止・取消で待機を解除する。
func (q *OptionalQueue) waitBatch(ctx context.Context, next time.Time) {
	delay := time.Until(next)
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		if q.Status().Pending >= optionalBacklogThreshold {
			return
		}
		select {
		case <-timer.C:
			return
		case <-ctx.Done():
			return
		case <-q.closing:
			return
		case <-q.backlog:
		}
	}
}

// Status は主体情報のない集計snapshotを返す。
func (q *OptionalQueue) Status() OptionalStatus { q.mu.Lock(); defer q.mu.Unlock(); return q.status }

// Close は受付を止め、期限内は保存完了を待つ。期限到達はworkerを取消し呼出元へ返す。
// 期限で返った場合もDoneを待つと、保存callbackと全予約の終了を確認できる。
func (q *OptionalQueue) Close(ctx context.Context) error {
	q.mu.Lock()
	if !q.status.Closed {
		q.status.Closed = true
		if q.closing != nil {
			close(q.closing)
		}
		close(q.queue)
	}
	q.mu.Unlock()
	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		q.cancel()
		return ctx.Err()
	}
}

// Done は全保存workerが終了したとき閉じる。HTTP要求内で待機しない。
func (q *OptionalQueue) Done() <-chan struct{} { return q.done }

// optionalQueuedRecord は所有権を独立させた値と、既存JSON基準の容量予約。
type optionalQueuedRecord struct {
	record OptionalRecord
	bytes  int
}

// cloneOptionalRecord は呼出元のpointer変更とHTTPヘッダbufferの保持を切り離す。
func cloneOptionalRecord(record OptionalRecord) OptionalRecord {
	record.Board = cloneOptionalField(record.Board)
	record.Operation = cloneOptionalField(record.Operation)
	record.TLSVersion = cloneOptionalField(record.TLSVersion)
	record.TLSCipher = cloneOptionalField(record.TLSCipher)
	record.UserAgent = cloneOptionalField(record.UserAgent)
	if record.UserAgent != nil {
		record.UserAgent.Base64 = strings.Clone(record.UserAgent.Base64)
		record.UserAgent.Display = strings.Clone(record.UserAgent.Display)
	}
	return record
}

// cloneOptionalField はnilを保ち、参照先の値だけを独立させる。
func cloneOptionalField[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
