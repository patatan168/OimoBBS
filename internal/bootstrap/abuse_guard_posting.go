// サイト共通の検出器を投稿確定・一括保存取消・署名照合後の復旧へ接続する。
package bootstrap

import (
	"context"
	"encoding/json"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"sort"
	"time"
)

// guardCandidate は検証済みframeの利用者投稿だけから秘密なしの比較材料を作る。
func (b *postingBoard) guardCandidate(op domain.Operation, id domain.ID, key uint64, rate app.RateRecord) (guardEntry, error) {
	var posts []domain.Post
	var title string
	if op.Type == "create" {
		var v domain.Create
		if err := json.Unmarshal(op.Payload, &v); err != nil {
			return guardEntry{}, err
		}
		posts = v.Posts
		title = v.Title
	} else {
		var v domain.Append
		if err := json.Unmarshal(op.Payload, &v); err != nil {
			return guardEntry{}, err
		}
		posts = v.Posts
	}
	if len(posts) == 0 {
		return guardEntry{}, store.ErrCorrupt
	}
	e := guardEntry{body: posts[0].Body, title: title, name: posts[0].Name, mail: posts[0].Mail, rawIP: rate.IP, create: op.Type == "create", id: id, board: b.owner, thread: key, number: posts[0].Number, at: op.Committed, ip: b.guardIPSubject(rate.IP), signature: guardBodySignature(posts[0].Body), cap: op.Actor.Kind == "cap"}
	if rate.TokenStatus == "valid" && rate.Token != nil {
		e.token = rate.Token.Subject
	}
	return e, nil
}

// reserveGuard は異なる板の並列投稿もサイトmutexで一件ずつ数え、未確定候補も比較対象にする。
func (b *postingBoard) reserveGuard(e guardEntry) error {
	g := b.guard
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// 共通検出器の時計はサイトの実時間とし、板の投稿表示用時計から独立させる。
	now := domain.Time(time.Now().UnixNano())
	if now < g.floor {
		return abuse.ErrRateClock
	}
	e.at = now
	b.pruneGuardCandidate(e.thread, e.at)
	if err := g.check(e); err != nil {
		return err
	}
	e.body = ""
	e.title = ""
	e.name = ""
	e.mail = ""
	e.rawIP = ""
	e.match = nil
	e.pending = true
	g.remember(e)
	return nil
}

// settleGuard は実保存結果で候補を確定または返却する。再送・拒否は件数に加算しない。
func (b *postingBoard) settleGuard(id domain.ID, durable bool) {
	if b.guard == nil {
		return
	}
	b.guard.mu.Lock()
	defer b.guard.mu.Unlock()
	b.guard.settle(id, durable)
}

// restoreAbuseGuard は起動時の署名照合済み現用投稿から直近10分の索引を再構築する。
func (r *Repository) restoreAbuseGuard() error {
	g := r.guard
	if g == nil {
		g = &abuseGuard{settings: defaultAbuseGuard()}
		r.guard = g
	}
	if row, ok := r.site.State().Rows["abuse_guard:active"]; ok {
		var v guardState
		if err := json.Unmarshal(row.Value, &v); err != nil {
			return err
		}
		g.mu.Lock()
		g.settings = v.Settings
		g.configured = true
		g.floor = v.Changed
		g.mu.Unlock()
	}
	now := domain.Time(time.Now().UnixNano())
	var restored guardRestore
	var initialWait uint32
	var initialRates *AdminRateSettings
	for _, b := range r.posting {
		_, err := b.worker.Submit(context.Background(), func() (any, error) {
			b.guard = g
			if !g.configured {
				var v boardValue
				if err := strictjson.Decode(b.control.State().Rows["board:state"].Value, &v); err != nil {
					return nil, err
				}
				initialWait = max(initialWait, v.Settings.Posting.TokenWait)
				rates := b.postingPolicy.Rates
				if b.postingPolicy.At == 0 {
					rates = defaultRateSettings()
					if b.admission != nil {
						rates = b.admission.policy.Defaults
					}
				}
				if initialRates == nil {
					initialRates = &rates
				} else {
					initialRates.Enabled = initialRates.Enabled || rates.Enabled
					initialRates.ReplySeconds = max(initialRates.ReplySeconds, rates.ReplySeconds)
					initialRates.ReplyBurst = min(initialRates.ReplyBurst, rates.ReplyBurst)
					initialRates.CreateSeconds = max(initialRates.CreateSeconds, rates.CreateSeconds)
					initialRates.CreateBurst = min(initialRates.CreateBurst, rates.CreateBurst)
					initialRates.CreateWindow = min(initialRates.CreateWindow, rates.CreateWindow)
				}
			}
			for key, p := range b.threads {
				err := p.VisitRecentAbusePosts(now, now-guardHistorySeconds*1e9, func(id domain.ID, post domain.Post, token *postcapture.TokenEvidence) {
					e := guardEntry{id: id, board: b.owner, thread: key, number: post.Number, at: post.Created, ip: b.guardIPSubject(post.Private.SourceIP), cap: post.Private.CapID != nil}
					if token != nil {
						e.token = token.Subject
					}
					restored.add(e, post.Body)
				})
				if err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
		if err != nil {
			return err
		}
	}
	entries := restored.finish()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].at == entries[j].at {
			return entries[i].id.String() < entries[j].id.String()
		}
		return entries[i].at < entries[j].at
	})
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.configured {
		g.settings.TokenWaitSeconds = initialWait
		if initialRates != nil {
			g.settings.Rates = *initialRates
		}
	}
	g.overflowUntil = restored.overflow
	g.entries = entries
	g.flood = nil
	g.pending = 0
	g.signatureFloor = 0
	r.bot.configure(g.settings.BotMode)
	g.trimSignatures()
	for _, e := range entries {
		g.floor = max(g.floor, e.at)
	}
	if now < g.floor {
		return app.ErrEvidenceGap
	}
	return nil
}

// updateGuardCandidate はスレ立ての採番後に未確定索引へ実際の公開参照を設定する。
func (b *postingBoard) updateGuardCandidate(id domain.ID, key uint64, number uint32) {
	if b.guard == nil {
		return
	}
	b.guard.mu.Lock()
	defer b.guard.mu.Unlock()
	for i := len(b.guard.entries) - 1; i >= 0; i-- {
		if b.guard.entries[i].id == id {
			if b.guard.entries[i].thread != key {
				b.guard.flood = nil
			}
			b.guard.entries[i].thread = key
			b.guard.entries[i].number = number
			return
		}
	}
}

// guardTokenWait は保存済みの共通Cookie待機時間を優先する。未保存時だけ旧板設定を維持する。
func (b *postingBoard) guardTokenWait(fallback uint32) uint32 {
	if b.guard == nil {
		return fallback
	}
	b.guard.mu.Lock()
	defer b.guard.mu.Unlock()
	if b.guard.configured {
		return b.guard.settings.TokenWaitSeconds
	}
	return fallback
}

// pruneGuard は削除確定・期限到達後に本文由来の索引と検出参照を除く。板所有列専用。
func (b *postingBoard) pruneGuard() {
	if b.guard == nil {
		return
	}
	g := b.guard
	g.mu.Lock()
	defer g.mu.Unlock()
	if b.group != nil {
		b.group.guardPruning = nil
	}
	// 共通検出器の時計はサイトの実時間とし、板の投稿表示用時計から独立させる。
	now := domain.Time(time.Now().UnixNano())
	g.prune(now, b.guardVisibility(now))
}

// guardVisibility は一走査だけ公開gateをスレッドごとに照合し、削除・非公開・期限を反映する。
func (b *postingBoard) guardVisibility(now domain.Time) func(domain.ID, uint64, uint32) bool {
	states := make(map[uint64]app.AbuseVisibility, min(16, len(b.threads)))
	return func(owner domain.ID, key uint64, number uint32) bool {
		if owner != b.owner {
			return true
		}
		state, ok := states[key]
		if !ok {
			if p := b.threads[key]; p != nil {
				state = p.AbuseVisibility(now)
			}
			states[key] = state
		}
		return state.Visible(number)
	}
}
