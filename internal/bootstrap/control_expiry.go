// 短命の制御行を耐久時刻付きで有界回収し、規制・再送記録の時計逆行を保守的に拒否する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// ErrControlExpiryClock は規制履歴の回収境界より時計が戻り、安全に受付できないことを示す。
var ErrControlExpiryClock = errors.New("clock precedes durable control cleanup boundary")

type controlExpiryWatermark struct {
	At domain.Time `json:"observed_at_ns"`
}

// validateControlExpiryWatermark は回収時刻を単調増加させ、時計逆行時の枠リセットを防ぐ。
func validateControlExpiryWatermark(key string, old, next json.RawMessage) error {
	var v controlExpiryWatermark
	if key != "control" || strictjson.Decode(next, &v) != nil || v.At <= 0 {
		return store.ErrCorrupt
	}
	if len(old) > 0 {
		var prior controlExpiryWatermark
		if strictjson.Decode(old, &prior) != nil || v.At <= prior.At {
			return store.ErrCorrupt
		}
	}
	return nil
}

// EnableControlExpiry はnullによる満了行回収を書き始める前に最低reader21を同期する。
func (r *Repository) EnableControlExpiry(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader >= 21 {
		return nil
	}
	site.MinimumReader = 21
	if e := appendControl(r.site, "control_expiry_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}

// ControlExpiryReport は状態行から除去した件数を返す。旧WAL全コピーの物理消去を示さない。
type ControlExpiryReport struct {
	Site   int  `json:"site_rows_removed"`
	Boards int  `json:"board_rows_removed"`
	More   bool `json:"more"`
}

// SweepExpiredControl は所有単位ごと最大limit行を回収する。limitは1..128。
// 元満了を延長せず、有効な再送receipt・発行規制履歴・失効記録を除去しない。
func (r *Repository) SweepExpiredControl(ctx context.Context, limit int) (ControlExpiryReport, error) {
	return r.sweepExpiredControl(ctx, limit, time.Now)
}

func (r *Repository) sweepExpiredControl(ctx context.Context, limit int, clock func() time.Time) (ControlExpiryReport, error) {
	return r.sweepExpiredControlMode(ctx, limit, clock, false)
}

// sweepExpiredControlMode は周期保守だけ混雑板を延期し、明示回収の完了条件は維持する。
func (r *Repository) sweepExpiredControlMode(ctx context.Context, limit int, clock func() time.Time, idle bool) (report ControlExpiryReport, err error) {
	if limit < 1 || limit > 128 {
		return report, errors.New("control expiry limit must be 1..128")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err = r.available(); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	var site siteState
	if err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return report, err
	}
	if site.MinimumReader < 21 {
		return report, errors.New("enable control expiry before cleanup")
	}
	now := domain.Time(clock().UnixNano())
	if now <= 0 || int64(now) < r.controlExpiryFloor.Load() {
		return report, ErrControlExpiryClock
	}
	// 回収対象選択も同じサイトmutexの下で行う。未満了receiptが旧失効件数を参照する間は延期。
	names, err := expiredControlNames(r.site.State(), 1, now)
	if err != nil {
		return report, err
	}
	owners := make([]domain.ID, 0, len(r.posting))
	boardNames := map[domain.ID][]string{}
	for id, b := range r.posting {
		submit := b.worker.Submit
		if idle {
			submit = b.worker.SubmitIdle
		}
		value, e := submit(ctx, func() (any, error) { return expiredControlNames(b.control.State(), 2, now) })
		if idle && errors.Is(e, board.ErrBusy) {
			report.More = true
			continue
		}
		if e != nil {
			return report, e
		}
		list := value.([]string)
		if len(list) > 0 {
			owners = append(owners, id)
			boardNames[id] = list
		}
	}
	if len(names) == 0 && len(owners) == 0 {
		return report, nil
	}
	// 先に時刻をSyncし、途中停止して板だけを回収しても逆行した時計で稼働しない。
	if int64(now) > r.controlExpiryFloor.Load() {
		changes := []store.Mutation{mutation("expiry_watermark", "control", controlExpiryWatermark{now}, nil)}
		if err = appendControlAt(r.site, now, "control_expiry_boundary", changes); err != nil {
			r.stopped = true
			return report, err
		}
		r.controlExpiryFloor.Store(int64(now))
	}
	var more bool
	report.Site, more, err = expireControlRows(r.site, names, now, limit)
	report.More = report.More || more
	if err != nil {
		r.stopped = true
		return report, err
	}
	if report.Site > 0 && r.anonymous != nil {
		if err = r.refreshAnonymousRevocations(); err != nil {
			r.stopped = true
			return report, err
		}
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].String() < owners[j].String() })
	for _, id := range owners {
		b := r.posting[id]
		submit := b.worker.Submit
		if idle {
			submit = b.worker.SubmitIdle
		}
		value, e := submit(ctx, func() (any, error) {
			count, more, e := expireControlRows(b.control, boardNames[id], now, limit)
			if e != nil {
				b.stopped = true
			}
			return ControlExpiryReport{Boards: count, More: more}, e
		})
		if idle && errors.Is(e, board.ErrBusy) {
			report.More = true
			continue
		}
		if e != nil {
			return report, e
		}
		result := value.(ControlExpiryReport)
		report.Boards += result.Boards
		report.More = report.More || result.More
	}
	return report, nil
}

// expiredControlNames は回収可能な短命行だけを名前順に返す。
func expiredControlNames(state store.ControlState, kind uint16, now domain.Time) ([]string, error) {
	names := []string{}
	keepRevocations := false
	if kind == 1 {
		required, remaining := uint32(0), uint32(0)
		for name, row := range state.Rows {
			if strings.HasPrefix(name, "token_revocation:") {
				var record tokenRevocation
				if e := strictjson.Decode(row.Value, &record); e != nil {
					return nil, e
				}
				if record.Expires > now {
					remaining++
				}
			}
			if strings.HasPrefix(name, "admin_receipt:") && isAnonymousReceipt(row.Value) {
				var receipt anonymousReceipt
				if e := strictjson.Decode(row.Value, &receipt); e != nil {
					return nil, e
				}
				if receipt.Expires > now {
					required = max(required, receipt.Result.Revocations)
				}
			}
		}
		keepRevocations = required > remaining
	}
	for name, row := range state.Rows {
		collection, _, ok := strings.Cut(name, ":")
		if !ok {
			continue
		}
		allowed := kind == 1 && (collection == "posting_violation" || collection == "abuse_guard_receipt" || collection == "operations_receipt" || collection == "admin_receipt" || collection == "token_issue" || collection == "token_reissue" || collection == "token_revocation" && !keepRevocations) || kind == 2 && (collection == "cap_command" || collection == "admin_receipt" || collection == "rule_receipt" || collection == "thread_settings_receipt" || collection == "local_rules_receipt")
		if !allowed {
			continue
		}
		var fields map[string]json.RawMessage
		if e := strictjson.Decode(row.Value, &fields); e != nil {
			return nil, e
		}
		var expires domain.Time
		if e := json.Unmarshal(fields["expires_at_ns"], &expires); e != nil {
			return nil, e
		}
		if expires <= now {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// expireControlRows はCASで限定行を一括除去し、再送の満了を確定時刻で検査する。
func expireControlRows(log *store.ControlLog, names []string, now domain.Time, limit int) (int, bool, error) {
	if len(names) == 0 {
		return 0, false, nil
	}
	state := log.State()
	changes := []store.Mutation{}
	for _, name := range names[:min(len(names), limit)] {
		collection, key, _ := strings.Cut(name, ":")
		row := state.Rows[name]
		changes = append(changes, store.Mutation{Collection: collection, Key: key, ExpectedRevision: row.Revision, Value: json.RawMessage("null")})
	}
	if e := appendControlAt(log, now, "expired_records_cleanup", changes); e != nil {
		return 0, true, e
	}
	return len(changes), len(names) > limit, nil
}

// appendControlAt は全mutationの確定時刻を固定し、回収境界と満了の比較を再生可能にする。
func appendControlAt(log *store.ControlLog, now domain.Time, reason string, changes []store.Mutation) error {
	frame, e := controlFrame(log.State(), domain.NewID(), now, reason, changes, []string{})
	if e != nil {
		return e
	}
	result := log.Append(frame)
	if result.Status != store.Durable {
		return errors.Join(ErrPostingUnavailable, result.Err)
	}
	return nil
}

// refreshAnonymousRevocations は共有mapを変更せず、Sync後の失効集合をatomicに配布する。
func (r *Repository) refreshAnonymousRevocations() error {
	current := r.anonymous
	next := &anonymousState{policy: current.policy, key: current.key, revoked: map[domain.Hash]tokenRevocation{}}
	for name, row := range r.site.State().Rows {
		if strings.HasPrefix(name, "token_revocation:") {
			var record tokenRevocation
			if e := strictjson.Decode(row.Value, &record); e != nil {
				return e
			}
			next.revoked[record.Subject] = record
		}
	}
	r.anonymous = next
	r.liveAnonymous.Store(next)
	return nil
}

// RunControlExpiryMaintenance は起動後直ちに走査し、以後一分ごとに取りこぼしを回収する。
func (r *Repository) RunControlExpiryMaintenance(ctx context.Context) error {
	for {
		if _, e := r.sweepExpiredControlMode(ctx, 128, time.Now, true); e != nil {
			return e
		}
		if e := r.sweepReports(time.Now()); e != nil {
			return e
		}
		// 履歴予算の消費は確定済み位置を保持した次周期の再開で処理する。
		// 有界走査の未完了だけで公開サーバーを停止せず、破損・保存失敗は伝播する。
		if e := r.maintainThreadAudits(ctx); e != nil && !onlyAuditHistoryBudget(e) {
			return e
		}
		timer := time.NewTimer(time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// onlyAuditHistoryBudget は有界走査の未完了だけを延期する。併記された保存失敗は延期しない。
func onlyAuditHistoryBudget(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyAuditHistoryBudget(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyAuditHistoryBudget(wrapped.Unwrap())
	}
	return err == store.ErrHistoryBudget
}
