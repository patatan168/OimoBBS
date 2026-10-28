// 通常返信による通報を重複排除し、保存済み匿名主体に期限付き規制を適用する。
package bootstrap

import (
	"context"
	"errors"
	"html"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
)

const autoReportWindow = 24 * time.Hour
const autoReportStop = 10 * time.Minute
const autoReportQuorum = 3
const autoReportCapacity = 1024

// ErrAutoReportInput は短い通報の対象番号が不正な場合に返す。
var ErrAutoReportInput = errors.New("report requires a valid response number")

// AutoReportConfig は専用通報板と受付開始時刻を指定する。省略時は自動停止しない。
// Sinceは再起動時に変更せず、導入前の通報を新しい規制へ読み替えない。
type AutoReportConfig struct {
	BoardKey string `json:"board_key"`
	Since    string `json:"since"`
}

type autoReportTarget struct {
	Board   domain.ID
	Subject domain.Hash
}
type autoReportVote struct {
	Operation domain.ID
	Reporter  domain.Hash
	IP        domain.Hash
	At        domain.Time
	Reference autoReportReference
}
type autoReportReference struct {
	Board string `json:"board_key"`
	Key   uint64 `json:"thread_key"`
	Post  uint32 `json:"post_number"`
}
type autoReportMessage struct {
	Reference autoReportReference
	Operation domain.ID
	Reporter  app.EvidencePostIdentity
	At        domain.Time
}

// autoReportNetwork は通報票の重複判定に使うIPv4アドレスまたはIPv6 /64を返す。
// 不正なIPは票にせず、IPv4射影IPv6はIPv4と同一に扱う。原本のIPは変更しない。
func autoReportNetwork(raw string) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return ""
	}
	ip = ip.Unmap()
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().String()
	}
	return ip.String()
}

// autoReportCommandTarget は短い通報の対象表記とコマンドの有無を返す。
// アンカーとコマンドの区切りは空白/改行。旧書式も受理済み原本の復旧のため読む。
func autoReportCommandTarget(body string) (string, bool) {
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "!report") && !strings.HasPrefix(body, ">>") {
		return "", false
	}
	parts := strings.Fields(body)
	if parts[0] == "!report" {
		if len(parts) < 2 {
			return "", true
		}
		return parts[1], true
	}
	if len(parts) >= 2 && strings.HasPrefix(parts[0], ">>") && parts[1] == "!report" {
		return parts[0], true
	}
	return "", false
}

// parseAutoReportCommand は同じスレッドの一レスを指定する。理由は任意で、曖昧な番号は拒否する。
func parseAutoReportCommand(body string) (uint32, bool) {
	target, command := autoReportCommandTarget(body)
	if !command {
		return 0, false
	}
	number := strings.TrimPrefix(target, ">>")
	n, err := strconv.ParseUint(number, 10, 32)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != number {
		return 0, false
	}
	return uint32(n), true
}

// parseAutoReport は一レスの同一origin URLと空でない理由を要求する。範囲・他サイトは扱わない。
func parseAutoReport(body, origin string) (autoReportReference, bool) {
	var target, reason string
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"対象URL：", "対象URL:", "通報：", "通報:"} {
			if strings.HasPrefix(line, prefix) {
				if target != "" {
					return autoReportReference{}, false
				}
				target = strings.TrimSpace(strings.TrimPrefix(line, prefix))
			}
		}
		for _, prefix := range []string{"理由：", "理由:"} {
			if strings.HasPrefix(line, prefix) {
				reason = strings.TrimSpace(strings.TrimPrefix(line, prefix))
			}
		}
	}
	if target == "" || reason == "" {
		return autoReportReference{}, false
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme+"://"+u.Host != origin || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return autoReportReference{}, false
	}
	parts := strings.Split(strings.TrimSuffix(u.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "test" || parts[2] != "read.cgi" || !validBoardKey(parts[3]) {
		return autoReportReference{}, false
	}
	key, e1 := strconv.ParseUint(parts[4], 10, 64)
	post, e2 := strconv.ParseUint(parts[5], 10, 32)
	if e1 != nil || e2 != nil || key == 0 || post == 0 || strconv.FormatUint(key, 10) != parts[4] || strconv.FormatUint(post, 10) != parts[5] {
		return autoReportReference{}, false
	}
	return autoReportReference{parts[3], key, uint32(post)}, true
}

// collectAutoReport は現在の24時間窓だけを保持する。同一IDまたは同一接続元の追加票を数えない。
func collectAutoReport(votes []autoReportVote, next autoReportVote) ([]autoReportVote, bool) {
	return collectAutoReportWithPolicy(votes, next, defaultReportPolicy())
}

// collectAutoReportWithPolicy は指定窓と票数を使い、同じ主体・接続元のHMACを重複集計しない。
func collectAutoReportWithPolicy(votes []autoReportVote, next autoReportVote, p ReportPolicy) ([]autoReportVote, bool) {
	kept := make([]autoReportVote, 0, p.Quorum)
	duplicate := false
	latest := next.At
	for _, vote := range votes {
		latest = max(latest, vote.At)
	}
	for _, vote := range votes {
		if vote.At <= latest-domain.Time(p.window()) {
			continue
		}
		kept = append(kept, vote)
		duplicate = duplicate || vote.Operation == next.Operation || vote.Reporter == next.Reporter || vote.IP == next.IP
	}
	added := !duplicate && next.At > latest-domain.Time(p.window()) && len(kept) < p.Quorum
	if added {
		kept = append(kept, next)
	}
	slices.SortFunc(kept, func(a, b autoReportVote) int {
		if a.At < b.At {
			return -1
		}
		if a.At > b.At {
			return 1
		}
		return 0
	})
	return kept, added && len(kept) == p.Quorum
}

// autoReportJournals は板worker内で参照する。日付で絞り、通常投稿で原本を走査しない。
func autoReportJournals(b *postingBoard, from time.Time) []*evidence.Journal {
	var out []*evidence.Journal
	first, _ := strconv.ParseUint(from.UTC().Format("20060102"), 10, 64)
	var days []uint64
	for day := range b.journals {
		if day >= first {
			days = append(days, day)
		}
	}
	slices.Sort(days)
	for _, day := range days {
		out = append(out, b.journals[day])
	}
	return out
}

// restoreAutoReports は直近の受理原本から票を再構築する。保存失敗のproposalは票にしない。
func (r *Repository) restoreAutoReports() error {
	if r.cfg.AutoReports == nil {
		return nil
	}
	for id, b := range r.posting {
		if b.matchesKey(r.cfg.AutoReports.BoardKey) {
			r.autoReportBoard = id
			break
		}
	}
	if r.autoReportBoard == (domain.ID{}) {
		return errors.New("automatic report board does not exist")
	}
	if err := r.initReportReceipts(); err != nil {
		return err
	}
	r.autoReportVotes = make(map[autoReportTarget][]autoReportVote)
	now := time.Now()
	since := r.reportSince()
	from := max(domain.Time(now.Add(-r.operations().Reports.window()).UnixNano()), since)
	groups := make(map[autoReportReference][]autoReportMessage)
	for _, b := range r.posting {
		_, err := b.worker.Submit(context.Background(), func() (any, error) {
			err := app.VisitAcceptedRecordsInRange(autoReportJournals(b, time.Unix(0, int64(from))), func(owner domain.ID, _ domain.U64, at domain.Time, _ domain.ID) bool {
				return owner == b.owner && at >= from && at <= domain.Time(now.UnixNano())
			}, func(row app.AcceptedEvidence) error {
				message, ok, err := r.prepareAutoReport(row, domain.Time(now.UnixNano()))
				if err != nil || !ok {
					return err
				}
				group := groups[message.Reference]
				// 自己通報一件が先に入っていても、対象照合後に必要票数を復元できるよう一件分だけ余裕を持つ。
				if len(group) >= r.operations().Reports.Quorum+1 || group == nil && len(groups) >= autoReportCapacity {
					return nil
				}
				for _, prior := range group {
					if prior.Reporter.Subject == message.Reporter.Subject || autoReportNetwork(prior.Reporter.IP) == autoReportNetwork(message.Reporter.IP) {
						return nil
					}
				}
				groups[message.Reference] = append(group, message)
				return nil
			})
			return nil, err
		})
		if err != nil {
			return err
		}
	}
	var messages []autoReportMessage
	for _, group := range groups {
		messages = append(messages, group...)
	}
	slices.SortFunc(messages, func(a, b autoReportMessage) int {
		if a.At < b.At {
			return -1
		}
		if a.At > b.At {
			return 1
		}
		return strings.Compare(a.Operation.String(), b.Operation.String())
	})
	for _, message := range messages {
		if err := r.applyAutoReport(message, domain.Time(now.UnixNano())); err != nil {
			return err
		}
	}
	return r.restorePrivateReportVotes(domain.Time(now.UnixNano()))
}

// acceptAutoReport はsource workerを解放してから判定する。確定済み投稿は副作用失敗でも受理のままとする。
// 失敗時はwriterを止め、再起動時に署名済み原本から未反映の規制を再開する。
func (r *Repository) acceptAutoReport(owner domain.ID, key uint64, post uint32) {
	if r.cfg.AutoReports == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.stopped {
		return
	}
	now := domain.Time(time.Now().UnixNano())
	b := r.posting[owner]
	value, err := b.worker.Submit(context.Background(), func() (any, error) {
		return app.AcceptedRecordsForPost(autoReportJournals(b, time.Now().Add(-r.operations().Reports.window())), owner, domain.U64(key), post, "post", now, 1)
	})
	if err == nil {
		for _, row := range value.([]app.AcceptedEvidence) {
			var message autoReportMessage
			var ok bool
			message, ok, err = r.prepareAutoReport(row, now)
			if err == nil && ok {
				err = r.applyAutoReport(message, now)
			}
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		r.stopped = true
	}
}

// prepareAutoReport は原本の認証済み主体と指定URLだけを複製する。本文・UAを票のRAMに保持しない。
func (r *Repository) prepareAutoReport(row app.AcceptedEvidence, now domain.Time) (autoReportMessage, bool, error) {
	var message autoReportMessage
	since := r.reportSince()
	if row.Committed < since || row.Committed <= now-domain.Time(r.operations().Reports.window()) || row.Committed > now {
		return message, false, nil
	}
	body, err := row.ReportBody()
	if err != nil {
		return message, false, err
	}
	body = html.UnescapeString(body)
	ref, ok := parseAutoReport(body, r.cfg.Public.BaseURL)
	if row.Board != r.autoReportBoard {
		ok = false
	}
	if !ok && row.Thread != 0 {
		if post, command := parseAutoReportCommand(body); command {
			if source := r.posting[row.Board]; source != nil {
				ref, ok = autoReportReference{source.boardKey(), uint64(row.Thread), post}, true
			}
		}
	}
	if !ok {
		return message, false, nil
	}
	known := false
	for _, b := range r.posting {
		if b.matchesKey(ref.Board) && b.owner != r.autoReportBoard {
			settings := b.autoReports.Load()
			// 復旧時の候補上限を旧票で埋めず、新しい集計期間の票だけを残す。
			known = boardAutoReportsEnabled(settings) && (settings == nil || row.Committed >= settings.Since)
			break
		}
	}
	if !known {
		return message, false, nil
	}
	reporter, err := row.Identity()
	if err != nil {
		return message, false, err
	}
	if reporter.Subject == (domain.Hash{}) || autoReportNetwork(reporter.IP) == "" {
		return message, false, nil
	}
	reporter.Agents = nil
	return autoReportMessage{ref, row.Operation, reporter, row.Committed}, true, nil
}

// applyAutoReport は原本の匿名主体を対象にする。IP規制へ代替せず、キャップ投稿・自己通報は除く。
// Repository.mu所有中、または公開受付前だけ呼ぶ。対象workerとsource workerを同時に所有しない。
func (r *Repository) applyAutoReport(message autoReportMessage, now domain.Time) error {
	if message.At < r.reportSince() {
		return nil
	}
	if message.Reporter.Subject == (domain.Hash{}) || message.Reporter.Cap != (domain.ID{}) {
		return nil
	}
	ref, reporter := message.Reference, message.Reporter
	var target *postingBoard
	for _, b := range r.posting {
		if b.matchesKey(ref.Board) {
			target = b
			break
		}
	}
	if target == nil || target.owner == r.autoReportBoard {
		return nil
	}
	value, err := target.worker.Submit(context.Background(), func() (any, error) {
		settings := target.autoReports.Load()
		if !boardAutoReportsEnabled(settings) || settings != nil && message.At < settings.Since {
			return nil, nil
		}
		if target.stopped {
			return nil, ErrPostingUnavailable
		}
		journals := make([]*evidence.Journal, 0, len(target.journals))
		for _, journal := range target.journals {
			journals = append(journals, journal)
		}
		rows, err := app.AcceptedRecordsForPost(journals, target.owner, domain.U64(ref.Key), ref.Post, "post", now, 1)
		if err != nil || len(rows) == 0 {
			return nil, err
		}
		person, err := rows[0].Identity()
		if err != nil {
			return nil, err
		}
		if person.Subject == (domain.Hash{}) || person.Cap != (domain.ID{}) || person.Subject == reporter.Subject {
			return nil, nil
		}
		return nil, r.recordAutoReport(target, person.Subject, message, now)
	})
	_ = value
	return err
}

// recordAutoReport は設定票数の成立時だけ既存board_ruleへSyncする。追加通報で停止を延長しない。
func (r *Repository) recordAutoReport(b *postingBoard, subject domain.Hash, message autoReportMessage, now domain.Time) error {
	network := autoReportNetwork(message.Reporter.IP)
	if network == "" {
		return nil
	}
	key := autoReportTarget{b.owner, subject}
	for _, entry := range b.denials {
		rule := entry.rule
		if rule.Reason == "abuse" && rule.Starts <= now && rule.Expires > now && len(rule.Conditions) == 1 && rule.Conditions[0].Field == "token" && rule.Conditions[0].Value == subject.String() {
			delete(r.autoReportVotes, key)
			return nil
		}
	}
	for target, votes := range r.autoReportVotes {
		if len(votes) == 0 || votes[len(votes)-1].At <= now-domain.Time(r.operations().Reports.window()) {
			delete(r.autoReportVotes, target)
		}
	}
	if len(r.autoReportVotes) >= autoReportCapacity && r.autoReportVotes[key] == nil {
		return nil
	}
	vote := autoReportVote{message.Operation, message.Reporter.Subject, identity.MAC(b.dedupKey[:], "oimo/auto-report-ip/v1", []byte(network)), message.At, message.Reference}
	policy := r.operations().Reports
	votes, ready := collectAutoReportWithPolicy(r.autoReportVotes[key], vote, policy)
	r.autoReportVotes[key] = votes
	if !ready {
		return nil
	}
	if _, exists := b.denials[message.Operation]; exists {
		delete(r.autoReportVotes, key)
		return nil
	}
	if len(b.denials) >= 1000 || r.denialCount >= 10000 {
		return nil
	}
	if err := r.enableDenials(b.owner, true, false, false, false); err != nil {
		return err
	}
	refs := make([]autoReportEvidenceRef, len(votes))
	for i, vote := range votes {
		refs[i] = autoReportEvidenceRef{vote.Operation, vote.Reference}
	}
	if err := r.enableReportReviewReader(); err != nil {
		return err
	}
	started := votes[len(votes)-1].At
	rule := denialRule{ID: message.Operation, Revision: 1, Scope: denialScope{"board", b.owner}, Operations: []string{"create", "reply"}, Conditions: []denialCondition{{"token", "exact", subject.String(), "deny"}}, Effect: denialEffect{Type: "deny"}, Starts: started, Expires: started + domain.Time(policy.stop()), Reason: "abuse", Enabled: true, Reports: refs, ReportPolicy: &policy}
	compiled, err := compileDenial(rule)
	if err != nil {
		return err
	}
	if err = appendControl(b.control, "auto_report_stop", []store.Mutation{mutation("board_rule", rule.ID.String(), rule, nil)}, []string{rule.ID.String()}); err != nil {
		b.stopped = true
		return err
	}
	b.denials[rule.ID] = compiled
	r.denialCount++
	delete(r.autoReportVotes, key)
	return nil
}
