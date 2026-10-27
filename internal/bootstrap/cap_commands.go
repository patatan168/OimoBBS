// CAP管理コマンドを非公開の所有操作へ変換し、本文を投稿正本へ渡さない。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// ErrCapCommand は公開投稿へ戻してはならない管理コマンドの構文・対象エラー。
var ErrCapCommand = errors.New("invalid CAP management command")

type capCommand struct {
	Kind    string
	Post    uint32
	Minutes uint32
}

// parseCapCommand はコマンドらしい入力を予約し、構文不正でも公開投稿へ戻さない。
func parseCapCommand(body string) (capCommand, bool, error) {
	fields := strings.Fields(body)
	var command capCommand
	candidate := len(fields) > 1 && strings.HasPrefix(fields[0], ">>") && strings.HasPrefix(fields[1], "!") && fields[1] != "!report"
	for _, f := range fields {
		if f == "!ban" || f == "!delete" || f == "!unban" || f == "!stop" {
			candidate = true
		}
	}
	if !candidate {
		return command, false, nil
	}
	if len(fields) < 2 || len(fields) > 3 || !strings.HasPrefix(fields[0], ">>") {
		return command, true, ErrCapCommand
	}
	raw := strings.TrimPrefix(fields[0], ">>")
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || n == 0 || fmt.Sprint(n) != raw {
		return command, true, ErrCapCommand
	}
	command.Post, command.Kind = uint32(n), strings.TrimPrefix(fields[1], "!")
	switch fields[1] {
	case "!ban":
		command.Minutes = permanentDenyMinutes
		if len(fields) == 3 {
			duration := fields[2]
			if len(duration) < 2 {
				return command, true, ErrCapCommand
			}
			units := map[byte]uint64{'m': 1, 'h': 60, 'd': 1440}
			factor := units[duration[len(duration)-1]]
			count, err := strconv.ParseUint(duration[:len(duration)-1], 10, 32)
			if err != nil || count == 0 || factor == 0 || count > uint64(maxCapBanMinutes)/factor || fmt.Sprint(count) != duration[:len(duration)-1] {
				return command, true, ErrCapCommand
			}
			command.Minutes = uint32(count * factor)
		}
	case "!delete", "!unban", "!stop":
		if len(fields) != 2 {
			return command, true, ErrCapCommand
		}
	default:
		return command, true, ErrCapCommand
	}
	return command, true, nil
}

// submitCapCommandForm はサイトmutex→板workerの順で規制件数と資格変更を直列化する。
func (r *Repository) submitCapCommandForm(ctx context.Context, b *postingBoard, run func() (any, error)) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return nil, err
	}
	return r.submitPosting(ctx, b.worker, run)
}

// executeCapCommand は確認・Cookie・CAP認証を通過した操作だけを既存の管理台帳へ確定する。
// 管理frameは既存形式のadmin actorを使い、CAP由来の理由とIDを監査表示で識別する。
func (r *Repository) executeCapCommand(b *postingBoard, key uint64, c capCommand, cap capValue, d domain.Dedup, site siteState) LegacyFormResult {
	fail := legacyFailure
	p := b.threads[key]
	if p == nil || key == reportReceiptKey {
		return fail(ErrCapCommand)
	}
	now := domain.Time(b.clock().UnixNano())
	if now <= 0 || now > permanentDenyExpiry-86400e9 {
		return fail(ErrPostingUnavailable)
	}
	if b.controlExpiryFloor != nil && int64(now) < b.controlExpiryFloor.Load() {
		return fail(ErrControlExpiryClock)
	}
	seq, expires, _, state, err := p.ThreadActionState()
	if err != nil || expires <= now || state == "hidden" {
		return fail(ErrCapCommand)
	}
	snapshot := p.Snapshot(now)
	if snapshot == nil || c.Post > snapshot.PostCount {
		return fail(ErrCapCommand)
	}
	dedupIdentity := d.Request
	if d.RequestID != nil {
		dedupIdentity = *d.RequestID
	}
	requestKey := identity.MAC(b.dedupKey[:], "oimo/cap-command-key/v1", cap.ID[:], b.owner[:], []byte(fmt.Sprint(key)), dedupIdentity[:])
	request := identity.MAC(b.dedupKey[:], "oimo/cap-command-request/v1", cap.ID[:], d.Request[:])
	receiptExpiry := now + 86400e9
	if d.Mode == "implicit" {
		receiptExpiry = now + 30e9
	}
	receipt := capCommandReceipt{Key: requestKey, Request: request, Cap: cap.ID, Board: b.owner, Thread: domain.U64(key), Post: c.Post, Kind: c.Kind, Minutes: c.Minutes, Rules: []domain.ID{}, Created: now, Expires: receiptExpiry}
	var subject domain.Hash
	if row, ok := b.control.State().Rows["cap_command:"+requestKey.String()]; ok {
		var prior capCommandReceipt
		if err := strictjson.Decode(row.Value, &prior); err != nil {
			return fail(err)
		}
		if prior.Created > now {
			return fail(ErrPostingUnavailable)
		}
		if prior.Expires > now {
			if prior.Request != request {
				return fail(ErrCapCommand)
			}
			if prior.Done {
				result := capCommandSuccess(key, c.Post)
				result.Duplicate = true
				return result
			}
			receipt = prior
		}
	}
	if c.Kind == "ban" || c.Kind == "unban" {
		subject, err = capCommandSubject(b, key, c.Post, now)
		if err != nil {
			return fail(err)
		}
	}
	newIntent := true
	if row, ok := b.control.State().Rows["cap_command:"+requestKey.String()]; ok {
		var prior capCommandReceipt
		if strictjson.Decode(row.Value, &prior) != nil {
			return fail(store.ErrCorrupt)
		}
		newIntent = prior.Expires <= now
	}
	if newIntent {
		if site.MinimumReader < capCommandsReader {
			site.MinimumReader = capCommandsReader
			if err := appendControl(r.site, "cap_commands_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{b.owner.String()}); err != nil {
				r.stopped = true
				return fail(err)
			}
		}
		if c.Kind == "unban" {
			receipt.Rules = capCommandRules(b, subject)
		}
		count := 0
		for name := range b.control.State().Rows {
			if strings.HasPrefix(name, "cap_command:") {
				count++
			}
		}
		if count >= 200000 {
			return fail(ErrPostingUnavailable)
		}
		if err := b.saveCapCommandReceipt(receipt); err != nil {
			return fail(err)
		}
	}
	operationKey := capCommandOperationKey(b, receipt)
	reason := "cap_command_" + c.Kind
	etag := fmt.Sprintf(`"%s:%d:%d"`, b.owner, key, seq)
	switch c.Kind {
	case "delete":
		_, err = b.moderateThread(key, AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: c.Post, Last: c.Post, Mode: "transparent"}}}, etag, operationKey, request, cap.ID, reason, site)
	case "stop":
		_, err = b.changeThreadAction(threadActionCommand{Admin: cap.ID, Key: key, Edit: AdminThreadAction{Kind: "stop"}, ETag: etag, RequestKey: operationKey, Request: request, SiteRevision: site.PublicRevision})
	case "ban", "unban":
		err = r.capCommandRule(b, c, receipt, subject, now)
	}
	if err != nil {
		if b.stopped {
			return legacyResult(RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.Unknown, Err: err}}, ThreadKey: key})
		}
		return fail(err)
	}
	receipt.Done = true
	if err := b.saveCapCommandReceipt(receipt); err != nil {
		return legacyResult(RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.Unknown, Err: err}}, ThreadKey: key})
	}
	return capCommandSuccess(key, c.Post)
}

func capCommandSuccess(key uint64, post uint32) LegacyFormResult {
	result := legacyResult(RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.Durable}, PostNumber: post}, ThreadKey: key})
	result.Management = true
	return result
}

func capCommandDuration(c capCommand) string {
	if c.Kind != "ban" {
		return c.Kind
	}
	if c.Minutes == permanentDenyMinutes {
		return "permanent"
	}
	return fmt.Sprintf("%dm", c.Minutes)
}

// capCommandRule は署名原本の匿名主体を対象にし、IPや表示IDへ規制を広げない。
func (r *Repository) capCommandRule(b *postingBoard, c capCommand, receipt capCommandReceipt, subject domain.Hash, now domain.Time) error {
	capID, requestKey, request := receipt.Cap, capCommandOperationKey(b, receipt), receipt.Request
	if row, ok := b.control.State().Rows["rule_receipt:"+requestKey.String()]; ok {
		var prior ruleReceipt
		if err := strictjson.Decode(row.Value, &prior); err != nil {
			return err
		}
		if prior.Created > now {
			return ErrPostingUnavailable
		}
		if prior.Expires > now {
			if prior.Request != request {
				return ErrCapCommand
			}
			return nil
		}
	}
	input := AdminRuleInput{Minutes: c.Minutes, Operations: []string{"create", "reply"}, Reason: "manual"}
	input.Target = subject.String()
	input.Match = &AdminRuleMatch{Field: "token", Operator: "exact", Effect: "deny"}
	if err := r.enableDenials(b.owner, true, false, false, false); err != nil {
		return err
	}
	if c.Minutes == permanentDenyMinutes {
		if err := r.enableReportReviewReader(); err != nil {
			return err
		}
	}
	if c.Kind == "unban" {
		for _, id := range receipt.Rules {
			entry, ok := b.denials[id]
			if !ok {
				return store.ErrCorrupt
			}
			if !entry.rule.Enabled {
				continue
			}
			original := entry.rule
			revoked := original
			revoked.Enabled = false
			revoked.Revision++
			// 解除は各ルールへ一意の再送鍵を束縛する。
			subkey := identity.MAC(b.dedupKey[:], "oimo/cap-unban-rule/v1", requestKey[:], original.ID[:])
			receipt := ruleReceipt{domain.NewID(), capID, subkey, request, revoked, now, now + 86400e9}
			if err := b.saveRule(adminauth.Session{Admin: capID}, receipt); err != nil {
				return err
			}
			compiled, _ := compileDenial(revoked)
			b.denials[revoked.ID] = compiled
		}
		return nil
	}
	rule, err := r.prepareRule(b, domain.ID{}, input, b.adminRules().ETag(), now)
	if err != nil {
		return err
	}
	saved := ruleReceipt{domain.NewID(), capID, requestKey, request, rule, now, now + domain.Time(24*time.Hour)}
	if err := b.saveRule(adminauth.Session{Admin: capID}, saved); err != nil {
		return err
	}
	compiled, _ := compileDenial(rule)
	b.denials[rule.ID] = compiled
	r.denialCount++
	return nil
}

// capCommandSubject は保持中の署名原本から匿名主体を取り出し、CAP・システムレスを拒否する。
func capCommandSubject(b *postingBoard, key uint64, post uint32, now domain.Time) (domain.Hash, error) {
	journals := make([]*evidence.Journal, 0, len(b.journals))
	for _, j := range b.journals {
		journals = append(journals, j)
	}
	rows, err := app.AcceptedRecordsForPost(journals, b.owner, domain.U64(key), post, "post", now, 1)
	if err != nil {
		return domain.Hash{}, err
	}
	if len(rows) != 1 {
		return domain.Hash{}, ErrCapCommand
	}
	person, err := rows[0].Identity()
	if err != nil {
		return domain.Hash{}, err
	}
	if person.Subject == (domain.Hash{}) || person.Cap != (domain.ID{}) {
		return domain.Hash{}, ErrCapCommand
	}
	return person.Subject, nil
}
