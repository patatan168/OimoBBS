// 自動停止の成立票を署名済み原本から限定照会し、閲覧前に本文を含まない監査を同期する。
package bootstrap

import (
	"context"
	"fmt"
	"html"
	"os"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
)

// reviewAutoReportContents は現在の担当・追加閲覧権限を所有mutex内で検査する。
func (r *Repository) reviewAutoReportContents(ctx context.Context, s adminauth.Session, b *postingBoard, rule denialRule, requestID string) ([]autoReportContent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.authorizeEvidence(s, "evidence.manage", b.owner, false); err != nil {
		return nil, err
	}
	if err := r.enableReportReviewReader(); err != nil {
		return nil, err
	}
	refs := rule.Reports
	if len(refs) == 0 || validateAutoReportRefs(rule) != nil {
		return nil, store.ErrCorrupt
	}
	out := make([]autoReportContent, len(refs))
	for i, ref := range refs {
		content, err := r.reviewReportVote(ctx, s, b, rule, ref, requestID)
		if err != nil {
			return nil, err
		}
		out[i] = content
	}
	return out, nil
}

// reviewReportVote は非公開受付と公開通報を同じ参照で解決する。未保持・権限外は明示する。
func (r *Repository) reviewReportVote(ctx context.Context, s adminauth.Session, b *postingBoard, rule denialRule, ref autoReportEvidenceRef, requestID string) (autoReportContent, error) {
	c := autoReportContent{Message: "通報原本が保持されていないか、受付元板の閲覧権限がありません。"}
	key, err := reportKey(r.cfg.DataDir)
	if err != nil {
		return c, err
	}
	defer clear(key[:])
	v, err := readReport(r.cfg.DataDir, ref.Operation, key)
	if err == nil && v.Expires > domain.Time(time.Now().UnixNano()) && v.Automatic != nil && v.Board == b.owner {
		if err = r.auditReportReview(ctx, s, b, []domain.ID{v.ID}, requestID); err != nil {
			return c, err
		}
		c.ReportBody = v.Reason
		c.At = reportReviewTime(v.Created)
		c.Source = "非公開受付"
		c.Message = ""
		if ref.Target.Key == 0 {
			n, _ := fmt.Sscan(v.Ranges, &ref.Target.Post)
			if n == 1 {
				ref.Target.Key = uint64(v.Thread)
				ref.Target.Board = b.slug
			}
		}
	} else {
		if err != nil && !os.IsNotExist(err) {
			return c, err
		}
		for _, source := range r.posting {
			if r.authorizeEvidence(s, "evidence.manage", source.owner, false) != nil {
				continue
			}
			_, err = source.worker.Submit(ctx, func() (any, error) {
				var selected []app.AcceptedEvidence
				err := app.VisitAcceptedRecordsInRange(reportReviewJournalsWithPolicy(source, rule.Starts, ruleReportPolicy(rule)), func(owner domain.ID, _ domain.U64, at domain.Time, _ domain.ID) bool {
					return owner == source.owner && at <= rule.Starts && at > rule.Starts-domain.Time(ruleReportPolicy(rule).window())
				}, func(row app.AcceptedEvidence) error {
					if row.Operation == ref.Operation && row.Expires > domain.Time(time.Now().UnixNano()) {
						selected = append(selected, row)
					}
					return nil
				})
				if err != nil || len(selected) == 0 {
					return nil, err
				}
				row := selected[0]
				if err = r.auditReportReviewWorker(s, source, []domain.ID{row.RecordID}, requestID); err != nil {
					return nil, err
				}
				body, err := row.ReportBody()
				if err != nil {
					return nil, err
				}
				c.ReportBody = html.UnescapeString(body)
				c.At = reportReviewTime(row.Committed)
				c.Source = "公開通報（" + source.publicName + "）"
				c.Message = ""
				if ref.Target.Key == 0 {
					target, ok := parseAutoReport(c.ReportBody, r.cfg.Public.BaseURL)
					if post, command := parseAutoReportCommand(c.ReportBody); command {
						target, ok = autoReportReference{source.slug, uint64(row.Thread), post}, true
					}
					if ok && target.Board == b.slug {
						ref.Target = target
					}
				}
				return nil, nil
			})
			if err != nil {
				return c, err
			}
			if c.Message == "" {
				break
			}
		}
	}
	if ref.Target.Key == 0 {
		return c, nil
	}
	c.Target = fmt.Sprintf("/boards/%s/threads/%d/posts/%d#post-%d", b.owner, ref.Target.Key, (ref.Target.Post-1)/50*50+1, ref.Target.Post)
	_, err = b.worker.Submit(ctx, func() (any, error) {
		journals := make([]*evidence.Journal, 0, len(b.journals))
		for _, j := range b.journals {
			journals = append(journals, j)
		}
		rows, e := app.AcceptedRecordsForPost(journals, b.owner, domain.U64(ref.Target.Key), ref.Target.Post, "post", domain.Time(time.Now().UnixNano()), 1)
		if e != nil {
			return nil, e
		}
		if len(rows) == 0 {
			c.TargetBody = "対象レスの原本は保持期限を過ぎています。"
			return nil, nil
		}
		person, e := rows[0].Identity()
		if e != nil {
			return nil, e
		}
		if person.Subject.String() != rule.Conditions[0].Value {
			return nil, store.ErrCorrupt
		}
		if e = r.auditReportReviewWorker(s, b, []domain.ID{rows[0].RecordID}, requestID); e != nil {
			return nil, e
		}
		body, e := rows[0].ReportBody()
		c.TargetBody = html.UnescapeString(body)
		return nil, e
	})
	return c, err
}

func (r *Repository) auditReportReview(ctx context.Context, s adminauth.Session, b *postingBoard, ids []domain.ID, key string) error {
	_, err := b.worker.Submit(ctx, func() (any, error) { return nil, r.auditReportReviewWorker(s, b, ids, key) })
	return err
}

// auditReportReviewWorker は原本IDだけを既存の照会監査へ同期する。板worker内から呼ぶ。
func (r *Repository) auditReportReviewWorker(s adminauth.Session, b *postingBoard, ids []domain.ID, key string) error {
	if b.stopped {
		return ErrPostingUnavailable
	}
	at := domain.Time(time.Now().UnixNano())
	requestKey := identity.MAC(b.dedupKey[:], "oimo/report-review-key/v1", s.Admin[:], []byte(key))
	request := identity.MAC(b.dedupKey[:], "oimo/report-review/v1", s.Admin[:], []byte(fmt.Sprint(ids)))
	kid := uint32(8)
	targets := make([]string, len(ids))
	for i, id := range ids {
		targets[i] = id.String()
	}
	frame, err := controlFrame(b.control.State(), domain.NewID(), at, "post_evidence_query", []store.Mutation{mutation("post_evidence_query", "latest", postEvidenceAudit{s.Admin, at, ids}, nil)}, targets, domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "post_evidence_query", Request: &request, Idempotency: &requestKey, KeyID: &kid})
	if err != nil {
		return err
	}
	if b.control.Append(frame).Status != store.Durable {
		b.stopped = true
		return ErrPostingUnavailable
	}
	return nil
}

// reportReviewJournals は成立前24時間に重なる日別原本だけを照会する。板worker内で呼ぶ。
func reportReviewJournals(b *postingBoard, at domain.Time) []*evidence.Journal {
	return reportReviewJournalsWithPolicy(b, at, defaultReportPolicy())
}

// reportReviewJournalsWithPolicy は停止成立時の集計窓に重なる原本を照会する。
func reportReviewJournalsWithPolicy(b *postingBoard, at domain.Time, p ReportPolicy) []*evidence.Journal {
	first := time.Unix(0, int64(at-domain.Time(p.window()))).UTC().Format("20060102")
	last := time.Unix(0, int64(at)).UTC().Format("20060102")
	out := []*evidence.Journal{}
	for day, j := range b.journals {
		date := fmt.Sprint(day)
		if date >= first && date <= last {
			out = append(out, j)
		}
	}
	return out
}
