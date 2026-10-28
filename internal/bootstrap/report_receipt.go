// 各板の固定受付案内と、公開レスを増やさない署名付き非公開通報を接続する。
package bootstrap

import (
	"errors"
	"net/netip"
	"strconv"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const reportReceiptKey uint64 = 1
const reportReceiptTitle = "通報受付スレッド"

type automaticReportReceipt struct {
	Source   domain.ID    `json:"source_board_id"`
	Reporter domain.Hash  `json:"reporter_hmac"`
	Dedup    domain.Dedup `json:"dedup"`
}

// receiptSnapshot は各板で一つの最古キーを使う。案内以外のDATを生成しない。
func receiptSnapshot(origin, slug string) (*app.PostingSnapshot, error) {
	return receiptSnapshotWithPolicy(origin, slug, defaultReportPolicy())
}

// receiptSnapshotWithPolicy は現在の集計条件を案内に反映し、本文の版も更新する。
func receiptSnapshotWithPolicy(origin, slug string, p ReportPolicy) (*app.PostingSnapshot, error) {
	body := "この板の通報受付です。通報は公開されず、レス数は増えません。\n対象URL：" + origin + "/test/read.cgi/" + slug + "/スレッドキー/レス番号/\n理由：任意（省略可）\n対象レス一件のURLを記入してください。" + reportDuration(p.WindowSeconds) + "以内に異なる匿名ID・IPから" + strconv.Itoa(p.Quorum) + "票で対象板の書き込みを" + reportDuration(p.StopSeconds) + "停止します。\n通常の対象スレッドでは >>レス番号 !report（改行・理由省略可）も使えます。この方法は通常の公開レスになります。"
	dat, err := compat.DAT(domain.Post{Number: 1, Kind: "system", Visibility: "visible", Name: "通報案内", Body: body, Identity: domain.Identity{DateText: "1970/01/01(木) 09:00:01"}}, reportReceiptTitle)
	if err != nil {
		return nil, err
	}
	return app.NewSystemThreadSnapshot(reportReceiptTitle, dat), nil
}

// receiptReference は理由を任意とし、他サイト・範囲・曖昧な対象を既存URL検査で拒否する。
func receiptReference(body, origin string) (autoReportReference, bool) {
	return parseAutoReport(body+"\n理由：通報", origin)
}

// initReportReceipts は保存形式のreaderを先に同期し、既存の私有依頼保存・期限回収を使う。
func (r *Repository) initReportReceipts() error {
	if err := r.ensureReports(); err != nil {
		return err
	}
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	if site.MinimumReader < 66 {
		site.MinimumReader = 66
		if err := appendControl(r.site, "report_receipt_reader", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); err != nil {
			return err
		}
	}
	return nil
}

// privateReportRetry は板workerから呼ぶ。保存済み要求だけを戻し、期限・票を延長しない。
func (r *Repository) privateReportRetry(b *postingBoard, d domain.Dedup, now domain.Time) (RepositoryPostingResult, bool, error) {
	r.reportMu.Lock()
	defer r.reportMu.Unlock()
	key, err := reportKey(r.cfg.DataDir)
	if err != nil {
		return RepositoryPostingResult{}, false, err
	}
	defer clear(key[:])
	ids, err := reportFiles(r.cfg.DataDir)
	if err != nil {
		return RepositoryPostingResult{}, false, err
	}
	for _, id := range ids {
		v, err := readReport(r.cfg.DataDir, id, key)
		if err != nil {
			return RepositoryPostingResult{}, false, err
		}
		a := v.Automatic
		if a == nil || a.Source != b.owner || a.Dedup.Expires <= now || createRequest(&a.Dedup) != createRequest(&d) {
			continue
		}
		if a.Dedup.Request != d.Request {
			return RepositoryPostingResult{}, false, postinput.ErrInput
		}
		return RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.Durable}, OperationID: v.ID, PostNumber: 1, Duplicate: true}, ThreadKey: reportReceiptKey}, true, nil
	}
	return RepositoryPostingResult{}, false, nil
}

// savePrivateReport は既存の確認・規制・投稿枠の検査後、公開WALを作らず私有fileを同期する。
func (r *Repository) savePrivateReport(b *postingBoard, input postinput.Input, d domain.Dedup, ref autoReportReference, target domain.ID, subject domain.Hash, ip netip.Addr, now time.Time) (RepositoryPostingResult, *autoReportMessage) {
	r.reportMu.Lock()
	defer r.reportMu.Unlock()
	fail := func(err error) (RepositoryPostingResult, *autoReportMessage) { return formFailure(err), nil }
	key, err := reportKey(r.cfg.DataDir)
	if err != nil {
		return fail(err)
	}
	defer clear(key[:])
	ids, err := reportFiles(r.cfg.DataDir)
	if err != nil {
		return fail(err)
	}
	if len(ids) >= reportLimit {
		return fail(errors.New("private report capacity reached"))
	}
	if target == (domain.ID{}) {
		return fail(postinput.ErrInput)
	}
	at := domain.Time(now.UnixNano())
	v := deletionReport{ID: domain.NewID(), Board: target, Thread: domain.U64(ref.Key), Ranges: strconv.FormatUint(uint64(ref.Post), 10), Category: "normal", Reason: input.Body, SourceIP: ip.String(), LookupHash: domain.Hash{1}, State: "open", Created: at, Updated: at, Expires: at + 180*86400e9, Revision: 1, Automatic: &automaticReportReceipt{Source: b.owner, Reporter: subject, Dedup: d}}
	if err = validateReport(v); err != nil {
		return fail(postinput.ErrInput)
	}
	if err = writeReport(r.cfg.DataDir, v, key); err != nil {
		b.stopped = true
		result := formFailure(err)
		result.Status = store.Unknown
		return result, nil
	}
	message := &autoReportMessage{Reference: ref, Operation: v.ID, Reporter: app.EvidencePostIdentity{IP: ip.String(), Subject: subject}, At: at}
	return RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.Durable}, OperationID: v.ID, PostNumber: 1}, ThreadKey: reportReceiptKey}, message
}

// restorePrivateReportVotes は公開投稿の復旧後に私有通報も同じ判定へ渡す。
func (r *Repository) restorePrivateReportVotes(now domain.Time) error {
	key, err := reportKey(r.cfg.DataDir)
	if err != nil {
		return err
	}
	defer clear(key[:])
	ids, err := reportFiles(r.cfg.DataDir)
	if err != nil {
		return err
	}
	since := r.reportSince()
	for _, id := range ids {
		v, err := readReport(r.cfg.DataDir, id, key)
		if err != nil {
			return err
		}
		if v.Automatic == nil || v.Created <= now-domain.Time(r.operations().Reports.window()) || v.Created < since || v.Created > now {
			continue
		}
		target := r.posting[v.Board]
		if target == nil {
			continue
		}
		n, _ := strconv.ParseUint(v.Ranges, 10, 32)
		message := autoReportMessage{autoReportReference{target.boardKey(), uint64(v.Thread), uint32(n)}, v.ID, app.EvidencePostIdentity{IP: v.SourceIP, Subject: v.Automatic.Reporter}, v.Created}
		if err = r.applyAutoReport(message, now); err != nil {
			return err
		}
	}
	return nil
}

// validateAutomaticReportReceipt はCookieを持たない固定型と受付元・再送情報を検査する。
func validateAutomaticReportReceipt(a *automaticReportReceipt, v deletionReport) error {
	if a == nil {
		return nil
	}
	if a.Source == (domain.ID{}) || a.Dedup.Subject == (domain.Hash{}) || a.Dedup.Request == (domain.Hash{}) || a.Dedup.KeyID != 8 || a.Dedup.PostNumber != 1 || a.Dedup.Expires < v.Created || a.Dedup.Expires > v.Created+86400e9 || (a.Dedup.Mode != "implicit" && a.Dedup.Mode != "explicit") {
		return store.ErrCorrupt
	}
	if (a.Dedup.Mode == "explicit") != (a.Dedup.RequestID != nil) {
		return store.ErrCorrupt
	}
	return nil
}

// reportDuration は通報の案内で使う時間を整数の時間・分・秒へ整える。
func reportDuration(seconds int) string {
	if seconds%3600 == 0 {
		return strconv.Itoa(seconds/3600) + "時間"
	}
	if seconds%60 == 0 {
		return strconv.Itoa(seconds/60) + "分"
	}
	return strconv.Itoa(seconds) + "秒"
}
