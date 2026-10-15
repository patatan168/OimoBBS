// Web/legacy共通の通常フォーム受付。確認・再送・受理規制を板ワーカーへ接続する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strconv"
	"time"
)

// SubmitLegacyForm は読了したフォームと信頼済みHTTP観測を板ワーカーへ渡す内部API。
// この内部入口はCookieなしとして処理する。HTTP入口は共通処理へ検証対象Cookieを渡す。
// 確認Cookieの値を別引数で受け、未確認時は保存せずConfirmationを返す。
// WebルートはCSRFを迂回しないよう拒否する。試行制限は公開HTTP境界側の責務。
func (r *Repository) SubmitLegacyForm(ctx context.Context, owner domain.ID, body []byte, contentType string, observation evidence.HTTPObservation, confirmationToken string) LegacyFormResult {
	return r.submitForm(ctx, owner, body, contentType, observation, confirmationToken, "", false)
}

// submitForm のWeb経路は、HTTP境界を検証したSubmitWebRequestからのみ呼ぶ。
func (r *Repository) submitForm(ctx context.Context, owner domain.ID, body []byte, contentType string, observation evidence.HTTPObservation, confirmationToken, webCookie string, web bool, anonymousRaw ...string) (result LegacyFormResult) {
	defer func() { annotateOptionalResult(ctx, owner, result) }()
	var repeatCandidate *violationCandidate
	reportCandidate := false
	var privateMessage *autoReportMessage
	defer func() {
		if result.Status == store.Durable && privateMessage != nil {
			r.mu.Lock()
			defer r.mu.Unlock()
			if !r.closed && !r.stopped {
				if e := r.applyAutoReport(*privateMessage, domain.Time(time.Now().UnixNano())); e != nil {
					r.stopped = true
				}
			}
		} else if result.Status == store.Durable && reportCandidate {
			r.acceptAutoReport(owner, result.ThreadKey, result.PostNumber)
		}
	}()
	started := time.Now()
	fail := legacyFailure
	rawAnonymous := ""
	if len(anonymousRaw) > 1 {
		return fail(ErrPostingRequest)
	}
	if len(anonymousRaw) == 1 {
		rawAnonymous = anonymousRaw[0]
	}

	if (!web && observation.Route != "bbs_post" || web && observation.Route != "web_create" && observation.Route != "web_reply") || observation.BoardID != owner || uint64(observation.BodyBytes) != uint64(len(body)) {
		return fail(postinput.ErrInput)
	}
	capture, e := json.Marshal(observation)
	if e != nil {
		return fail(e)
	}
	if e = evidence.ValidateHTTPObservation(capture); e != nil {
		return fail(e)
	}
	readingIP, _ := netip.ParseAddr(observation.Resolved.IP)
	r.prepareReading(ctx, owner.String(), readingIP)
	if e := r.checkReading(owner.String(), readingIP, observedUserAgent(observation.SelectedHeaders)); e != nil {
		return fail(e)
	}
	fields, e := compat.ParseForm(body, contentType, web)
	if e != nil {
		return fail(e)
	}
	// Webの通常フォームでは空欄。全欄を埋めるbotを保存・DNS・worker予約より前に拒否する。
	if web && fields["oimo_contact"] != "" {
		return fail(postinput.ErrInput)
	}
	var key uint64
	if raw := fields["key"]; raw != "" {
		key, e = strconv.ParseUint(raw, 10, 64)
		if e != nil || key == 0 || strconv.FormatUint(key, 10) != raw {
			return fail(postinput.ErrInput)
		}
	}
	if web && (key == 0 && observation.Route != "web_create" || key != 0 && observation.Route != "web_reply") {
		return fail(postinput.ErrInput)
	}
	b, e := r.postingOwner(owner)
	if e != nil {
		return fail(e)
	}
	privateReceipt := key == reportReceiptKey && b.receipt.Load() != nil
	var receiptRef autoReportReference
	var receiptTarget domain.ID
	var receiptTargetBoard *postingBoard
	if privateReceipt {
		var ok bool
		receiptRef, ok = receiptReference(fields["MESSAGE"], r.cfg.Public.BaseURL)
		if !ok || b.slug != r.cfg.AutoReports.BoardKey && receiptRef.Board != b.slug {
			return fail(errors.Join(postinput.ErrInput, ErrAutoReportInput))
		}
		r.mu.Lock()
		for id, board := range r.posting {
			if board.slug == receiptRef.Board {
				receiptTarget = id
				break
			}
		}
		r.mu.Unlock()
		if receiptTarget == (domain.ID{}) || receiptRef.Key == reportReceiptKey {
			return fail(ErrAutoReportInput)
		}
		targetBoard, err := r.postingOwner(receiptTarget)
		if err != nil {
			return fail(err)
		}
		receiptTargetBoard = targetBoard
		snapshot, status := targetBoard.publicSnapshot(receiptRef.Key, domain.Time(time.Now().UnixNano()))
		if status != 200 || receiptRef.Post > snapshot.PostCount {
			return fail(ErrAutoReportInput)
		}

	}
	if r.cfg.AutoReports != nil && !privateReceipt && boardAutoReportsEnabled(b.autoReports.Load()) {
		if key != 0 {
			_, reportCandidate = parseAutoReportCommand(fields["MESSAGE"])
		}
		if _, command := autoReportCommandTarget(fields["MESSAGE"]); command && (!reportCandidate || owner == r.autoReportBoard) {
			return fail(errors.Join(postinput.ErrInput, ErrAutoReportInput))
		}
		if owner == r.autoReportBoard {
			_, link := parseAutoReport(fields["MESSAGE"], r.cfg.Public.BaseURL)
			reportCandidate = reportCandidate || link
		}
	}
	command, commandCandidate, commandErr := parseCapCommand(fields["MESSAGE"])
	if commandErr != nil || commandCandidate && (key == 0 || privateReceipt) {
		return fail(ErrCapCommand)
	}
	cleanMail, capID, capSecretRaw, e := postinput.ExtractCap(fields["mail"])
	if e != nil {
		return fail(e)
	}
	if commandCandidate && capID == nil {
		return fail(ErrCap)
	}
	capOnly := fields["oimo_cap_only"] != ""
	if capOnly && (key != 0 || fields["oimo_cap_only"] != "1") {
		return fail(postinput.ErrInput)
	}
	if capOnly && capID == nil {
		return fail(ErrCap)
	}
	if capID != nil {
		if e = r.ensureCapDisplayReader(ctx, b, *capID, capSecretRaw, key == 0, capOnly); e != nil {
			return fail(e)
		}
	}
	// サイト名の版を所有mutexで取得する。板設定はworker実行時の確定値を使う。
	r.mu.Lock()
	var anonState *anonymousState
	var site siteState
	e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site)
	r.mu.Unlock()
	if e != nil {
		return fail(e)
	}
	// サービスDNSの補完は所有ワーカーに入る前に準備し、通常投稿列を止めない。
	if ip, err := netip.ParseAddr(observation.Resolved.IP); err == nil {
		r.resolveNetworkHost(ctx, ip, true)
	}
	var originRecast tokenReissue
	if ip, err := netip.ParseAddr(observation.Resolved.IP); err == nil {
		r.mu.Lock()
		if r.anonymous != nil {
			row, ok := r.site.State().Rows["token_reissue:"+r.tokenReissueOrigin(ip).String()]
			if ok {
				e = strictjson.Decode(row.Value, &originRecast)
			}
		}
		r.mu.Unlock()
		if e != nil {
			return fail(e)
		}
	}
	tokenStatus := "absent"
	var verified abuse.Anon
	anonymousMode := "off"
	var tokenWait uint32
	batchKey := key
	if privateReceipt {
		batchKey = 0
	}
	submit := func(run func() (any, error)) (any, error) {
		if commandCandidate {
			return r.submitCapCommandForm(ctx, b, run)
		}
		return r.submitPostingBatch(ctx, b, batchKey, run)
	}
	value, e := submit(func() (any, error) {
		anonState = r.liveAnonymous.Load()
		if b.stopped {
			return fail(ErrPostingUnavailable), nil
		}
		if fields["bbs"] != b.slug {
			return fail(postinput.ErrInput), nil
		}
		if e := b.validate(capture); e != nil {
			return fail(e), nil
		}
		var settings boardValue
		if e := strictjson.Decode(b.control.State().Rows["board:state"].Value, &settings); e != nil {
			return fail(e), nil
		}
		s := settings.Settings
		var endings []postinput.EndResponse
		if row, ok := b.control.State().Rows["thread_settings:active"]; ok {
			configured, e := b.threadSettings()
			if e != nil {
				return fail(e), nil
			}
			s.Thread.PostLimit = configured.Settings.PostLimit
			s.Version = max(b.control.State().Rows["board:state"].Revision, row.Revision)
			endings = configured.Settings.endResponses()
		}
		if settings.Status != "open" || s.Posting.ForceAge || s.Posting.AllowSoko || s.Identity.AllowFusianasan {
			return fail(postinput.ErrUnsupported), nil
		}
		cleanFields := make(map[string]string, len(fields))
		for k, v := range fields {
			cleanFields[k] = v
		}
		cleanFields["mail"] = cleanMail
		var cap *capValue
		if capID != nil {
			cap, e = authenticateCap(b.liveCaps.Load(), b.capKey, *capID, capSecretRaw, b.owner, key == 0, domain.Time(b.clock().UnixNano()))
			if e != nil {
				return fail(e), nil
			}
		}
		if key != 0 && !privateReceipt && cap == nil {
			if p := b.threads[key]; p != nil {
				if policy, ok := p.PostingPolicy(domain.Time(b.clock().UnixNano())); ok && policy.CapOnly {
					return fail(ErrCap), nil
				}
			}
		}
		input, e := postinput.Prepare(cleanFields, key == 0, b.dedupKey)
		if e != nil {
			return fail(e), nil
		}
		if cap != nil {
			input.Credential = identity.MAC(b.dedupKey[:], "oimo/post-cap-credential/v1", input.Credential[:], cap.ID[:], cap.Secret[:])
		}
		ip, e := netip.ParseAddr(observation.Resolved.IP)
		if e != nil || ip.String() != observation.Resolved.IP {
			return fail(postinput.ErrInput), nil
		}
		ip = ip.Unmap()
		if e := r.checkReading(owner.String(), ip, observedUserAgent(observation.SelectedHeaders)); e != nil {
			return fail(e), nil
		}
		family := byte(6)
		if ip.Is4() {
			family = 4
		}
		now := b.clock()
		if web {
			if e := abuse.VerifyWebCSRF(webCookie, fields["csrf"], observation.Route, b.csrfKey[:], 6, now); e != nil {
				return fail(e), nil
			}
		}
		anonymousMode, tokenWait = effectiveAnonymous(anonState, s.Posting)
		tokenWait = b.guardTokenWait(tokenWait)
		if r.liveSlipEnabled.Load() {
			anonymousMode = "required"
		}
		if anonState != nil && rawAnonymous != "" {
			var err error
			verified, err = anonState.verify(rawAnonymous, now)
			if err == nil {
				tokenStatus = "valid"
			} else {
				tokenStatus = "invalid"
			}
		}
		var tokenSubject domain.Hash
		if tokenStatus == "valid" && anonymousMode != "off" {
			tokenSubject = anonState.subject(verified.ID)
		}
		matched, ruleErr := b.matchedRules(ip, input, tokenSubject, key == 0, domain.Time(now.UnixNano()), observation.SelectedHeaders, false)
		if cap != nil {
			exemptCapConnectionRules(matched)
		}
		denied, requireToken := composeMatchedRules(matched)
		overrides := matchedOverrides(matched)
		if ruleErr != nil {
			return fail(ruleErr), nil
		}
		if requireToken {
			anonymousMode = "required"
		}
		if anonymousMode == "off" {
			tokenStatus, verified = "absent", abuse.Anon{}
		}
		if anonymousMode == "required" && tokenStatus != "valid" {
			confirmationToken = ""
		}
		at := domain.Time(now.UnixNano())
		d := input.Dedup(b.dedupKey, b.owner, key, append([]byte{family}, ip.AsSlice()...), at)
		challenge, e := b.confirmation(confirmationToken, input, d, site, s, key, now)
		if e != nil {
			return fail(e), nil
		}
		if challenge != nil {
			if cap != nil {
				challenge.Management = commandCandidate
				challenge.Preview.Cap = cap.Name
				challenge.IDMode = "CAP_USER"
			}
			result := fail(ErrConfirmationRequired)
			result.Confirmation = challenge
			return result, nil
		}
		if privateReceipt {
			if result, ok, err := r.privateReportRetry(b, d, at); err != nil {
				return fail(err), nil
			} else if ok {
				return legacyResult(result), nil
			}
		}
		if d.Mode == "explicit" {
			if result, ok := b.explicitRetry(&d, at); ok {
				return legacyResult(result), nil
			}
		} else if key == 0 {
			if oldKey, exists := b.createRequests[createRequest(&d)]; exists {
				if result, ok := b.threads[oldKey].CreateRetry(&d, at); ok {
					return legacyResult(RepositoryPostingResult{result, oldKey}), nil
				}
			}
		} else if p := b.threads[key]; p != nil {
			if result, ok := p.Retry(&d, at); ok {
				return legacyResult(RepositoryPostingResult{result, key}), nil
			}
		}
		// 設定変更後も受理済み再送は元結果へ戻す。新規受理だけ停止する。
		if r.liveSlipEnabled.Load() && tokenStatus != "valid" {
			return fail(abuse.ErrToken), nil
		}
		if !commandCandidate && (key == 0 && s.Posting.Create == "disabled" || key != 0 && s.Posting.Reply == "disabled") {
			return fail(ErrPostingDisabled), nil
		}
		if (key == 0 && s.Posting.Create == "cap_only" || key != 0 && s.Posting.Reply == "cap_only") && cap == nil {
			return fail(ErrCap), nil
		}
		if e := b.checkNetworkAccess(s.Identity.Access, ip, cap != nil, s.Identity.Networks); e != nil {
			return fail(e), nil
		}
		if cap == nil {
			if e := b.repeatedViolationWait(tokenSubject, at); e != nil {
				return fail(e), nil
			}
		}
		if denied {
			if cap == nil && tokenStatus == "valid" && targetedSpamViolation(matched) {
				repeatCandidate = &violationCandidate{tokenSubject, violationRequest(b.dedupKey, tokenSubject, d), at}
			}
			return fail(ErrPostingDenied), nil
		}
		if anonymousMode != "off" && verified.ID == (domain.ID{}) {
			if err := anonymousOriginWait(originRecast, now); err != nil {
				return fail(err), nil
			}
		}
		if e := anonymousWait(verified, tokenWait, now); e != nil {
			return fail(e), nil
		}
		if commandCandidate {
			if e := ctx.Err(); e != nil {
				return fail(e), nil
			}
			return r.executeCapCommand(b, key, command, *cap, d, site), nil
		}
		var water struct {
			Last domain.U64 `json:"last_removed_bump"`
		}
		if e := strictjson.Decode(b.control.State().Rows["bump_watermark:ranking"].Value, &water); e != nil {
			return fail(e), nil
		}
		bump := water.Last
		for _, p := range b.threads {
			if v := p.BumpValue(); v > bump {
				bump = v
			}
		}
		if bump == domain.U64(math.MaxUint64) {
			return fail(postinput.ErrInput), nil
		}
		c := postinput.BuildContext{DisplayCommands: s.Identity.DisplayCommands, AllowStrengthen: s.Identity.AllowStrengthen, Board: b.owner, SourceIP: observation.Resolved.IP, Now: now, PublicKey: b.publicKey, SlipNetKey: b.slipNetKey, SlipUAKey: b.slipUAKey, Network: b.classifyNetwork(s.Identity.Networks, ip), UserAgent: observedUserAgent(observation.SelectedHeaders), Bump: bump + 1, Dedup: d,
			Versions: domain.Versions{Site: site.PublicRevision, Board: s.Version},
			Policy:   initialPostingPolicy(s),
			Limits:   postinput.Limits{EndResponses: endings, Name: s.Input.NameBytes, Mail: s.Input.MailBytes, Title: s.Input.TitleBytes, Body: s.Input.BodyBytes, Lines: s.Input.BodyLines, Noname: s.Input.Noname, EndMessage: s.Thread.EndMessage, NameRequired: s.Input.NameRequired, ForceNoname: s.Input.ForceNoname, HideMail: s.Input.HideMail}}
		c.AnonymousID = verified.ID
		if cap != nil {
			c.Cap = &postinput.Cap{ID: cap.ID, Name: cap.Name, Revision: cap.Revision}
		}
		var ticket *abuse.RateTicket
		finished := false
		if b.admission != nil {
			ticket, c.RateKeys, c.Now, e = b.admission.reserveOverrides(b.owner, ip, key == 0, b.clock, verified.ID, overrides)
			if e != nil {
				return fail(e), nil
			}
			c.Dedup = input.Dedup(b.dedupKey, b.owner, key, append([]byte{family}, ip.AsSlice()...), domain.Time(c.Now.UnixNano()))
			defer func() {
				if !finished {
					if err := b.admission.limits.Release(ticket); err != nil {
						b.stopped = true
					}
				}
			}()
		}
		if e := anonymousWait(verified, tokenWait, c.Now); e != nil {
			return fail(e), nil
		}
		if verified.ID != (domain.ID{}) && verified.Expires <= c.Now.Unix() {
			return fail(abuse.ErrToken), nil
		}
		if privateReceipt && !boardAutoReportsEnabled(receiptTargetBoard.autoReports.Load()) {
			return fail(ErrAutoReportDisabled), nil
		}
		var frame []byte
		if privateReceipt {
			copyInput := input
			// 返信にタイトル制限を適用しない。破棄する検証用frameには最小の仮タイトルを使う。
			copyInput.Title = "."
			_, e = postinput.Build(nil, copyInput, c)
		} else if key == 0 {
			frame, e = postinput.Build(nil, input, c)
		} else if p := b.threads[key]; p != nil {
			frame, e = p.PreparePost(input, c)
		} else {
			e = postinput.ErrInput
		}
		if e != nil {
			return fail(e), nil
		}
		if !privateReceipt {
			display := postcapture.Display{Noname: c.Limits.Noname, ForceNoname: c.Limits.ForceNoname, HideMail: c.Limits.HideMail}
			if cap == nil {
				capture, e = postcapture.New(observation, input, key, display, frame)
			} else {
				capture, e = postcapture.NewWithCap(observation, input, key, display, frame, postcapture.CapEvidence{ID: cap.ID, Revision: cap.Revision, Name: cap.Name, KeyID: cap.KeyID})
			}
			if e != nil {
				return fail(e), nil
			}
			if len(overrides) > 0 {
				capture, e = postcapture.WithOverrides(capture, overrides)
				if e != nil {
					return fail(e), nil
				}
			}
			if anonState != nil {
				var proof *postcapture.TokenEvidence
				if tokenStatus == "valid" {
					_, rate := b.admission.tokenCharge(b.owner, verified.ID, key == 0)
					proof = &postcapture.TokenEvidence{Subject: anonState.subject(verified.ID), Rate: rate}
				}
				capture, e = postcapture.WithAnonymous(capture, frame, key, tokenStatus, proof)
				if e != nil {
					return fail(e), nil
				}
			}
		}
		if e = ctx.Err(); e != nil {
			return fail(e), nil
		}
		if cap != nil {
			if _, e = authenticateCap(b.liveCaps.Load(), b.capKey, cap.ID, capSecretRaw, b.owner, key == 0, domain.Time(b.clock().UnixNano())); e != nil {
				return fail(e), nil
			}
		}
		var result RepositoryPostingResult
		if privateReceipt {
			if cap != nil {
				tokenSubject = domain.Hash{}
			}
			result, privateMessage = r.savePrivateReport(b, input, c.Dedup, receiptRef, receiptTarget, tokenSubject, ip, c.Now)
		} else {
			result = b.postAdmitted(key, frame, capture)
		}
		if errors.Is(result.Err, app.ErrPostingPrepared) && !result.Duplicate {
			b.group.guards = append(b.group.guards, postingGuard{b.group.current, func() error {
				if b.currentSiteRevision != nil && b.currentSiteRevision() != site.PublicRevision {
					return ErrPostingUnavailable
				}
				if cap != nil {
					_, err := authenticateCap(b.liveCaps.Load(), b.capKey, cap.ID, capSecretRaw, b.owner, false, domain.Time(b.clock().UnixNano()))
					return err
				}
				return nil
			}})
		}
		if ticket != nil {
			if errors.Is(result.Err, app.ErrPostingPrepared) {
				finished = true
				b.group.settlers = append(b.group.settlers, func(saved store.CommitResult) error {
					switch {
					case saved.Status == store.Unknown:
						return b.admission.limits.Uncertain(ticket)
					case saved.Status == store.Durable && !result.Duplicate:
						return b.admission.limits.Commit(ticket)
					default:
						return b.admission.limits.Release(ticket)
					}
				})
				return legacyResult(result), nil
			}
			switch {
			case result.Status == store.Unknown:
				e = b.admission.limits.Uncertain(ticket)
			case result.Status == store.Durable && !result.Duplicate:
				e = b.admission.limits.Commit(ticket)
			default:
				e = b.admission.limits.Release(ticket)
			}
			finished = true
			if e != nil {
				b.stopped = true
				result.Status, result.Err = store.Unknown, e
			}
		}
		return legacyResult(result), nil
	})
	if e != nil {
		return fail(e)
	}
	result = value.(LegacyFormResult)
	if repeatCandidate != nil {
		if err := r.recordViolation(*repeatCandidate); err != nil {
			return fail(err)
		}
	}
	r.recordPostingLatency(started, result.RepositoryPostingResult)
	if anonymousMode == "off" && rawAnonymous != "" {
		base, _ := parseOrigin(r.cfg.Public.BaseURL)
		result.AnonymousCookie = &http.Cookie{Name: "oimo_anon", Path: "/", HttpOnly: true, Secure: base.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: -1}
	}
	if anonymousMode != "off" && (result.Confirmation != nil || result.Status == store.Durable && tokenStatus == "valid") {
		ip, err := parseRateIP(observation.Resolved.IP)
		if err != nil {
			return fail(err)
		}
		cookie, err := r.anonymousCookie(rawAnonymous, ip, time.Now)
		if err != nil {
			// 受理済み投稿の成功を更新Cookieの失敗で取り消さない。
			if result.Status == store.Durable {
				return result
			}
			return fail(err)
		} else {
			result.AnonymousCookie = cookie
		}
	}
	return result
}

var ErrPostingDisabled = errors.New("posting disabled by board administrator")

func formFailure(e error) RepositoryPostingResult {
	return RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: e}}}
}
