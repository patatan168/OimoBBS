// Web/legacy共通の通常フォーム受付。確認・再送・受理規制を板ワーカーへ接続する。
package bootstrap

import (
	"context"
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
	capture, e := evidence.MarshalHTTPObservation(observation)
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
		r.recordBotFailure(rawAnonymous, "honeypot", observation.Route, body, time.Now())
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
		if !ok || !b.matchesKey(r.cfg.AutoReports.BoardKey) && !b.matchesKey(receiptRef.Board) {
			return fail(errors.Join(postinput.ErrInput, ErrAutoReportInput))
		}
		r.mu.Lock()
		for id, board := range r.posting {
			if board.matchesKey(receiptRef.Board) {
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
	// 正規化とtrip生成は入力・不変の用途鍵だけに依存し、HTTP側で並行して準備できる。
	// エラーは従来の所有列内の位置で返し、認可・停止判定の優先順を変えない。
	cleanFields := make(map[string]string, len(fields))
	for k, v := range fields {
		cleanFields[k] = v
	}
	cleanFields["mail"] = cleanMail
	preparedInput, inputErr := postinput.Prepare(cleanFields, key == 0, b.dedupKey)
	// 規約本文のJSONを投稿ごとに復号せず、不変のスナップショットを共有する。
	var anonState *anonymousState
	siteSnapshot := r.liveConsent.Load()
	if siteSnapshot == nil {
		return fail(ErrPostingUnavailable)
	}
	site := siteSnapshot.Site
	consentDigest := siteSnapshot.Digest
	site.PublicRevision = domain.U64(r.publicRevision.Load())
	// 入力された板キーを固定し、所有板との一致は保存前の所有列で検査する。
	observation, e = observation.WithBoardAlias(fields["bbs"])
	if e != nil {
		return fail(e)
	}
	// 分類用キャッシュのDNS観測を原本へ固定し、提出時には再照会しない。
	observation, e = r.observePostingReverseDNS(ctx, observation)
	if e != nil {
		return fail(e)
	}
	capture, e = evidence.MarshalHTTPObservation(observation)
	if e != nil {
		return fail(e)
	}
	var originRecast tokenReissue
	if ip, err := netip.ParseAddr(observation.Resolved.IP); err == nil {
		r.mu.RLock()
		if r.anonymous != nil {
			row, ok := r.site.State().Rows["token_reissue:"+r.tokenReissueOrigin(ip).String()]
			if ok {
				e = strictjson.Decode(row.Value, &originRecast)
			}
		}
		r.mu.RUnlock()
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

	// 直結HTTP観測の検査は不変byteだけを読む。並行可能な標準検査器は所有列へ入る前に実行する。
	// 拒否を返す位置は従来通りとし、停止・板名不一致の優先順を維持する。
	var observationErr error
	if b.parallelCaptureValidation {
		observationErr = b.validateBase(capture)
	}
	value, e := submit(func() (any, error) {
		if b.group != nil && b.group.pendingKeys[key] {
			b.group.finishPreparations()
		}
		if b.group != nil && (b.group.rebuild || b.group.full) {
			return fail(errPostingRebuild), nil
		}
		anonState = r.liveAnonymous.Load()
		if b.stopped {
			return fail(ErrPostingUnavailable), nil
		}
		if !b.matchesKey(fields["bbs"]) {
			return fail(postinput.ErrInput), nil
		}
		if b.parallelCaptureValidation {
			if observationErr != nil {
				return fail(observationErr), nil
			}
		} else if e := b.validate(capture); e != nil {
			return fail(e), nil
		}
		settings, settingsErr := b.postingFormSettings()
		if settingsErr != nil {
			return fail(settingsErr), nil
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
		if inputErr != nil {
			return fail(inputErr), nil
		}
		// バッチ再試行でも資格HMACを重ねず、毎回元の入力から始める。
		input := preparedInput
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
				if malformedCSRF(fields["csrf"]) {
					r.recordBotFailure(rawAnonymous, "malformed_csrf", observation.Route, body, now)
				}
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
		// 待機中の規約更新も再検査し、専ブラとWebに同じ同意を適用する。
		if latest := r.liveConsent.Load(); latest != nil {
			site.Terms, site.Consent = latest.Site.Terms, latest.Site.Consent
			consentDigest = latest.Digest
		}
		challenge, e := b.confirmation(confirmationToken, input, site, consentDigest, s, key, now)
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
		if cap == nil && tokenStatus == "valid" {
			if err := r.bot.check(tokenSubject, trafficNow()); err != nil {
				return fail(err), nil
			}
		}
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
		if b.group != nil {
			bump = max(bump, b.group.preparationBump)
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
			// 未確定の構築失敗が保持する枠で後続を拒否しない。先行分を所有列へ反映してから再照合する。
			var limited *abuse.RateLimited
			if errors.As(e, &limited) && b.group != nil && len(b.group.preparations) > 0 {
				b.group.finishPreparations()
				if b.group.rebuild || b.group.full {
					return fail(errPostingRebuild), nil
				}
				ticket, c.RateKeys, c.Now, e = b.admission.reserveOverrides(b.owner, ip, key == 0, b.clock, verified.ID, overrides)
			}

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
		var buildFrame func() ([]byte, error)
		var candidate *app.PreparedPosting
		var guard *guardEntry
		if privateReceipt {
			copyInput := input
			copyInput.Title = "."
			buildFrame = func() ([]byte, error) { return postinput.Build(nil, copyInput, c) }
		} else if key == 0 {
			buildFrame = func() ([]byte, error) { return postinput.Build(nil, input, c) }
		} else if p := b.threads[key]; p != nil {
			var buildCandidate func() (*app.PreparedPosting, error)
			buildCandidate, e = p.PreparePostingWork(input, c)
			if e == nil {
				buildFrame = func() ([]byte, error) {
					var err error
					candidate, err = buildCandidate()
					if err != nil {
						return nil, err
					}
					return candidate.Frame(), nil
				}
			}
		} else {
			e = postinput.ErrInput
		}
		if e != nil {
			return fail(e), nil
		}

		display := postcapture.Display{Noname: c.Limits.Noname, ForceNoname: c.Limits.ForceNoname, HideMail: c.Limits.HideMail}
		proof := postcapture.Proof{Overrides: overrides, TokenStatus: "not_checked"}
		if cap != nil {
			proof.Cap = &postcapture.CapEvidence{ID: cap.ID, Revision: cap.Revision, Name: cap.Name, KeyID: cap.KeyID}
		}
		if anonState != nil {
			proof.TokenStatus = tokenStatus
			if tokenStatus == "valid" {
				_, rate := b.admission.tokenCharge(b.owner, verified.ID, key == 0)
				proof.Token = &postcapture.TokenEvidence{Subject: anonState.subject(verified.ID), Rate: rate}
			}
		}
		work := func() ([]byte, []byte, *postcapture.Capture, error) {
			frame, err := buildFrame()
			if err != nil {
				return nil, nil, nil, err
			}
			if privateReceipt {
				return frame, capture, nil, nil
			}
			raw, metadata, err := postcapture.NewWithProofMetadata(observation, input, key, display, frame, proof)
			if err == nil && candidate != nil {
				f, op, rate := candidate.Metadata()
				rate.TokenStatus, rate.Token = metadata.TokenValidation, metadata.Token
				var entry guardEntry
				entry, err = b.guardCandidate(op, f.Records[0].ID, key, rate)
				guard = &entry
			}
			return frame, raw, metadata, err
		}
		rejectCompletion := func(err error) (any, error) {
			if ticket != nil {
				if releaseErr := b.admission.limits.Release(ticket); releaseErr != nil {
					b.stopped = true
					err = releaseErr
				}
			}
			return fail(err), nil
		}
		complete := func(frame, capture []byte, captureMetadata *postcapture.Capture, buildErr error) (any, error) {
			if buildErr != nil {
				return rejectCompletion(buildErr)
			}
			if err := ctx.Err(); err != nil {
				return rejectCompletion(err)
			}
			if cap != nil {
				if _, err := authenticateCap(b.liveCaps.Load(), b.capKey, cap.ID, capSecretRaw, b.owner, key == 0, domain.Time(b.clock().UnixNano())); err != nil {
					return rejectCompletion(err)
				}
			}

			var result RepositoryPostingResult
			if privateReceipt {
				if cap != nil {
					tokenSubject = domain.Hash{}
				}
				result, privateMessage = r.savePrivateReport(b, input, c.Dedup, receiptRef, receiptTarget, tokenSubject, ip, c.Now)
			} else {
				result = b.postAdmittedCandidate(key, frame, capture, captureMetadata, candidate, guard)
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
		}

		if b.group != nil && key != 0 && !privateReceipt {
			release, err := b.reservePreparation()
			if err == nil {
				finished = true
				b.group.preparationBump = c.Bump
				b.group.addPreparation(key, work, complete, release)
				return fail(errPostingPreparing), nil
			}
			if b.group.hasPrepared() {
				b.group.full = true
				return fail(errPostingRebuild), nil
			}
		}
		frame, raw, metadata, err := work()
		finished = true
		return complete(frame, raw, metadata, err)

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
