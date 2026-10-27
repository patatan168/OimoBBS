// HTTP観測成分をサイト・板へ固定し、別保存先での流用を拒否する。
package bootstrap

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
)

func bindPostingCapture(validate func([]byte) error, site, board domain.ID) func([]byte) error {
	return func(raw []byte) error {
		if e := validate(raw); e != nil {
			return e
		}
		observation, e := evidence.PostingHTTPObservation(raw)
		if e != nil {
			return e
		}
		if observation != nil && (observation.SiteID != site || observation.BoardID != board) {
			return evidence.ErrHTTPObservation
		}
		return nil
	}
}

// validateCaptureMetadata は資格・追加規制を照合し、鍵回収の下限を排他更新する。
// 並行呼出し中は所有列が停止しており、規制の変更やcapCommittedの参照を行わない。
func (b *postingBoard) validateCaptureMetadata(capture *postcapture.Capture) error {
	b.captureMetadataMu.Lock()
	defer b.captureMetadataMu.Unlock()
	if err := b.validateOverrideCaptureValue(capture); err != nil {
		return err
	}
	if err := validateCapEvidence(capture.Cap, capture.Committed, capture.Target == 0, b.liveCaps.Load(), b.owner); err != nil {
		return err
	}
	if capture.Cap != nil {
		b.capCommitted[capture.Cap.ID] = max(b.capCommitted[capture.Cap.ID], capture.Committed)
	}
	return nil
}

// postingValidator は外部検証器の契約に従って必須記録の独立検証を組み立てる。
func (b *postingBoard) postingValidator() evidence.PayloadValidator {
	if b.parallelCaptureValidation {
		return app.PostingValidatorConcurrent(b.validate)
	}
	return app.PostingValidator(b.validate)
}
