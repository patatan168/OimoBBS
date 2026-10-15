// 板単位のスレ立て再送を、正規化済み要求と匿名主体のHMACで索引化する。
package bootstrap

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
)

type createRequestKey struct {
	mode    string
	keyID   uint32
	subject domain.Hash
	token   domain.Hash
}

func createRequest(d *domain.Dedup) createRequestKey {
	token := d.Request
	if d.Mode == "explicit" && d.RequestID != nil {
		token = *d.RequestID
	}
	return createRequestKey{d.Mode, d.KeyID, d.Subject, token}
}
func (b *postingBoard) restoreCreateRequests(now domain.Time) error {
	b.createRequests = map[createRequestKey]uint64{}
	explicit := map[createRequestKey]bool{}
	for _, p := range b.threads {
		for _, d := range p.ExplicitDedups(now) {
			k := createRequest(d)
			if explicit[k] {
				return app.ErrEvidenceGap
			}
			explicit[k] = true
		}
	}
	for key, p := range b.threads {
		d := p.CreateDedup(now)
		if d == nil {
			continue
		}
		request := createRequest(d)
		if old, exists := b.createRequests[request]; exists && old != key {
			return app.ErrEvidenceGap
		}
		b.createRequests[request] = key
	}
	return nil
}

// explicitRetry はスレッドをまたぐ同一IDを板全体で照合する。
func (b *postingBoard) explicitRetry(want *domain.Dedup, now domain.Time) (RepositoryPostingResult, bool) {
	for key, p := range b.threads {
		if result, ok := p.Retry(want, now); ok {
			return RepositoryPostingResult{result, key}, true
		}
	}
	return RepositoryPostingResult{}, false
}
