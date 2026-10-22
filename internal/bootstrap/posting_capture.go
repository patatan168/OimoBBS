// HTTP観測成分をサイト・板へ固定し、別保存先での流用を拒否する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
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
