// 完成ペアに署名登録した関連計画を用途別に照合し、出力除去前に使用済みへ同期する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

// BackupPairRelatedPlans は既存の本文部分/鍵束部分/完成鍵束計画の配置。
// 完成ペア作成時に登録する。回収時には署名された配置だけを使う。
type BackupPairRelatedPlans struct {
	PartialPlan     string
	PartialKeysPlan string
	KeysPlan        string
}

type backupPairRelatedRef struct {
	Kind string      `json:"kind"`
	Path string      `json:"plan_file"`
	SHA  domain.Hash `json:"plan_sha256"`
}

type backupPairPlanV2 struct {
	Schema  uint32                   `json:"schema"`
	Mode    string                   `json:"mode"`
	Body    backupPartialCleanupPlan `json:"body"`
	Keys    backupKeysCleanupPlan    `json:"keys"`
	Related []backupPairRelatedRef   `json:"related_plans"`
}

type backupPairRelatedState struct {
	ref     backupPairRelatedRef
	raw     []byte
	limit   int64
	retired bool
}

// relatedPaths は3用途を固定順に列挙し、信頼根/ペア計画/両出力との重なりを拒否する。
func (opts BackupPairRelatedPlans) relatedPaths(body, keys, trust, plan string) ([]backupPairRelatedRef, error) {
	refs := []backupPairRelatedRef{}
	all := []string{body, keys, trust, plan, plan + backupKeysRetireSuffix}
	for i, path := range []string{opts.PartialPlan, opts.PartialKeysPlan, opts.KeysPlan} {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("related plans require clean absolute paths")
		}
		for _, candidate := range []string{path, path + backupKeysRetireSuffix} {
			for _, other := range all {
				if e := separateBackupPaths(candidate, other); e != nil {
					return nil, e
				}
			}
		}
		all = append(all, path, path+backupKeysRetireSuffix)
		refs = append(refs, backupPairRelatedRef{relatedPlanKinds[i], path, domain.Hash{}})
	}
	return refs, nil
}

var relatedPlanKinds = [3]string{"partial_body", "partial_keys", "complete_keys"}

// validateRelatedRefs は署名された最大3用途を重複/逆順/出力内pathなしで検査する。
func validateRelatedRefs(p backupPairPlan, refs []backupPairRelatedRef) error {
	if len(refs) == 0 || len(refs) > 3 {
		return errors.New("invalid related plan count")
	}
	paths := []string{p.Body.Root, p.Keys.Root, p.Body.Plan, p.Body.Plan + backupKeysRetireSuffix}
	last := -1
	for _, ref := range refs {
		index := -1
		for i, kind := range relatedPlanKinds {
			if kind == ref.Kind {
				index = i
			}
		}
		if index <= last || index < 0 || ref.SHA == (domain.Hash{}) || !filepath.IsAbs(ref.Path) || filepath.Clean(ref.Path) != ref.Path || len(ref.Path)+len(backupKeysRetireSuffix) > 4096 || len(filepath.Base(ref.Path))+len(backupKeysRetireSuffix) > 255 {
			return errors.New("invalid related plan reference")
		}
		last = index
		for _, candidate := range []string{ref.Path, ref.Path + backupKeysRetireSuffix} {
			for _, other := range paths {
				if e := separateBackupPaths(candidate, other); e != nil {
					return e
				}
			}
		}
		paths = append(paths, ref.Path, ref.Path+backupKeysRetireSuffix)
	}
	return nil
}

// loadPairRelatedPlans は全計画の署名・用途・root/manifest対応を照合する。payload/計画は変更しない。
func loadPairRelatedPlans(ctx context.Context, p backupPairPlan, refs []backupPairRelatedRef, trust instance, trustRaw []byte, trustPath string, allowRetired bool) ([]backupPairRelatedState, error) {
	states := []backupPairRelatedState{}
	for _, ref := range refs {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		for _, candidate := range []string{ref.Path, ref.Path + backupKeysRetireSuffix} {
			if e := separateBackupPaths(candidate, trustPath); e != nil {
				return nil, e
			}
		}
		state, e := loadPairRelatedPlan(p, ref, trust, trustRaw, allowRetired)
		if e != nil {
			return nil, e
		}
		states = append(states, state)
	}
	return states, nil
}

func loadPairRelatedPlan(p backupPairPlan, ref backupPairRelatedRef, trust instance, trustRaw []byte, allowRetired bool) (state backupPairRelatedState, err error) {
	state.ref = ref
	state.limit = backupKeysPlanLimit
	if ref.Kind == "partial_body" {
		state.limit = backupPartialPlanLimit
	}
	state.raw, err = readPrivate(ref.Path, state.limit)
	if err != nil {
		return state, err
	}
	var env backupKeysPlanEnvelope
	if err = strictjson.Decode(state.raw, &env); err != nil {
		return state, err
	}
	if ref.SHA != (domain.Hash{}) && ref.SHA != env.SHA {
		return state, errors.New("related plan signed payload changed")
	}
	state.ref.SHA = env.SHA
	state.retired = env.Retired
	switch ref.Kind {
	case "partial_body":
		q, e := decodeBackupPartialPlanState(state.raw, trust, trustRaw, allowRetired)
		if e != nil {
			return state, e
		}
		b := p.Body
		if q.Root != b.Root || q.Plan != ref.Path || q.Device != b.Device || q.Inode != b.Inode || q.TrustSHA != b.TrustSHA || q.ManifestSHA != b.ManifestSHA || q.ManifestBytes != b.ManifestBytes {
			return state, errors.New("related body plan binding mismatch")
		}
		err = matchRelatedManifest(q.Manifest, b.Manifest)
	case "partial_keys":
		q, e := decodePartialKeysPlanState(state.raw, trust, trustRaw, allowRetired)
		if e != nil {
			return state, e
		}
		k := p.Keys
		if q.Root != k.Root || q.Plan != ref.Path || q.Device != k.Device || q.Inode != k.Inode || q.TrustSHA != k.TrustSHA || q.BundleSHA != k.BundleSHA {
			return state, errors.New("related partial keys binding mismatch")
		}
		err = matchRelatedManifest(q.Bundle, k.Bundle)
	case "complete_keys":
		q, e := decodeBackupKeysPlanState(state.raw, trust, trustRaw, allowRetired)
		if e != nil {
			return state, e
		}
		k := p.Keys
		if q.Root != k.Root || q.Plan != ref.Path || q.Device != k.Device || q.Inode != k.Inode || q.TrustSHA != k.TrustSHA || q.BundleSHA != k.BundleSHA || q.Created > k.Created {
			return state, errors.New("related complete keys binding mismatch")
		}
		err = matchRelatedManifest(q.Bundle, k.Bundle)
	default:
		return state, errors.New("unknown related plan purpose")
	}
	return state, err
}

// matchRelatedManifest は用途別署名で認証済みのmanifest全項目の一致を要求する。
func matchRelatedManifest[T any](a, b T) error {
	ar, e := json.Marshal(a)
	if e != nil {
		return e
	}
	br, e := json.Marshal(b)
	if e != nil {
		return e
	}
	if string(ar) != string(br) {
		return errors.New("related plan manifest mismatch")
	}
	return nil
}

// retirePairRelatedPlans は事前照合済みの未使用計画だけを同期退役させ、成功数を境界ごとに記録する。
func retirePairRelatedPlans(ctx context.Context, states []backupPairRelatedState, report *BackupPairReport, boundary func(string) error) error {
	for _, state := range states {
		if e := ctx.Err(); e != nil {
			return e
		}
		if state.retired {
			continue
		}
		if e := retireBackupCleanupPlan(state.ref.Path, state.raw, state.limit); e != nil {
			return e
		}
		*report.RelatedRetiredCount++
		if e := boundary("pair:related_plan_retired"); e != nil {
			return e
		}
	}
	return nil
}

// requirePairRelatedRetired はroot除去や鍵回収へ進む前に、登録計画の現存署名と使用済み印を再検査する。
func requirePairRelatedRetired(ctx context.Context, p backupPairPlan, refs []backupPairRelatedRef, trust instance, trustRaw []byte, trustPath string, report *BackupPairReport) error {
	if len(refs) == 0 {
		return nil
	}
	states, e := loadPairRelatedPlans(ctx, p, refs, trust, trustRaw, trustPath, true)
	if e != nil {
		return e
	}
	retired := 0
	for _, state := range states {
		if state.retired {
			retired++
		}
	}
	*report.RelatedRetiredCount = retired
	if retired != len(states) {
		return errors.New("related plan retirement was rolled back")
	}
	return nil
}
