// 独立carryの大きな集合・途中Sync・改変を実WALと製品codecで検証する。
package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func carryCollectionFixture(t *testing.T) (app.BodyCarry, app.BodyReclamation) {
	t.Helper()
	carry := app.BodyCarry{Dedups: []app.DedupCarry{}, Rates: []app.RateCarry{}}
	at := domain.Time(time.Now().Add(-time.Minute).UnixNano())
	rule := domain.NewID()
	for i := range 300 {
		id := domain.NewID()
		value := domain.Dedup{Mode: "implicit", KeyID: 8, PostNumber: uint32(i + 1), Expires: at + 30e9}
		d := store.PackDedup{ID: id, Seq: domain.U64(i + 1), Committed: at, Value: value}
		raw, e := store.EncodeRejectedDedup(d, d.Seq, 0)
		if e != nil {
			t.Fatal(e)
		}
		carry.Dedups = append(carry.Dedups, app.DedupCarry{ID: id, Source: d.Seq, Entry: base64.StdEncoding.EncodeToString(raw)})
		carry.Rates = append(carry.Rates, app.RateCarry{ID: id, Number: uint32(i + 1), At: at, Expires: at + 3660e9, Keys: []domain.RateKey{{Rule: rule, KeyID: 7, Subject: domain.Hash{1}, Cost: 1}}})
	}
	d, r, e := carry.Digest(0)
	if e != nil {
		t.Fatal(e)
	}
	return carry, app.BodyReclamation{Schema: 2, Deletion: domain.NewID(), Key: 1, At: at, Sequence: 300, DedupSHA: d, RateSHA: r}
}

func TestBodyCarryPagedRecovery(t *testing.T) {
	for _, stage := range []string{"", "reclaim:carry_page", "reclaim:carry_seal"} {
		t.Run(stage, func(t *testing.T) {
			carry, proof := carryCollectionFixture(t)
			proof.Owner = domain.NewID()
			parent := t.TempDir()
			if e := os.Chmod(parent, 0700); e != nil {
				t.Fatal(e)
			}
			dir := filepath.Join(parent, "carry")
			first, e := controlFrame(store.ControlState{Rows: map[string]store.ControlRow{}}, domain.NewID(), proof.At, "thread_body_carry", []store.Mutation{mutation("dedup_carry", carry.Dedups[0].ID.String(), carry.Dedups[0], nil)}, []string{proof.Deletion.String()})
			if e != nil {
				t.Fatal(e)
			}
			log, e := store.CreateControl(dir, store.Header{Kind: 3, Owner: proof.Owner, Key: uint64(proof.Key), Generation: 1}, first, validateDeletion)
			if e != nil {
				t.Fatal(e)
			}
			b := &postingBoard{deletions: map[uint64]*store.ControlLog{1: log}, checkpoint: func(string) {}}
			b.deletionCheckpoint = func(s string) error {
				if stage != "" && s == stage {
					return errors.New("crash")
				}
				return nil
			}
			e = b.persistBodyCarry(proof, carry)
			if (e != nil) != (stage != "") {
				t.Fatal(e)
			}
			if e = log.Close(); e != nil {
				t.Fatal(e)
			}
			log, e = store.OpenControl(dir, 3, proof.Owner, 1, validateDeletion)
			if e != nil {
				t.Fatal(e)
			}
			defer log.Close()
			b.deletions[1] = log
			b.deletionCheckpoint = nil
			before := log.State().Seq
			ready, e := readBodyCarry(log.State(), proof)
			if e != nil {
				t.Fatal(e)
			}
			if ready == nil {
				if e = b.persistBodyCarry(proof, carry); e != nil {
					t.Fatal(e)
				}
			} else if log.State().Seq != before {
				t.Fatal("read mutated state")
			}
			ready, e = readBodyCarry(log.State(), proof)
			if e != nil || ready == nil || len(ready.Dedups) != 300 || len(ready.Rates) != 300 {
				t.Fatal("carry recovery", e)
			}
			checkCarryTamper(t, log.State(), proof)
		})
	}
}

func checkCarryTamper(t *testing.T, state store.ControlState, proof app.BodyReclamation) {
	t.Helper()
	for _, kind := range []string{"missing_dedup", "dedup_source", "missing_rate", "rate_expiry", "rate_keys", "seal_proof", "seal_count"} {
		t.Run(kind, func(t *testing.T) {
			rows := map[string]store.ControlRow{}
			for name, row := range state.Rows {
				rows[name] = row
			}
			changed := false
			for name, row := range rows {
				switch {
				case kind == "missing_dedup" && strings.HasPrefix(name, "dedup_carry:"):
					delete(rows, name)
					changed = true
				case kind == "dedup_source" && strings.HasPrefix(name, "dedup_carry:"):
					var v app.DedupCarry
					if e := json.Unmarshal(row.Value, &v); e != nil {
						t.Fatal(e)
					}
					v.Source++
					row.Value, _ = json.Marshal(v)
					rows[name] = row
					changed = true
				case (kind == "missing_rate" || kind == "rate_expiry" || kind == "rate_keys") && strings.HasPrefix(name, "rate_carry:"):
					if kind == "missing_rate" {
						delete(rows, name)
					} else {
						var v app.RateCarry
						if e := json.Unmarshal(row.Value, &v); e != nil {
							t.Fatal(e)
						}
						if kind == "rate_expiry" {
							v.Expires++
						} else {
							v.Keys[0].Subject[0] ^= 1
						}
						row.Value, _ = json.Marshal(v)
						rows[name] = row
					}
					changed = true
				case (kind == "seal_proof" || kind == "seal_count") && name == "reclamation:carry":
					var v bodyCarrySeal
					if e := json.Unmarshal(row.Value, &v); e != nil {
						t.Fatal(e)
					}
					if kind == "seal_proof" {
						v.Proof[0] ^= 1
					} else {
						v.Rates++
					}
					row.Value, _ = json.Marshal(v)
					rows[name] = row
					changed = true
				}
				if changed {
					break
				}
			}
			if !changed {
				t.Fatal(fmt.Sprint("missing fixture ", kind))
			}
			if _, e := readBodyCarry(store.ControlState{Seq: state.Seq, Rows: rows}, proof); e == nil {
				t.Fatal("tampered carry accepted")
			}
		})
	}
}
