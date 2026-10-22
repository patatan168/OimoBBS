// 要求識別と時計値を原本から返し、時計逆行や欠測を補正しないことを検査する。
package app

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"slices"
	"testing"
)

func TestAcceptedRequestMetadataPreservesObservation(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	var p postingProposal
	if e := json.Unmarshal(r.Proposal.Payload, &p); e != nil {
		t.Fatal(e)
	}
	obs := &evidence.HTTPObservation{SiteID: domain.NewID(), InstanceID: domain.NewID(), BoardID: r.Board, BootID: domain.NewID(), ConnectionID: domain.NewID(), RequestID: domain.NewID(), Received: r.Committed - 100, BodyCompleted: r.Committed - 150, MonotonicElapsed: 80}
	result, e := projectAcceptedResult(r, p)
	if e != nil {
		t.Fatal(e)
	}
	identity, timing, e := projectAcceptedRequestMetadata(r, p, obs, result)
	if e != nil {
		t.Fatal(e)
	}
	assertAcceptedIdentity(t, identity, obs)
	assertAcceptedClock(t, timing, obs)
	if timing["prepared_at_ns"] != nil || timing["response_finished_at_ns"] != nil {
		t.Fatal("unrecorded prepare/response time inferred")
	}
	if len(timing["missing_fields"].([]evidence.MissingField)) != 2 {
		t.Fatal("missing prepare/response fields not explained")
	}
}

func assertAcceptedIdentity(t *testing.T, identity map[string]any, obs *evidence.HTTPObservation) {
	t.Helper()
	for key, id := range map[string]domain.ID{"site_id": obs.SiteID, "site_instance_id": obs.InstanceID, "board_id": obs.BoardID, "process_boot_id": obs.BootID, "connection_id": obs.ConnectionID, "request_id": obs.RequestID} {
		if identity[key] != id {
			t.Fatal("observed identity replaced", key)
		}
	}
	if !slices.Equal(identity["post_numbers"].([]uint32), []uint32{1}) {
		t.Fatal("committed post numbers lost")
	}
}

func assertAcceptedClock(t *testing.T, timing map[string]any, obs *evidence.HTTPObservation) {
	t.Helper()
	if timing["received_at_ns"] != obs.Received || timing["body_completed_at_ns"] != obs.BodyCompleted || timing["monotonic_elapsed_ns"] != obs.MonotonicElapsed {
		t.Fatal("wall-clock regression hidden", timing)
	}
}

func TestAcceptedRequestMetadataDoesNotInventLegacyObservation(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	selected, e := r.Project([]string{"connection"})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(selected)
	var decoded map[string]any
	if e = json.Unmarshal(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"identity", "time", "connection"} {
		if decoded[key] != nil {
			t.Fatal("legacy observation inferred", key)
		}
	}
	if decoded["connection_missing_reason"] != "not_recorded_in_capture" {
		t.Fatal("legacy gap not explained")
	}
	unselected, e := r.Project(nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, found := unselected["identity"]; found {
		t.Fatal("unselected request IDs disclosed")
	}
}
