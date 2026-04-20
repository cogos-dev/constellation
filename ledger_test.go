// ledger_test.go — Tests for hash-chained event ledger and coherence validation.
//
// Covers: CanonicalizeEvent, HashEvent, NewEvent, canonicalJSON (RFC 8785),
// ValidateCoherence (hash chain, schema, temporal monotonicity).
package constellation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Area 4: Ledger Operations — Canonicalization
// ---------------------------------------------------------------------------

func TestCanonicalizeEvent_SortedKeys(t *testing.T) {
	// RFC 8785 requires sorted keys. Verify the output has alphabetical key order.
	payload := &EventPayload{
		Type:      "test",
		Timestamp: "2026-04-10T00:00:00Z",
		NodeID:    "abc123",
	}

	canonical, err := CanonicalizeEvent(payload)
	if err != nil {
		t.Fatalf("CanonicalizeEvent error: %v", err)
	}

	// The keys should be sorted: "node_id", "timestamp", "type"
	expected := `{"node_id":"abc123","timestamp":"2026-04-10T00:00:00Z","type":"test"}`
	if string(canonical) != expected {
		t.Errorf("canonical JSON:\n  got:  %s\n  want: %s", string(canonical), expected)
	}
}

func TestCanonicalizeEvent_WithPriorHash(t *testing.T) {
	// When prior_hash is set, it should appear in the canonical output.
	payload := &EventPayload{
		Type:      "test",
		Timestamp: "2026-04-10T00:00:00Z",
		NodeID:    "abc123",
		PriorHash: "deadbeef",
	}

	canonical, err := CanonicalizeEvent(payload)
	if err != nil {
		t.Fatalf("CanonicalizeEvent error: %v", err)
	}

	// Keys sorted: "node_id", "prior_hash", "timestamp", "type"
	expected := `{"node_id":"abc123","prior_hash":"deadbeef","timestamp":"2026-04-10T00:00:00Z","type":"test"}`
	if string(canonical) != expected {
		t.Errorf("canonical JSON:\n  got:  %s\n  want: %s", string(canonical), expected)
	}
}

func TestCanonicalizeEvent_WithData(t *testing.T) {
	// When data is present, it should appear sorted in the canonical output.
	payload := &EventPayload{
		Type:      "test",
		Timestamp: "2026-04-10T00:00:00Z",
		NodeID:    "abc123",
		Data: map[string]interface{}{
			"zebra": "last",
			"alpha": "first",
		},
	}

	canonical, err := CanonicalizeEvent(payload)
	if err != nil {
		t.Fatalf("CanonicalizeEvent error: %v", err)
	}

	// The data map should also have sorted keys.
	// Full sorted key order: "data", "node_id", "timestamp", "type"
	expected := `{"data":{"alpha":"first","zebra":"last"},"node_id":"abc123","timestamp":"2026-04-10T00:00:00Z","type":"test"}`
	if string(canonical) != expected {
		t.Errorf("canonical JSON:\n  got:  %s\n  want: %s", string(canonical), expected)
	}
}

func TestCanonicalizeEvent_EmptyPriorHash_Omitted(t *testing.T) {
	// An empty prior_hash should not appear in canonical output.
	payload := &EventPayload{
		Type:      "test",
		Timestamp: "2026-04-10T00:00:00Z",
		NodeID:    "abc123",
		PriorHash: "",
	}

	canonical, err := CanonicalizeEvent(payload)
	if err != nil {
		t.Fatalf("CanonicalizeEvent error: %v", err)
	}

	// Should NOT contain "prior_hash".
	got := string(canonical)
	if contains(got, "prior_hash") {
		t.Errorf("canonical JSON should not contain prior_hash when empty: %s", got)
	}
}

func TestCanonicalizeEvent_Deterministic(t *testing.T) {
	// Same payload should always produce the same canonical bytes.
	payload := &EventPayload{
		Type:      "heartbeat",
		Timestamp: "2026-04-10T12:00:00.123456789Z",
		NodeID:    "deadbeef01234567",
		PriorHash: "aabbccdd",
		Data:      map[string]interface{}{"cycle": float64(42)},
	}

	c1, err := CanonicalizeEvent(payload)
	if err != nil {
		t.Fatalf("first CanonicalizeEvent error: %v", err)
	}
	c2, err := CanonicalizeEvent(payload)
	if err != nil {
		t.Fatalf("second CanonicalizeEvent error: %v", err)
	}

	if string(c1) != string(c2) {
		t.Errorf("non-deterministic canonicalization:\n  c1: %s\n  c2: %s", c1, c2)
	}
}

// ---------------------------------------------------------------------------
// HashEvent
// ---------------------------------------------------------------------------

func TestHashEvent_KnownVector(t *testing.T) {
	// SHA-256 of empty string is a known value.
	emptyHash := HashEvent([]byte(""))
	expectedEmptySHA := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if emptyHash != expectedEmptySHA {
		t.Errorf("HashEvent(\"\") = %s, want %s", emptyHash, expectedEmptySHA)
	}
}

func TestHashEvent_DifferentInputsDifferentHashes(t *testing.T) {
	h1 := HashEvent([]byte("hello"))
	h2 := HashEvent([]byte("world"))
	if h1 == h2 {
		t.Error("different inputs produced the same hash")
	}
}

func TestHashEvent_Deterministic(t *testing.T) {
	data := []byte(`{"node_id":"abc","timestamp":"2026-04-10T00:00:00Z","type":"test"}`)
	h1 := HashEvent(data)
	h2 := HashEvent(data)
	if h1 != h2 {
		t.Errorf("non-deterministic HashEvent: %s vs %s", h1, h2)
	}
}

func TestHashEvent_MatchesManualSHA256(t *testing.T) {
	data := []byte("constellation protocol test vector")
	manual := sha256.Sum256(data)
	expected := hex.EncodeToString(manual[:])
	got := HashEvent(data)
	if got != expected {
		t.Errorf("HashEvent = %s, manual SHA-256 = %s", got, expected)
	}
}

// ---------------------------------------------------------------------------
// NewEvent
// ---------------------------------------------------------------------------

func TestNewEvent_FirstEvent_NoPriorHash(t *testing.T) {
	// The first event in a ledger should have no prior_hash.
	env, err := NewEvent("node1", "init", 1, "", nil)
	if err != nil {
		t.Fatalf("NewEvent error: %v", err)
	}

	if env.HashedPayload.PriorHash != "" {
		t.Errorf("first event should have empty prior_hash, got %q", env.HashedPayload.PriorHash)
	}
	if env.Metadata.Seq != 1 {
		t.Errorf("seq = %d, want 1", env.Metadata.Seq)
	}
	if env.Metadata.Hash == "" {
		t.Error("hash is empty")
	}
	if env.HashedPayload.NodeID != "node1" {
		t.Errorf("node_id = %q, want %q", env.HashedPayload.NodeID, "node1")
	}
	if env.HashedPayload.Type != "init" {
		t.Errorf("type = %q, want %q", env.HashedPayload.Type, "init")
	}
}

func TestNewEvent_ChainedEvents_PriorHashLinked(t *testing.T) {
	// Creating events with prior_hash should link them.
	e1, err := NewEvent("node1", "heartbeat", 1, "", map[string]interface{}{"cycle": float64(1)})
	if err != nil {
		t.Fatalf("NewEvent(1) error: %v", err)
	}

	e2, err := NewEvent("node1", "heartbeat", 2, e1.Metadata.Hash, map[string]interface{}{"cycle": float64(2)})
	if err != nil {
		t.Fatalf("NewEvent(2) error: %v", err)
	}

	if e2.HashedPayload.PriorHash != e1.Metadata.Hash {
		t.Errorf("e2.prior_hash = %s, want %s (e1.hash)", e2.HashedPayload.PriorHash, e1.Metadata.Hash)
	}
}

func TestNewEvent_HashVerifiable(t *testing.T) {
	// The hash stored in metadata should match a fresh re-hash of the canonical payload.
	env, err := NewEvent("nodeX", "test", 1, "", map[string]interface{}{"key": "value"})
	if err != nil {
		t.Fatalf("NewEvent error: %v", err)
	}

	canonical, err := CanonicalizeEvent(&env.HashedPayload)
	if err != nil {
		t.Fatalf("CanonicalizeEvent error: %v", err)
	}
	recomputed := HashEvent(canonical)

	if recomputed != env.Metadata.Hash {
		t.Errorf("recomputed hash %s != stored hash %s", recomputed, env.Metadata.Hash)
	}
}

func TestNewEvent_TimestampIsRFC3339Nano(t *testing.T) {
	env, err := NewEvent("node1", "test", 1, "", nil)
	if err != nil {
		t.Fatalf("NewEvent error: %v", err)
	}

	_, parseErr := time.Parse(time.RFC3339Nano, env.HashedPayload.Timestamp)
	if parseErr != nil {
		t.Errorf("timestamp %q is not valid RFC3339Nano: %v", env.HashedPayload.Timestamp, parseErr)
	}
}

func TestNewEvent_WithData(t *testing.T) {
	data := map[string]interface{}{"key": "value", "count": float64(42)}
	env, err := NewEvent("node1", "test", 1, "", data)
	if err != nil {
		t.Fatalf("NewEvent error: %v", err)
	}
	if env.HashedPayload.Data == nil {
		t.Fatal("Data should not be nil")
	}
	if env.HashedPayload.Data["key"] != "value" {
		t.Errorf("Data[key] = %v, want 'value'", env.HashedPayload.Data["key"])
	}
}

// ---------------------------------------------------------------------------
// EventEnvelope JSON roundtrip
// ---------------------------------------------------------------------------

func TestEventEnvelope_JSONRoundtrip(t *testing.T) {
	// Serializing and deserializing an EventEnvelope should preserve all fields.
	original, err := NewEvent("node1", "heartbeat", 5, "priorfeed", map[string]interface{}{
		"cycle": float64(5),
	})
	if err != nil {
		t.Fatalf("NewEvent error: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var restored EventEnvelope
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if restored.Metadata.Hash != original.Metadata.Hash {
		t.Errorf("hash mismatch: %s vs %s", restored.Metadata.Hash, original.Metadata.Hash)
	}
	if restored.Metadata.Seq != original.Metadata.Seq {
		t.Errorf("seq mismatch: %d vs %d", restored.Metadata.Seq, original.Metadata.Seq)
	}
	if restored.HashedPayload.Type != original.HashedPayload.Type {
		t.Errorf("type mismatch: %s vs %s", restored.HashedPayload.Type, original.HashedPayload.Type)
	}
	if restored.HashedPayload.PriorHash != original.HashedPayload.PriorHash {
		t.Errorf("prior_hash mismatch: %s vs %s", restored.HashedPayload.PriorHash, original.HashedPayload.PriorHash)
	}
}

// ---------------------------------------------------------------------------
// Coherence Validation
// ---------------------------------------------------------------------------

func buildChain(t *testing.T, nodeID string, count int) []*EventEnvelope {
	t.Helper()
	events := make([]*EventEnvelope, 0, count)
	priorHash := ""
	for i := 1; i <= count; i++ {
		env, err := NewEvent(nodeID, "heartbeat", int64(i), priorHash, map[string]interface{}{
			"cycle": float64(i),
		})
		if err != nil {
			t.Fatalf("NewEvent(%d) error: %v", i, err)
		}
		priorHash = env.Metadata.Hash
		events = append(events, env)
		// Small delay to ensure timestamp monotonicity.
		time.Sleep(time.Millisecond)
	}
	return events
}

func TestValidateCoherence_ValidChain(t *testing.T) {
	// A properly constructed chain should pass all 3 validation layers.
	events := buildChain(t, "node1", 10)

	report := ValidateCoherence(events)
	if !report.Pass {
		t.Errorf("expected pass=true for valid chain, got false")
		for _, c := range report.Checks {
			if !c.Pass {
				t.Errorf("  failed check: %s — %s", c.Layer, c.Detail)
			}
		}
	}
	if len(report.Checks) != 3 {
		t.Errorf("expected 3 checks, got %d", len(report.Checks))
	}
}

func TestValidateCoherence_EmptyLedger(t *testing.T) {
	// An empty event list should pass validation.
	report := ValidateCoherence([]*EventEnvelope{})
	if !report.Pass {
		t.Error("empty ledger should pass validation")
	}
}

func TestValidateCoherence_SingleEvent(t *testing.T) {
	// A single event should pass validation.
	events := buildChain(t, "node1", 1)
	report := ValidateCoherence(events)
	if !report.Pass {
		t.Errorf("single event should pass, got false")
		for _, c := range report.Checks {
			if !c.Pass {
				t.Errorf("  failed: %s — %s", c.Layer, c.Detail)
			}
		}
	}
}

func TestValidateCoherence_BrokenHashChain(t *testing.T) {
	// Modifying a prior_hash should be detected by the hash chain check.
	events := buildChain(t, "node1", 5)

	// Break the chain: set event[2].prior_hash to garbage.
	events[2].HashedPayload.PriorHash = "0000000000000000000000000000000000000000000000000000000000000000"

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for broken hash chain")
	}

	// The hash_chain layer should fail.
	found := false
	for _, c := range report.Checks {
		if c.Layer == "hash_chain" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Error("hash_chain check should have failed")
	}
}

func TestValidateCoherence_TamperedPayload(t *testing.T) {
	// Changing the payload data without updating the hash should be detected.
	events := buildChain(t, "node1", 5)

	// Tamper with event[1]'s data but keep its hash unchanged.
	events[1].HashedPayload.Data = map[string]interface{}{"tampered": true}

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for tampered payload")
	}
}

func TestValidateCoherence_SequenceGap(t *testing.T) {
	// A gap in sequence numbers should be detected by temporal monotonicity.
	events := buildChain(t, "node1", 3)

	// Skip seq 2 -> 4 (instead of 2 -> 3).
	events[2].Metadata.Seq = 4

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for sequence gap")
	}

	found := false
	for _, c := range report.Checks {
		if c.Layer == "temporal" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Error("temporal check should have failed for sequence gap")
	}
}

func TestValidateCoherence_TimestampReversal(t *testing.T) {
	// A timestamp going backwards should be detected.
	events := buildChain(t, "node1", 3)

	// Make event[2] have a timestamp before event[1].
	events[2].HashedPayload.Timestamp = "2000-01-01T00:00:00Z"

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for timestamp reversal")
	}

	found := false
	for _, c := range report.Checks {
		if c.Layer == "temporal" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Error("temporal check should have failed for time reversal")
	}
}

func TestValidateCoherence_MissingType(t *testing.T) {
	// An event with empty type should fail schema validation.
	events := buildChain(t, "node1", 3)
	events[1].HashedPayload.Type = ""

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for missing type")
	}
	found := false
	for _, c := range report.Checks {
		if c.Layer == "schema" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Error("schema check should have failed for missing type")
	}
}

func TestValidateCoherence_MissingNodeID(t *testing.T) {
	events := buildChain(t, "node1", 2)
	events[0].HashedPayload.NodeID = ""

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for missing node_id")
	}
}

func TestValidateCoherence_MissingTimestamp(t *testing.T) {
	events := buildChain(t, "node1", 2)
	events[0].HashedPayload.Timestamp = ""

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for missing timestamp")
	}
}

func TestValidateCoherence_InvalidTimestamp(t *testing.T) {
	events := buildChain(t, "node1", 2)
	events[0].HashedPayload.Timestamp = "not-a-timestamp"

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for invalid timestamp")
	}
}

func TestValidateCoherence_MissingHash(t *testing.T) {
	events := buildChain(t, "node1", 2)
	events[0].Metadata.Hash = ""

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("expected pass=false for missing hash")
	}
}

// ---------------------------------------------------------------------------
// canonicalJSON edge cases
// ---------------------------------------------------------------------------

func TestCanonicalJSON_NestedObject(t *testing.T) {
	// Nested maps should also have sorted keys.
	payload := &EventPayload{
		Type:      "test",
		Timestamp: "2026-04-10T00:00:00Z",
		NodeID:    "node1",
		Data: map[string]interface{}{
			"outer": map[string]interface{}{
				"z": float64(1),
				"a": float64(2),
			},
		},
	}

	canonical, err := CanonicalizeEvent(payload)
	if err != nil {
		t.Fatalf("CanonicalizeEvent error: %v", err)
	}

	got := string(canonical)
	// The nested keys should be sorted: "a" before "z".
	expected := `{"data":{"outer":{"a":2,"z":1}},"node_id":"node1","timestamp":"2026-04-10T00:00:00Z","type":"test"}`
	if got != expected {
		t.Errorf("nested canonical JSON:\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestCanonicalJSON_Array(t *testing.T) {
	// Arrays should preserve order (not be sorted).
	payload := &EventPayload{
		Type:      "test",
		Timestamp: "2026-04-10T00:00:00Z",
		NodeID:    "node1",
		Data: map[string]interface{}{
			"items": []interface{}{"b", "a", "c"},
		},
	}

	canonical, err := CanonicalizeEvent(payload)
	if err != nil {
		t.Fatalf("CanonicalizeEvent error: %v", err)
	}

	got := string(canonical)
	// Arrays preserve insertion order.
	expected := `{"data":{"items":["b","a","c"]},"node_id":"node1","timestamp":"2026-04-10T00:00:00Z","type":"test"}`
	if got != expected {
		t.Errorf("array canonical JSON:\n  got:  %s\n  want: %s", got, expected)
	}
}

// helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
