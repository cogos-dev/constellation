// tls_test.go — Tests for trust scoring, peer registry, heartbeat signing,
// and identity conflict detection.
//
// Note: The constellation protocol does NOT use TLS certificates. Instead,
// it uses ECDSA-signed heartbeats for mutual authentication. This file
// tests those mechanisms, which serve the same purpose as mTLS in
// traditional systems.
//
// Covers: TrustLevel, PeerRegistry, ProcessHeartbeat, VerifyHeartbeat,
// identity conflict detection, EMA trust scoring.
package constellation

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Area 2: Trust Scoring — TrustLevel thresholds
// ---------------------------------------------------------------------------

func TestTrustLevel_Thresholds(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{1.0, "trusted"},
		{0.7, "trusted"},
		{0.71, "trusted"},
		{0.69, "pending"},
		{0.5, "pending"},
		{0.4, "pending"},
		{0.39, "suspect"},
		{0.2, "suspect"},
		{0.19, "rejected"},
		{0.0, "rejected"},
		{-0.1, "rejected"},
	}

	for _, tt := range tests {
		got := TrustLevel(tt.score)
		if got != tt.want {
			t.Errorf("TrustLevel(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// PeerRegistry operations
// ---------------------------------------------------------------------------

func TestNewPeerRegistry_Empty(t *testing.T) {
	pr := NewPeerRegistry()
	if pr == nil {
		t.Fatal("NewPeerRegistry() returned nil")
	}
	peers := pr.AllPeers()
	if len(peers) != 0 {
		t.Errorf("new registry has %d peers, want 0", len(peers))
	}
}

func TestPeerRegistry_AddPeer(t *testing.T) {
	pr := NewPeerRegistry()
	pr.AddPeer("localhost:8101")

	peer := pr.GetPeer("localhost:8101")
	if peer == nil {
		t.Fatal("GetPeer returned nil after AddPeer")
	}
	if peer.Trust != 0.5 {
		t.Errorf("initial trust = %v, want 0.5", peer.Trust)
	}
	if peer.Addr != "localhost:8101" {
		t.Errorf("addr = %q, want %q", peer.Addr, "localhost:8101")
	}
}

func TestPeerRegistry_AddPeer_Idempotent(t *testing.T) {
	// Adding the same peer twice should not create duplicates.
	pr := NewPeerRegistry()
	pr.AddPeer("localhost:8101")
	pr.AddPeer("localhost:8101")

	peers := pr.AllPeers()
	if len(peers) != 1 {
		t.Errorf("duplicate AddPeer created %d entries, want 1", len(peers))
	}
}

func TestPeerRegistry_GetPeer_NotFound(t *testing.T) {
	pr := NewPeerRegistry()
	peer := pr.GetPeer("nonexistent:9999")
	if peer != nil {
		t.Error("GetPeer should return nil for unknown address")
	}
}

func TestPeerRegistry_GetByID_NotFound(t *testing.T) {
	pr := NewPeerRegistry()
	peer := pr.GetByID("unknown-id")
	if peer != nil {
		t.Error("GetByID should return nil for unknown node ID")
	}
}

func TestPeerRegistry_AllPeers_MultipleEntries(t *testing.T) {
	pr := NewPeerRegistry()
	pr.AddPeer("host1:8101")
	pr.AddPeer("host2:8102")
	pr.AddPeer("host3:8103")

	peers := pr.AllPeers()
	if len(peers) != 3 {
		t.Errorf("AllPeers() returned %d entries, want 3", len(peers))
	}
}

// ---------------------------------------------------------------------------
// ProcessHeartbeat — trust EMA
// ---------------------------------------------------------------------------

func TestProcessHeartbeat_LearnIdentity(t *testing.T) {
	// First heartbeat from a peer should learn its identity.
	pr := NewPeerRegistry()
	pr.AddPeer("peer1:8100")

	id, _ := GenerateIdentity()
	hb := &Heartbeat{
		NodeID:   id.NodeID,
		Seq:      1,
		LastHash: "hash1",
		TreeHash: "tree1",
	}

	err := pr.ProcessHeartbeat("peer1:8100", hb, id.PublicKey)
	if err != nil {
		t.Fatalf("ProcessHeartbeat error: %v", err)
	}

	peer := pr.GetPeer("peer1:8100")
	if peer.NodeID != id.NodeID {
		t.Errorf("NodeID not learned: got %q, want %q", peer.NodeID, id.NodeID)
	}

	// Should also be findable by ID.
	byID := pr.GetByID(id.NodeID)
	if byID == nil {
		t.Fatal("GetByID returned nil after learning identity")
	}
}

func TestProcessHeartbeat_ConsistentSequence_TrustIncreases(t *testing.T) {
	// Consistent sequential heartbeats should increase trust toward 1.0.
	pr := NewPeerRegistry()
	pr.AddPeer("peer1:8100")

	id, _ := GenerateIdentity()

	// Send 10 consistent heartbeats.
	for seq := int64(1); seq <= 10; seq++ {
		hb := &Heartbeat{
			NodeID:   id.NodeID,
			Seq:      seq,
			LastHash: "hash",
			TreeHash: "tree",
		}
		if err := pr.ProcessHeartbeat("peer1:8100", hb, id.PublicKey); err != nil {
			t.Fatalf("ProcessHeartbeat(seq=%d) error: %v", seq, err)
		}
	}

	peer := pr.GetPeer("peer1:8100")
	if peer.Trust < TrustThresholdTrusted {
		t.Errorf("trust after 10 consistent heartbeats = %v, want >= %v", peer.Trust, TrustThresholdTrusted)
	}
	if TrustLevel(peer.Trust) != "trusted" {
		t.Errorf("trust level = %q, want %q", TrustLevel(peer.Trust), "trusted")
	}
}

func TestProcessHeartbeat_SequenceDrift_TrustDecreases(t *testing.T) {
	// A sequence gap should decrease trust.
	pr := NewPeerRegistry()
	pr.AddPeer("peer1:8100")

	id, _ := GenerateIdentity()

	// First heartbeat establishes seq=1.
	hb1 := &Heartbeat{NodeID: id.NodeID, Seq: 1}
	pr.ProcessHeartbeat("peer1:8100", hb1, id.PublicKey)

	// Skip to seq=5 (drift).
	hb2 := &Heartbeat{NodeID: id.NodeID, Seq: 5}
	pr.ProcessHeartbeat("peer1:8100", hb2, id.PublicKey)

	peer := pr.GetPeer("peer1:8100")
	if peer.DriftCount != 1 {
		t.Errorf("drift count = %d, want 1", peer.DriftCount)
	}
	// Trust should have decreased from the initial 0.5.
	// After first consistent hb: 0.8*0.5 + 0.2*1.0 = 0.6
	// After drift: 0.8*0.6 + 0.2*0.0 = 0.48
	if peer.Trust >= 0.6 {
		t.Errorf("trust after drift = %v, should have decreased from ~0.6", peer.Trust)
	}
}

func TestProcessHeartbeat_RejectedPeer_ReturnsError(t *testing.T) {
	// A rejected peer's heartbeats should be refused.
	pr := NewPeerRegistry()
	pr.AddPeer("peer1:8100")

	// Manually mark as rejected.
	peer := pr.GetPeer("peer1:8100")
	peer.Rejected = true

	id, _ := GenerateIdentity()
	hb := &Heartbeat{NodeID: id.NodeID, Seq: 1}
	err := pr.ProcessHeartbeat("peer1:8100", hb, id.PublicKey)
	if err == nil {
		t.Error("expected error for rejected peer, got nil")
	}
}

// ---------------------------------------------------------------------------
// Identity Conflict Detection
// ---------------------------------------------------------------------------

func TestProcessHeartbeat_IdentityConflict(t *testing.T) {
	// Two different addresses claiming the same NodeID within the conflict window
	// should be detected and both rejected.
	pr := NewPeerRegistry()
	pr.AddPeer("addr1:8100")
	pr.AddPeer("addr2:8200")

	id, _ := GenerateIdentity()

	// First address learns identity.
	hb1 := &Heartbeat{NodeID: id.NodeID, Seq: 1}
	err := pr.ProcessHeartbeat("addr1:8100", hb1, id.PublicKey)
	if err != nil {
		t.Fatalf("first heartbeat error: %v", err)
	}

	// Second address claims the same NodeID within the window.
	hb2 := &Heartbeat{NodeID: id.NodeID, Seq: 1}
	err = pr.ProcessHeartbeat("addr2:8200", hb2, id.PublicKey)
	if err == nil {
		t.Error("expected identity conflict error, got nil")
	}

	// Both peers should be rejected.
	peer1 := pr.GetPeer("addr1:8100")
	peer2 := pr.GetPeer("addr2:8200")

	if !peer1.Rejected {
		t.Error("original peer should be rejected after identity conflict")
	}
	if !peer2.Rejected {
		t.Error("conflicting peer should be rejected after identity conflict")
	}
	if peer1.Trust != 0 {
		t.Errorf("original peer trust = %v, want 0", peer1.Trust)
	}
	if peer2.Trust != 0 {
		t.Errorf("conflicting peer trust = %v, want 0", peer2.Trust)
	}
}

func TestProcessHeartbeat_DriftCount_Resets_OnConsistent(t *testing.T) {
	// After a drift, a subsequent consistent heartbeat should reset drift count.
	pr := NewPeerRegistry()
	pr.AddPeer("peer1:8100")

	id, _ := GenerateIdentity()

	// Seq 1.
	pr.ProcessHeartbeat("peer1:8100", &Heartbeat{NodeID: id.NodeID, Seq: 1}, id.PublicKey)

	// Drift: seq 5.
	pr.ProcessHeartbeat("peer1:8100", &Heartbeat{NodeID: id.NodeID, Seq: 5}, id.PublicKey)
	peer := pr.GetPeer("peer1:8100")
	if peer.DriftCount != 1 {
		t.Errorf("drift count after gap = %d, want 1", peer.DriftCount)
	}

	// Consistent: seq 6.
	pr.ProcessHeartbeat("peer1:8100", &Heartbeat{NodeID: id.NodeID, Seq: 6}, id.PublicKey)
	if peer.DriftCount != 0 {
		t.Errorf("drift count after consistent = %d, want 0", peer.DriftCount)
	}
}

// ---------------------------------------------------------------------------
// Heartbeat signing/verification roundtrip
// ---------------------------------------------------------------------------

func TestHeartbeatSignAndVerify_Roundtrip(t *testing.T) {
	// Build a heartbeat the same way the heartbeat runner does, then verify it.
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity error: %v", err)
	}

	pubDER, err := id.MarshalPublicKey()
	if err != nil {
		t.Fatalf("MarshalPublicKey error: %v", err)
	}

	hb := &Heartbeat{
		NodeID:    id.NodeID,
		TreeHash:  "treehash123",
		Seq:       42,
		LastHash:  "lasthash456",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		PublicKey: base64.StdEncoding.EncodeToString(pubDER),
	}

	// Sign.
	payload, err := json.Marshal(map[string]any{
		"node_id":   hb.NodeID,
		"tree_hash": hb.TreeHash,
		"seq":       hb.Seq,
		"last_hash": hb.LastHash,
		"timestamp": hb.Timestamp,
	})
	if err != nil {
		t.Fatalf("marshal payload error: %v", err)
	}

	sig, err := id.Sign(payload)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	hb.Signature = base64.StdEncoding.EncodeToString(sig)

	// Verify.
	valid, pubKey, err := VerifyHeartbeat(hb)
	if err != nil {
		t.Fatalf("VerifyHeartbeat error: %v", err)
	}
	if !valid {
		t.Error("VerifyHeartbeat returned false for a correctly signed heartbeat")
	}
	if pubKey == nil {
		t.Error("VerifyHeartbeat returned nil public key")
	}
}

func TestVerifyHeartbeat_InvalidSignature(t *testing.T) {
	// A heartbeat with a tampered signature should fail verification.
	id, _ := GenerateIdentity()
	pubDER, _ := id.MarshalPublicKey()

	hb := &Heartbeat{
		NodeID:    id.NodeID,
		TreeHash:  "tree",
		Seq:       1,
		LastHash:  "hash",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		PublicKey: base64.StdEncoding.EncodeToString(pubDER),
	}

	// Sign correctly.
	payload, _ := json.Marshal(map[string]any{
		"node_id":   hb.NodeID,
		"tree_hash": hb.TreeHash,
		"seq":       hb.Seq,
		"last_hash": hb.LastHash,
		"timestamp": hb.Timestamp,
	})
	sig, _ := id.Sign(payload)

	// Tamper with signature.
	sig[0] ^= 0xFF
	hb.Signature = base64.StdEncoding.EncodeToString(sig)

	valid, _, err := VerifyHeartbeat(hb)
	if err != nil {
		// Some tampered signatures may cause parse errors, which is also acceptable.
		return
	}
	if valid {
		t.Error("VerifyHeartbeat returned true for tampered signature")
	}
}

func TestVerifyHeartbeat_NodeIDMismatch(t *testing.T) {
	// If the NodeID in the heartbeat doesn't match the public key, reject it.
	id, _ := GenerateIdentity()
	pubDER, _ := id.MarshalPublicKey()

	hb := &Heartbeat{
		NodeID:    "wrong-node-id-not-matching-key",
		TreeHash:  "tree",
		Seq:       1,
		LastHash:  "hash",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		PublicKey: base64.StdEncoding.EncodeToString(pubDER),
	}

	// Sign with valid key but wrong NodeID.
	payload, _ := json.Marshal(map[string]any{
		"node_id":   hb.NodeID,
		"tree_hash": hb.TreeHash,
		"seq":       hb.Seq,
		"last_hash": hb.LastHash,
		"timestamp": hb.Timestamp,
	})
	sig, _ := id.Sign(payload)
	hb.Signature = base64.StdEncoding.EncodeToString(sig)

	_, _, err := VerifyHeartbeat(hb)
	if err == nil {
		t.Error("expected error for NodeID mismatch, got nil")
	}
}

func TestVerifyHeartbeat_InvalidPublicKeyBase64(t *testing.T) {
	hb := &Heartbeat{
		NodeID:    "somenode",
		PublicKey: "not-valid-base64!!!",
		Signature: "ditto",
	}

	_, _, err := VerifyHeartbeat(hb)
	if err == nil {
		t.Error("expected error for invalid base64 public key")
	}
}

func TestVerifyHeartbeat_InvalidPublicKeyDER(t *testing.T) {
	hb := &Heartbeat{
		NodeID:    "somenode",
		PublicKey: base64.StdEncoding.EncodeToString([]byte("garbage-not-der")),
		Signature: base64.StdEncoding.EncodeToString([]byte("fakesig")),
	}

	_, _, err := VerifyHeartbeat(hb)
	if err == nil {
		t.Error("expected error for invalid DER public key")
	}
}

// ---------------------------------------------------------------------------
// PeerSummary
// ---------------------------------------------------------------------------

func TestPeerRegistry_Summarize(t *testing.T) {
	pr := NewPeerRegistry()
	pr.AddPeer("host1:8100")

	id, _ := GenerateIdentity()
	hb := &Heartbeat{NodeID: id.NodeID, Seq: 1}
	pr.ProcessHeartbeat("host1:8100", hb, id.PublicKey)

	summaries := pr.Summarize()
	if len(summaries) != 1 {
		t.Fatalf("Summarize() returned %d entries, want 1", len(summaries))
	}

	s := summaries[0]
	if s.Addr != "host1:8100" {
		t.Errorf("Addr = %q, want %q", s.Addr, "host1:8100")
	}
	if s.Seq != 1 {
		t.Errorf("Seq = %d, want 1", s.Seq)
	}
	if s.TrustLevel == "" {
		t.Error("TrustLevel should not be empty")
	}
	if s.NodeID == "" {
		t.Error("NodeID should not be empty in summary")
	}
}

// ---------------------------------------------------------------------------
// EMA trust math
// ---------------------------------------------------------------------------

func TestEMATrustMath_ConsistentConvergesToOne(t *testing.T) {
	// After many consistent heartbeats, trust should approach 1.0.
	trust := 0.5
	for i := 0; i < 50; i++ {
		trust = EMADecay*trust + (1-EMADecay)*1.0
	}
	if trust < 0.99 {
		t.Errorf("trust after 50 consistent cycles = %v, want > 0.99", trust)
	}
}

func TestEMATrustMath_InconsistentConvergesToZero(t *testing.T) {
	// After many inconsistent heartbeats, trust should approach 0.0.
	trust := 0.5
	for i := 0; i < 50; i++ {
		trust = EMADecay*trust + (1-EMADecay)*0.0
	}
	if trust > 0.01 {
		t.Errorf("trust after 50 inconsistent cycles = %v, want < 0.01", trust)
	}
}

// ---------------------------------------------------------------------------
// identityFromPubKey (helper used in VerifyHeartbeat)
// ---------------------------------------------------------------------------

func TestIdentityFromPubKey_MatchesNodeID(t *testing.T) {
	// The NodeID derived from a public key should match the identity's NodeID.
	id, _ := GenerateIdentity()

	pubDER, _ := x509.MarshalPKIXPublicKey(id.PublicKey)
	recovered, _ := PublicKeyFromDER(pubDER)

	derivedID, err := identityFromPubKey(recovered)
	if err != nil {
		t.Fatalf("identityFromPubKey error: %v", err)
	}

	if derivedID != id.NodeID {
		t.Errorf("derived ID = %s, want %s", derivedID, id.NodeID)
	}
}
