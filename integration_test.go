// integration_test.go — Integration tests for multi-node constellation operations.
//
// These tests exercise the full stack: identity, git store, ledger, heartbeat,
// HTTP protocol, and peer trust scoring. They use real git repositories in
// temp directories and real HTTP servers on ephemeral ports.
//
// Build tag: Run with `go test -tags integration` to include these tests.
// Without the tag, these tests are skipped.

//go:build integration

package constellation

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// startTestNode creates and starts a node on a random port. Returns the node
// and a cleanup function. The node runs in a goroutine.
func startTestNode(t *testing.T, name string, port int, peers []string) (*Node, func()) {
	t.Helper()

	dataDir := filepath.Join(t.TempDir(), name)
	node, err := NewNode(name, port, dataDir)
	if err != nil {
		t.Fatalf("NewNode(%s) error: %v", name, err)
	}
	node.Hostname = "localhost"

	go func() {
		if err := node.Start(peers); err != nil {
			// Ignore "server closed" errors during shutdown.
			if err != http.ErrServerClosed {
				// Use stdlib log here (not t.Logf) to avoid a logging race
				// if this goroutine outlives the test body.
				log.Printf("[%s] Start error: %v", name, err)
			}
		}
	}()

	// Wait for the server to be ready.
	ready := false
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/state", port))
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
	}
	if !ready {
		t.Fatalf("node %s did not start within 2s", name)
	}

	cleanup := func() {
		node.Stop()
	}

	return node, cleanup
}

// waitForTrust polls a node's /peers endpoint until the given peer count
// reaches the specified trust level, or times out.
func waitForTrust(t *testing.T, port int, minTrusted int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/peers", port))
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		var peers []PeerSummary
		json.NewDecoder(resp.Body).Decode(&peers)
		resp.Body.Close()

		trustedCount := 0
		for _, p := range peers {
			if p.Trust >= TrustThresholdTrusted {
				trustedCount++
			}
		}
		if trustedCount >= minTrusted {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// ---------------------------------------------------------------------------
// Area 5: Integration — GitStore operations (no network, but uses real git)
// ---------------------------------------------------------------------------

func TestGitStore_AppendAndRecover(t *testing.T) {
	// Appending events to a GitStore and reading them back should work.
	dir := filepath.Join(t.TempDir(), "repo")
	store, err := NewGitStore(dir)
	if err != nil {
		t.Fatalf("NewGitStore error: %v", err)
	}

	// Build a 5-event chain.
	priorHash := ""
	for seq := int64(1); seq <= 5; seq++ {
		env, err := NewEvent("node1", "test", seq, priorHash, map[string]interface{}{
			"seq": float64(seq),
		})
		if err != nil {
			t.Fatalf("NewEvent(%d) error: %v", seq, err)
		}
		if err := store.AppendEvent(env); err != nil {
			t.Fatalf("AppendEvent(%d) error: %v", seq, err)
		}
		priorHash = env.Metadata.Hash
	}

	// Read back all events.
	events, err := store.ReadEventRange(1, 5)
	if err != nil {
		t.Fatalf("ReadEventRange error: %v", err)
	}
	if len(events) != 5 {
		t.Errorf("got %d events, want 5", len(events))
	}

	// Verify chain integrity.
	report := ValidateCoherence(events)
	if !report.Pass {
		t.Errorf("coherence check failed on freshly written chain")
		for _, c := range report.Checks {
			if !c.Pass {
				t.Errorf("  %s: %s", c.Layer, c.Detail)
			}
		}
	}

	// Verify tree hash is available.
	treeHash, err := store.TreeHash()
	if err != nil {
		t.Fatalf("TreeHash error: %v", err)
	}
	if treeHash == "" {
		t.Error("TreeHash should not be empty after appending events")
	}
}

func TestGitStore_LastEvent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	store, err := NewGitStore(dir)
	if err != nil {
		t.Fatalf("NewGitStore error: %v", err)
	}

	// Empty store should return nil.
	last, err := store.LastEvent()
	if err != nil {
		t.Fatalf("LastEvent (empty) error: %v", err)
	}
	if last != nil {
		t.Error("LastEvent on empty store should return nil")
	}

	// Append 3 events.
	priorHash := ""
	for seq := int64(1); seq <= 3; seq++ {
		env, err := NewEvent("node1", "test", seq, priorHash, nil)
		if err != nil {
			t.Fatalf("NewEvent(%d) error: %v", seq, err)
		}
		if err := store.AppendEvent(env); err != nil {
			t.Fatalf("AppendEvent(%d) error: %v", seq, err)
		}
		priorHash = env.Metadata.Hash
	}

	last, err = store.LastEvent()
	if err != nil {
		t.Fatalf("LastEvent error: %v", err)
	}
	if last == nil {
		t.Fatal("LastEvent returned nil after appending events")
	}
	if last.Metadata.Seq != 3 {
		t.Errorf("LastEvent seq = %d, want 3", last.Metadata.Seq)
	}
}

func TestGitStore_CorruptEvent_DetectedByCoherence(t *testing.T) {
	// CorruptEvent should modify the data such that ValidateCoherence fails.
	dir := filepath.Join(t.TempDir(), "repo")
	store, err := NewGitStore(dir)
	if err != nil {
		t.Fatalf("NewGitStore error: %v", err)
	}

	// Build chain.
	priorHash := ""
	for seq := int64(1); seq <= 5; seq++ {
		env, err := NewEvent("node1", "test", seq, priorHash, map[string]interface{}{
			"cycle": float64(seq),
		})
		if err != nil {
			t.Fatalf("NewEvent(%d) error: %v", seq, err)
		}
		if err := store.AppendEvent(env); err != nil {
			t.Fatalf("AppendEvent(%d) error: %v", seq, err)
		}
		priorHash = env.Metadata.Hash
	}

	// Corrupt event 3.
	if err := store.CorruptEvent(3); err != nil {
		t.Fatalf("CorruptEvent error: %v", err)
	}

	// Re-read and validate.
	events, err := store.ReadEventRange(1, 5)
	if err != nil {
		t.Fatalf("ReadEventRange error: %v", err)
	}

	report := ValidateCoherence(events)
	if report.Pass {
		t.Error("coherence should fail after corruption, but it passed")
	}

	// The hash_chain check should specifically fail.
	chainFailed := false
	for _, c := range report.Checks {
		if c.Layer == "hash_chain" && !c.Pass {
			chainFailed = true
			t.Logf("detected: %s", c.Detail)
		}
	}
	if !chainFailed {
		t.Error("hash_chain check should have failed after corruption")
	}
}

func TestGitStore_ReadEventRange_Subset(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	store, _ := NewGitStore(dir)

	priorHash := ""
	for seq := int64(1); seq <= 10; seq++ {
		env, _ := NewEvent("node1", "test", seq, priorHash, nil)
		store.AppendEvent(env)
		priorHash = env.Metadata.Hash
	}

	// Read only events 3-7.
	events, err := store.ReadEventRange(3, 7)
	if err != nil {
		t.Fatalf("ReadEventRange(3,7) error: %v", err)
	}
	if len(events) != 5 {
		t.Errorf("got %d events, want 5", len(events))
	}
	if events[0].Metadata.Seq != 3 {
		t.Errorf("first event seq = %d, want 3", events[0].Metadata.Seq)
	}
	if events[4].Metadata.Seq != 7 {
		t.Errorf("last event seq = %d, want 7", events[4].Metadata.Seq)
	}
}

func TestGitStore_CommitHash_Changes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	store, _ := NewGitStore(dir)

	env1, _ := NewEvent("node1", "test", 1, "", nil)
	store.AppendEvent(env1)

	hash1, err := store.CommitHash()
	if err != nil {
		t.Fatalf("CommitHash error: %v", err)
	}
	if hash1 == "" {
		t.Fatal("CommitHash should not be empty after first commit")
	}

	env2, _ := NewEvent("node1", "test", 2, env1.Metadata.Hash, nil)
	store.AppendEvent(env2)

	hash2, err := store.CommitHash()
	if err != nil {
		t.Fatalf("CommitHash error: %v", err)
	}
	if hash2 == hash1 {
		t.Error("CommitHash should change after a new commit")
	}
}

// ---------------------------------------------------------------------------
// Area 5: Integration — Node lifecycle
// ---------------------------------------------------------------------------

func TestNode_CreateAndAppendEvent(t *testing.T) {
	// Create a node, append events, verify the ledger is coherent.
	dataDir := filepath.Join(t.TempDir(), "test-node")
	node, err := NewNode("test-node", 0, dataDir)
	if err != nil {
		t.Fatalf("NewNode error: %v", err)
	}

	if node.Identity == nil {
		t.Fatal("node.Identity is nil")
	}
	if node.Identity.NodeID == "" {
		t.Fatal("node.Identity.NodeID is empty")
	}

	// Append 3 events.
	for i := 0; i < 3; i++ {
		if err := node.AppendEvent("test", map[string]any{"i": i}); err != nil {
			t.Fatalf("AppendEvent(%d) error: %v", i, err)
		}
	}

	// Self-check.
	report, err := node.SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck error: %v", err)
	}
	if !report.Pass {
		t.Error("SelfCheck failed on freshly created node")
		for _, c := range report.Checks {
			if !c.Pass {
				t.Errorf("  %s: %s", c.Layer, c.Detail)
			}
		}
	}
}

func TestNode_PersistsIdentity(t *testing.T) {
	// Creating a node twice in the same directory should load the same identity.
	dataDir := filepath.Join(t.TempDir(), "persistent")

	node1, err := NewNode("persistent", 0, dataDir)
	if err != nil {
		t.Fatalf("first NewNode error: %v", err)
	}
	id1 := node1.Identity.NodeID

	node2, err := NewNode("persistent", 0, dataDir)
	if err != nil {
		t.Fatalf("second NewNode error: %v", err)
	}
	id2 := node2.Identity.NodeID

	if id1 != id2 {
		t.Errorf("identity not persisted: first=%s, second=%s", id1, id2)
	}
}

func TestNode_RecoverSequence(t *testing.T) {
	// A node should recover its sequence number from existing events on restart.
	dataDir := filepath.Join(t.TempDir(), "recover")

	node1, err := NewNode("recover", 0, dataDir)
	if err != nil {
		t.Fatalf("NewNode error: %v", err)
	}

	for i := 0; i < 5; i++ {
		node1.AppendEvent("test", nil)
	}

	// Create a new node instance at the same data dir.
	node2, err := NewNode("recover", 0, dataDir)
	if err != nil {
		t.Fatalf("second NewNode error: %v", err)
	}

	state, err := node2.CurrentState()
	if err != nil {
		t.Fatalf("CurrentState error: %v", err)
	}
	if state.Seq != 5 {
		t.Errorf("recovered seq = %d, want 5", state.Seq)
	}
}

// ---------------------------------------------------------------------------
// Area 5: Integration — Two-node sync (HTTP-based)
// ---------------------------------------------------------------------------

func TestTwoNodes_TrustConvergence(t *testing.T) {
	// Start two nodes, verify they discover each other and converge to trusted.
	// This test requires real HTTP servers and takes ~30s to converge.
	if testing.Short() {
		t.Skip("skipping multi-node test in short mode")
	}

	nodeA, cleanupA := startTestNode(t, "alpha", 18201, nil)
	defer cleanupA()

	_, cleanupB := startTestNode(t, "beta", 18202, []string{
		fmt.Sprintf("localhost:%d", 18201),
	})
	defer cleanupB()

	// Also tell alpha about beta.
	nodeA.Peers.AddPeer(fmt.Sprintf("localhost:%d", 18202))

	// Wait for trust to converge (up to 60s).
	if !waitForTrust(t, 18201, 1, 60*time.Second) {
		t.Error("alpha did not reach trusted status with beta within 60s")
	}
	if !waitForTrust(t, 18202, 1, 60*time.Second) {
		t.Error("beta did not reach trusted status with alpha within 60s")
	}
}

func TestTwoNodes_HealthEndpoint(t *testing.T) {
	// Start a node and verify its /health endpoint returns pass=true.
	if testing.Short() {
		t.Skip("skipping HTTP test in short mode")
	}

	_, cleanup := startTestNode(t, "health-test", 18210, nil)
	defer cleanup()

	// Give it a moment to generate at least one event.
	time.Sleep(6 * time.Second)

	resp, err := http.Get("http://localhost:18210/health")
	if err != nil {
		t.Fatalf("GET /health error: %v", err)
	}
	defer resp.Body.Close()

	var report CoherenceReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("decode health response: %v", err)
	}

	if !report.Pass {
		t.Error("/health returned pass=false for a fresh node")
		for _, c := range report.Checks {
			if !c.Pass {
				t.Errorf("  %s: %s", c.Layer, c.Detail)
			}
		}
	}
}

func TestTwoNodes_StateEndpoint(t *testing.T) {
	// /state should return the node's identity and current sequence.
	if testing.Short() {
		t.Skip("skipping HTTP test in short mode")
	}

	node, cleanup := startTestNode(t, "state-test", 18211, nil)
	defer cleanup()

	time.Sleep(6 * time.Second)

	resp, err := http.Get("http://localhost:18211/state")
	if err != nil {
		t.Fatalf("GET /state error: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		State NodeState     `json:"state"`
		Peers []PeerSummary `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode state response: %v", err)
	}

	if result.State.NodeID != node.Identity.NodeID {
		t.Errorf("state NodeID = %s, want %s", result.State.NodeID, node.Identity.NodeID)
	}
	if result.State.Seq < 1 {
		t.Errorf("state Seq = %d, want >= 1", result.State.Seq)
	}
}

// ---------------------------------------------------------------------------
// Area 5: Integration — Tamper detection via /health after CorruptEvent
// ---------------------------------------------------------------------------

func TestNode_TamperDetectedByHealthEndpoint(t *testing.T) {
	// Corrupt an event in a running node's store, then check /health.
	if testing.Short() {
		t.Skip("skipping HTTP test in short mode")
	}

	node, cleanup := startTestNode(t, "tamper-test", 18212, nil)
	defer cleanup()

	// Wait for a few heartbeat events.
	time.Sleep(12 * time.Second)

	// Corrupt event 1.
	if err := node.Store.CorruptEvent(1); err != nil {
		t.Fatalf("CorruptEvent error: %v", err)
	}

	// /health should now report failure.
	resp, err := http.Get("http://localhost:18212/health")
	if err != nil {
		t.Fatalf("GET /health error: %v", err)
	}
	defer resp.Body.Close()

	// /health intentionally returns 503 when report.Pass == false
	// (protocol.go:200-203 — HTTP-native tamper signal, body still valid JSON).
	// Accept 200 (healthy) or 503 (tamper). Fail on anything else, which would
	// indicate a broken pipeline rather than a decisional output.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/health returned status %d, want 200 or 503", resp.StatusCode)
	}

	var report CoherenceReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("decode /health body: %v", err)
	}

	// We want pass=false because tamper detection fired — confirmed by the
	// explicit status/decode checks above (not because of a broken pipeline).
	if report.Pass {
		t.Error("/health should return pass=false after corruption")
	}
}

// ---------------------------------------------------------------------------
// Area 5: Integration — GitStore reopen (persistence across restarts)
// ---------------------------------------------------------------------------

func TestGitStore_ReopenPreservesEvents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reopen")

	// First session: write events.
	store1, err := NewGitStore(dir)
	if err != nil {
		t.Fatalf("first NewGitStore error: %v", err)
	}
	priorHash := ""
	for seq := int64(1); seq <= 3; seq++ {
		env, _ := NewEvent("node1", "test", seq, priorHash, nil)
		store1.AppendEvent(env)
		priorHash = env.Metadata.Hash
	}
	treeHash1, _ := store1.TreeHash()

	// Second session: reopen same directory.
	store2, err := NewGitStore(dir)
	if err != nil {
		t.Fatalf("second NewGitStore error: %v", err)
	}

	events, err := store2.ReadEventRange(1, 3)
	if err != nil {
		t.Fatalf("ReadEventRange error: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("got %d events after reopen, want 3", len(events))
	}

	treeHash2, _ := store2.TreeHash()
	if treeHash1 != treeHash2 {
		t.Errorf("tree hash changed after reopen: %s vs %s", treeHash1, treeHash2)
	}
}

// ---------------------------------------------------------------------------
// Area 3: BEP Protocol / HTTP protocol tests
// ---------------------------------------------------------------------------

func TestProtocol_JoinEndpoint(t *testing.T) {
	// POST /join should accept a new node and return a peer list.
	if testing.Short() {
		t.Skip("skipping HTTP test in short mode")
	}

	_, cleanup := startTestNode(t, "join-host", 18220, nil)
	defer cleanup()

	// Build a join request.
	id, _ := GenerateIdentity()
	reqBody := fmt.Sprintf(`{"node_id":"%s","name":"joiner","addr":"localhost:18221"}`, id.NodeID)

	resp, err := http.Post(
		"http://localhost:18220/join",
		"application/json",
		strings.NewReader(reqBody),
	)
	if err != nil {
		t.Fatalf("POST /join error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /join status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		Status string   `json:"status"`
		Peers  []string `json:"peers"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Status != "accepted" {
		t.Errorf("join status = %q, want %q", result.Status, "accepted")
	}
}

func TestProtocol_PeersEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping HTTP test in short mode")
	}

	_, cleanup := startTestNode(t, "peers-test", 18221, nil)
	defer cleanup()

	resp, err := http.Get("http://localhost:18221/peers")
	if err != nil {
		t.Fatalf("GET /peers error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /peers status = %d, want 200", resp.StatusCode)
	}

	var peers []PeerSummary
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatalf("decode /peers body: %v", err)
	}
	// A fresh node with no configured peers should return an empty list.
	if len(peers) != 0 {
		t.Errorf("expected empty peers on fresh node, got %d", len(peers))
	}
}

func TestProtocol_MethodNotAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping HTTP test in short mode")
	}

	_, cleanup := startTestNode(t, "method-test", 18222, nil)
	defer cleanup()

	// GET to a POST-only endpoint should return 405.
	resp, err := http.Get("http://localhost:18222/heartbeat")
	if err != nil {
		t.Fatalf("GET /heartbeat error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /heartbeat status = %d, want 405", resp.StatusCode)
	}
}

// Note: uses strings.NewReader directly for POST bodies — no wrapper needed.
