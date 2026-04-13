// heartbeat.go — Background heartbeat ticker and peer communication.
//
// Every 5 seconds: generate a simulated event, append to ledger, commit
// to git, sign the state snapshot, POST to all known peers.
package constellation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Heartbeat is the signed state snapshot sent to peers.
type Heartbeat struct {
	NodeID    string `json:"node_id"`
	ListenAddr string `json:"listen_addr"` // sender's listening address
	TreeHash  string `json:"tree_hash"`
	Seq       int64  `json:"seq"`
	LastHash  string `json:"last_hash"`
	Timestamp string `json:"timestamp"`
	PublicKey string `json:"public_key"` // base64-encoded DER
	Signature string `json:"signature"`  // base64-encoded ASN.1
}

// HeartbeatRunner manages the background heartbeat loop.
type HeartbeatRunner struct {
	node     *Node
	interval time.Duration
	stop     chan struct{}
	wg       sync.WaitGroup
}

// NewHeartbeatRunner creates a heartbeat runner.
func NewHeartbeatRunner(node *Node, interval time.Duration) *HeartbeatRunner {
	return &HeartbeatRunner{
		node:     node,
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Start begins the heartbeat loop.
func (hr *HeartbeatRunner) Start() {
	hr.wg.Add(1)
	go hr.run()
}

// Stop halts the heartbeat loop.
func (hr *HeartbeatRunner) Stop() {
	close(hr.stop)
	hr.wg.Wait()
}

func (hr *HeartbeatRunner) run() {
	defer hr.wg.Done()

	// Small random jitter so nodes don't heartbeat in lockstep.
	jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
	time.Sleep(jitter)

	ticker := time.NewTicker(hr.interval)
	defer ticker.Stop()

	for {
		select {
		case <-hr.stop:
			return
		case <-ticker.C:
			hr.tick()
		}
	}
}

func (hr *HeartbeatRunner) tick() {
	node := hr.node

	// Generate a simulated event.
	err := node.AppendEvent("heartbeat", map[string]any{
		"cycle": node.seq + 1,
	})
	if err != nil {
		log.Printf("[%s] Failed to append heartbeat event: %v", node.Name, err)
		return
	}

	// Build heartbeat.
	state, err := node.CurrentState()
	if err != nil {
		log.Printf("[%s] Failed to get state: %v", node.Name, err)
		return
	}

	pubDER, err := node.Identity.MarshalPublicKey()
	if err != nil {
		log.Printf("[%s] Failed to marshal pubkey: %v", node.Name, err)
		return
	}

	hb := &Heartbeat{
		NodeID:     state.NodeID,
		ListenAddr: node.ListenAddr(),
		TreeHash:   state.TreeHash,
		Seq:        state.Seq,
		LastHash:   state.LastHash,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		PublicKey:  base64.StdEncoding.EncodeToString(pubDER),
	}

	// Sign the heartbeat payload.
	payload, err := json.Marshal(map[string]any{
		"node_id":   hb.NodeID,
		"tree_hash": hb.TreeHash,
		"seq":       hb.Seq,
		"last_hash": hb.LastHash,
		"timestamp": hb.Timestamp,
	})
	if err != nil {
		log.Printf("[%s] Failed to marshal heartbeat payload: %v", node.Name, err)
		return
	}

	sig, err := node.Identity.Sign(payload)
	if err != nil {
		log.Printf("[%s] Failed to sign heartbeat: %v", node.Name, err)
		return
	}
	hb.Signature = base64.StdEncoding.EncodeToString(sig)

	// Broadcast to all peers.
	for _, peer := range node.Peers.AllPeers() {
		if peer.Rejected {
			continue
		}
		go sendHeartbeat(node.Name, peer.Addr, hb)
	}
}

func sendHeartbeat(nodeName, addr string, hb *Heartbeat) {
	data, err := json.Marshal(hb)
	if err != nil {
		return
	}

	url := fmt.Sprintf("http://%s/heartbeat", addr)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("[%s] Heartbeat to %s failed: %v", nodeName, addr, err)
		return
	}
	_ = resp.Body.Close()
}

func sendJoinRequest(node *Node, addr string) error {
	pubDER, err := node.Identity.MarshalPublicKey()
	if err != nil {
		return err
	}

	req := map[string]any{
		"node_id":    node.Identity.NodeID,
		"name":       node.Name,
		"addr":       node.ListenAddr(),
		"public_key": base64.StdEncoding.EncodeToString(pubDER),
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("http://%s/join", addr)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("join request returned %d", resp.StatusCode)
	}

	// Parse peer list from response.
	var result struct {
		Peers []string `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil // Join succeeded even if response parsing fails
	}

	// Add returned peers.
	for _, p := range result.Peers {
		node.Peers.AddPeer(p)
	}

	return nil
}

// VerifyHeartbeat checks the ECDSA signature on a heartbeat.
func VerifyHeartbeat(hb *Heartbeat) (bool, *ecdsa.PublicKey, error) {
	pubDER, err := base64.StdEncoding.DecodeString(hb.PublicKey)
	if err != nil {
		return false, nil, fmt.Errorf("decode public key: %w", err)
	}

	pubKey, err := PublicKeyFromDER(pubDER)
	if err != nil {
		return false, nil, fmt.Errorf("parse public key: %w", err)
	}

	// Verify NodeID matches public key.
	derivedID, err := identityFromPubKey(pubKey)
	if err != nil {
		return false, nil, fmt.Errorf("derive node id: %w", err)
	}
	if derivedID != hb.NodeID {
		return false, nil, fmt.Errorf("NodeID mismatch: heartbeat says %s, key derives %s",
			FormatNodeID(hb.NodeID), FormatNodeID(derivedID))
	}

	sig, err := base64.StdEncoding.DecodeString(hb.Signature)
	if err != nil {
		return false, nil, fmt.Errorf("decode signature: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"node_id":   hb.NodeID,
		"tree_hash": hb.TreeHash,
		"seq":       hb.Seq,
		"last_hash": hb.LastHash,
		"timestamp": hb.Timestamp,
	})
	if err != nil {
		return false, nil, fmt.Errorf("marshal payload: %w", err)
	}

	return Verify(pubKey, payload, sig), pubKey, nil
}

func identityFromPubKey(pubKey *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(der)
	return hex.EncodeToString(hash[:]), nil
}
