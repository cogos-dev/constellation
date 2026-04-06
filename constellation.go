// constellation.go — Trust scoring and identity conflict detection.
//
// Trust is tracked per-peer via exponential moving average (EMA) of
// heartbeat consistency. Thresholds: trusted >= 0.7, pending >= 0.4,
// suspect >= 0.2, rejected < 0.2.
package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"sync"
	"time"
)

// Trust thresholds.
const (
	TrustThresholdTrusted  = 0.7
	TrustThresholdPending  = 0.4
	TrustThresholdSuspect  = 0.2
	EMADecay               = 0.8
	IdentityConflictWindow = 30 * time.Second
	MaxDriftBeforeChallenge = 2
)

// TrustLevel returns a human-readable trust label.
func TrustLevel(score float64) string {
	switch {
	case score >= TrustThresholdTrusted:
		return "trusted"
	case score >= TrustThresholdPending:
		return "pending"
	case score >= TrustThresholdSuspect:
		return "suspect"
	default:
		return "rejected"
	}
}

// PeerState tracks a remote peer's last known state and trust.
type PeerState struct {
	NodeID     string         `json:"node_id"`
	Addr       string         `json:"addr"`
	PublicKey  *ecdsa.PublicKey `json:"-"`
	PublicDER  []byte         `json:"public_key_der,omitempty"`
	LastSeq    int64          `json:"last_seq"`
	LastHash   string         `json:"last_hash"`
	TreeHash   string         `json:"tree_hash"`
	Trust      float64        `json:"trust"`
	DriftCount int            `json:"drift_count"`
	LastSeen   time.Time      `json:"last_seen"`
	Rejected   bool           `json:"rejected"`
}

// PeerRegistry manages the set of known peers.
type PeerRegistry struct {
	mu    sync.RWMutex
	peers map[string]*PeerState // keyed by addr
	byID  map[string]*PeerState // keyed by node_id
}

// NewPeerRegistry creates an empty registry.
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{
		peers: make(map[string]*PeerState),
		byID:  make(map[string]*PeerState),
	}
}

// AddPeer registers a peer address (identity learned on first heartbeat).
func (pr *PeerRegistry) AddPeer(addr string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if _, exists := pr.peers[addr]; !exists {
		pr.peers[addr] = &PeerState{
			Addr:  addr,
			Trust: 0.5, // start neutral
		}
	}
}

// GetPeer returns the state for a peer address.
func (pr *PeerRegistry) GetPeer(addr string) *PeerState {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.peers[addr]
}

// GetByID returns the state for a node ID.
func (pr *PeerRegistry) GetByID(nodeID string) *PeerState {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.byID[nodeID]
}

// AllPeers returns all peer states.
func (pr *PeerRegistry) AllPeers() []*PeerState {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	result := make([]*PeerState, 0, len(pr.peers))
	for _, p := range pr.peers {
		result = append(result, p)
	}
	return result
}

// ProcessHeartbeat updates peer state based on a received heartbeat.
// Returns an error if an identity conflict is detected.
func (pr *PeerRegistry) ProcessHeartbeat(addr string, hb *Heartbeat, pubKey *ecdsa.PublicKey) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	peer, exists := pr.peers[addr]
	if !exists {
		peer = &PeerState{Addr: addr, Trust: 0.5}
		pr.peers[addr] = peer
	}

	if peer.Rejected {
		return fmt.Errorf("peer %s is rejected", addr)
	}

	// Identity conflict detection: same NodeID from different address with divergent state.
	if existing, ok := pr.byID[hb.NodeID]; ok && existing.Addr != addr {
		if time.Since(existing.LastSeen) < IdentityConflictWindow {
			// Two different addresses claiming the same NodeID within the window.
			log.Printf("[CONFLICT] NodeID %s claimed by both %s and %s",
				FormatNodeID(hb.NodeID), existing.Addr, addr)
			existing.Rejected = true
			existing.Trust = 0
			peer.Rejected = true
			peer.Trust = 0
			return fmt.Errorf("identity conflict: NodeID %s", FormatNodeID(hb.NodeID))
		}
	}

	// First heartbeat — learn identity.
	if peer.NodeID == "" {
		peer.NodeID = hb.NodeID
		peer.PublicKey = pubKey
		pr.byID[hb.NodeID] = peer
		log.Printf("[PEER] Learned identity for %s: %s", addr, FormatNodeID(hb.NodeID))
	}

	// Consistency check: sequence should be last_known + 1 (or first heartbeat).
	consistent := true
	if peer.LastSeq > 0 {
		if hb.Seq != peer.LastSeq+1 {
			consistent = false
			peer.DriftCount++
			log.Printf("[DRIFT] %s: expected seq %d, got %d (drift #%d)",
				FormatNodeID(hb.NodeID), peer.LastSeq+1, hb.Seq, peer.DriftCount)
		}
	}

	// Update EMA trust score.
	if consistent {
		peer.Trust = EMADecay*peer.Trust + (1-EMADecay)*1.0
		peer.DriftCount = 0
	} else {
		peer.Trust = EMADecay*peer.Trust + (1-EMADecay)*0.0
	}

	peer.LastSeq = hb.Seq
	peer.LastHash = hb.LastHash
	peer.TreeHash = hb.TreeHash
	peer.LastSeen = time.Now()

	return nil
}

// PeerSummary is the JSON-friendly view of a peer.
type PeerSummary struct {
	NodeID     string  `json:"node_id"`
	Addr       string  `json:"addr"`
	Seq        int64   `json:"seq"`
	Trust      float64 `json:"trust"`
	TrustLevel string  `json:"trust_level"`
	DriftCount int     `json:"drift_count"`
	LastSeen   string  `json:"last_seen"`
	Rejected   bool    `json:"rejected,omitempty"`
}

// Summarize returns a JSON-friendly summary of all peers.
func (pr *PeerRegistry) Summarize() []PeerSummary {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	result := make([]PeerSummary, 0, len(pr.peers))
	for _, p := range pr.peers {
		lastSeen := ""
		if !p.LastSeen.IsZero() {
			lastSeen = p.LastSeen.Format(time.RFC3339)
		}
		result = append(result, PeerSummary{
			NodeID:     FormatNodeID(p.NodeID),
			Addr:       p.Addr,
			Seq:        p.LastSeq,
			Trust:      p.Trust,
			TrustLevel: TrustLevel(p.Trust),
			DriftCount: p.DriftCount,
			LastSeen:   lastSeen,
			Rejected:   p.Rejected,
		})
	}
	return result
}
