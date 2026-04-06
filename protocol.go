// protocol.go — HTTP handlers for inter-node communication.
//
// Endpoints:
//   POST /heartbeat  — receive peer heartbeat
//   GET  /peers      — list peers + trust state
//   POST /challenge  — request event range verification
//   POST /join       — new node announces itself
//   GET  /health     — self coherence check
//   GET  /state      — full dump for testing
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// cors wraps a handler with CORS headers for dashboard access.
func cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

// RegisterHandlers wires up the HTTP mux for a node.
func RegisterHandlers(mux *http.ServeMux, node *Node) {
	mux.HandleFunc("/heartbeat", cors(handleHeartbeat(node)))
	mux.HandleFunc("/peers", cors(handlePeers(node)))
	mux.HandleFunc("/challenge", cors(handleChallenge(node)))
	mux.HandleFunc("/join", cors(handleJoin(node)))
	mux.HandleFunc("/health", cors(handleHealth(node)))
	mux.HandleFunc("/state", cors(handleState(node)))
}

func handleHeartbeat(node *Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var hb Heartbeat
		if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
			http.Error(w, "invalid heartbeat", http.StatusBadRequest)
			return
		}

		// Verify signature.
		valid, pubKey, err := VerifyHeartbeat(&hb)
		if err != nil {
			log.Printf("[%s] Heartbeat verification error from %s: %v",
				node.Name, FormatNodeID(hb.NodeID), err)
			http.Error(w, "verification failed", http.StatusForbidden)
			return
		}
		if !valid {
			log.Printf("[%s] Invalid signature from %s", node.Name, FormatNodeID(hb.NodeID))
			http.Error(w, "invalid signature", http.StatusForbidden)
			return
		}

		// Use the sender's self-reported listen address for peer registration.
		peerAddr := hb.ListenAddr
		if peerAddr == "" {
			peerAddr = r.RemoteAddr
		}

		if err := node.Peers.ProcessHeartbeat(peerAddr, &hb, pubKey); err != nil {
			log.Printf("[%s] Process heartbeat error: %v", node.Name, err)
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		// Check if challenge needed.
		peer := node.Peers.GetByID(hb.NodeID)
		if peer != nil && peer.DriftCount > MaxDriftBeforeChallenge {
			go issueChallenge(node, peer)
		}

		w.WriteHeader(http.StatusOK)
	}
}

func handlePeers(node *Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(node.Peers.Summarize())
	}
}

func handleChallenge(node *Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			StartSeq int64 `json:"start_seq"`
			EndSeq   int64 `json:"end_seq"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		events, err := node.Store.ReadEventRange(req.StartSeq, req.EndSeq)
		if err != nil {
			http.Error(w, fmt.Sprintf("read events: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"events":    events,
			"coherence": ValidateCoherence(events),
		})
	}
}

func handleJoin(node *Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			NodeID    string `json:"node_id"`
			Name      string `json:"name"`
			Addr      string `json:"addr"`
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		log.Printf("[%s] Join request from %s (%s)", node.Name, req.Name, FormatNodeID(req.NodeID))

		// Add the new peer.
		node.Peers.AddPeer(req.Addr)

		// Return list of known peer addresses (only those with learned identities).
		var peerAddrs []string
		seen := map[string]bool{req.Addr: true}
		for _, p := range node.Peers.AllPeers() {
			if p.NodeID != "" && !seen[p.Addr] {
				peerAddrs = append(peerAddrs, p.Addr)
				seen[p.Addr] = true
			}
		}
		// Include self.
		selfAddr := node.ListenAddr()
		if !seen[selfAddr] {
			peerAddrs = append(peerAddrs, selfAddr)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "accepted",
			"peers":  peerAddrs,
		})
	}
}

func handleHealth(node *Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		report, err := node.SelfCheck()
		if err != nil {
			http.Error(w, fmt.Sprintf("coherence check failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if !report.Pass {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(report)
	}
}

func handleState(node *Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		state, err := node.CurrentState()
		if err != nil {
			http.Error(w, fmt.Sprintf("state error: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"state": state,
			"peers": node.Peers.Summarize(),
		})
	}
}

// issueChallenge requests an event range from a drifting peer and re-validates.
func issueChallenge(node *Node, peer *PeerState) {
	startSeq := peer.LastSeq - 5
	if startSeq < 1 {
		startSeq = 1
	}

	log.Printf("[%s] Challenging %s for events %d-%d",
		node.Name, FormatNodeID(peer.NodeID), startSeq, peer.LastSeq)

	req := map[string]any{
		"start_seq": startSeq,
		"end_seq":   peer.LastSeq,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return
	}

	url := fmt.Sprintf("http://%s/challenge", peer.Addr)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("[%s] Challenge to %s failed: %v", node.Name, FormatNodeID(peer.NodeID), err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Events    []*EventEnvelope `json:"events"`
		Coherence *CoherenceReport `json:"coherence"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[%s] Challenge response parse error: %v", node.Name, err)
		return
	}

	if result.Coherence != nil && !result.Coherence.Pass {
		log.Printf("[%s] Challenge response from %s: INCOHERENT",
			node.Name, FormatNodeID(peer.NodeID))
		peer.Trust = 0.1
	} else {
		log.Printf("[%s] Challenge response from %s: coherent",
			node.Name, FormatNodeID(peer.NodeID))
	}
}
