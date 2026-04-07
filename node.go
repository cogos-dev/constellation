// node.go — Constellation node lifecycle.
//
// A Node holds its identity (ECDSA keypair), git-backed event store,
// peer registry, and coherence state. It manages startup (init repo,
// load/generate keys) and graceful shutdown.
package constellation

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Node is a self-referentially closed unit in the constellation.
type Node struct {
	Name      string
	Identity  *NodeIdentity
	Store     *GitStore
	Peers     *PeerRegistry
	Port      int
	DataDir   string
	Hostname  string // externally reachable hostname (default: localhost)

	server    *http.Server
	heartbeat *HeartbeatRunner
	mu        sync.RWMutex
	seq       int64
	lastHash  string
}

// ListenAddr returns the externally reachable address for this node.
func (n *Node) ListenAddr() string {
	host := n.Hostname
	if host == "" {
		host = n.Name
	}
	return fmt.Sprintf("%s:%d", host, n.Port)
}

// NewNode creates and initializes a node.
func NewNode(name string, port int, dataDir string) (*Node, error) {
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), "constellation", name)
	}

	n := &Node{
		Name:    name,
		Port:    port,
		DataDir: dataDir,
		Peers:   NewPeerRegistry(),
	}

	// Load or generate identity.
	idDir := filepath.Join(dataDir, "identity")
	id, err := LoadIdentity(idDir)
	if err != nil {
		id, err = GenerateIdentity()
		if err != nil {
			return nil, fmt.Errorf("generate identity: %w", err)
		}
		if err := SaveIdentity(id, idDir); err != nil {
			return nil, fmt.Errorf("save identity: %w", err)
		}
		log.Printf("[%s] Generated new identity: %s", name, FormatNodeID(id.NodeID))
	} else {
		log.Printf("[%s] Loaded identity: %s", name, FormatNodeID(id.NodeID))
	}
	n.Identity = id

	// Initialize git store.
	repoDir := filepath.Join(dataDir, "repo")
	store, err := NewGitStore(repoDir)
	if err != nil {
		return nil, fmt.Errorf("init git store: %w", err)
	}
	n.Store = store

	// Recover sequence from existing events.
	last, err := store.LastEvent()
	if err != nil {
		return nil, fmt.Errorf("read last event: %w", err)
	}
	if last != nil {
		n.seq = last.Metadata.Seq
		n.lastHash = last.Metadata.Hash
		log.Printf("[%s] Recovered ledger at seq %d", name, n.seq)
	}

	return n, nil
}

// Start begins serving HTTP and running heartbeats.
func (n *Node) Start(initialPeers []string) error {
	// Register initial peers.
	for _, addr := range initialPeers {
		n.Peers.AddPeer(addr)
	}

	// Set up HTTP server.
	mux := http.NewServeMux()
	RegisterHandlers(mux, n)
	n.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", n.Port),
		Handler: mux,
	}

	// Start heartbeat runner.
	n.heartbeat = NewHeartbeatRunner(n, 5*time.Second)
	n.heartbeat.Start()

	// Announce to initial peers.
	go n.announceToInitialPeers(initialPeers)

	log.Printf("[%s] Starting on port %d (NodeID: %s)", n.Name, n.Port, FormatNodeID(n.Identity.NodeID))
	if err := n.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Stop gracefully shuts down the node.
func (n *Node) Stop() {
	log.Printf("[%s] Shutting down...", n.Name)
	if n.heartbeat != nil {
		n.heartbeat.Stop()
	}
	if n.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n.server.Shutdown(ctx)
	}
}

// AppendEvent creates a new event and commits it to the git store.
func (n *Node) AppendEvent(eventType string, data map[string]any) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.seq++
	event, err := NewEvent(n.Identity.NodeID, eventType, n.seq, n.lastHash, data)
	if err != nil {
		return fmt.Errorf("create event: %w", err)
	}

	if err := n.Store.AppendEvent(event); err != nil {
		n.seq--
		return fmt.Errorf("append event: %w", err)
	}

	n.lastHash = event.Metadata.Hash
	return nil
}

// CurrentState returns the node's current state snapshot.
func (n *Node) CurrentState() (*NodeState, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	treeHash, err := n.Store.TreeHash()
	if err != nil && n.seq > 0 {
		return nil, fmt.Errorf("tree hash: %w", err)
	}

	return &NodeState{
		NodeID:   n.Identity.NodeID,
		Name:     n.Name,
		Seq:      n.seq,
		LastHash: n.lastHash,
		TreeHash: treeHash,
	}, nil
}

// SelfCheck runs coherence validation on the node's own ledger.
func (n *Node) SelfCheck() (*CoherenceReport, error) {
	events, err := n.Store.ReadEventRange(1, n.seq)
	if err != nil {
		return nil, fmt.Errorf("read events: %w", err)
	}
	return ValidateCoherence(events), nil
}

// NodeState is the snapshot sent in heartbeats.
type NodeState struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	Seq      int64  `json:"seq"`
	LastHash string `json:"last_hash"`
	TreeHash string `json:"tree_hash"`
}

// announceToInitialPeers sends a join request to bootstrap peers.
func (n *Node) announceToInitialPeers(peers []string) {
	time.Sleep(1 * time.Second) // Give peers time to start
	for _, addr := range peers {
		if err := sendJoinRequest(n, addr); err != nil {
			log.Printf("[%s] Failed to join %s: %v", n.Name, addr, err)
		}
	}
}
