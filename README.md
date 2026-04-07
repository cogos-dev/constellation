# Constellation Protocol — Proof of Concept

> Part of the [CogOS ecosystem](https://github.com/cogos-dev) — **how it TRUSTS**

A distributed trust protocol where **identity is a dynamical property** — coherence with history — rather than a static credential. Each node maintains a hash-chained event ledger in a git repository, broadcasts signed state snapshots to peers, and derives trust from temporal consistency rather than certificate authority.

## What This Proves

Three properties, each demonstrated by a dedicated test scenario:

### 1. Self-Referential Closure

Each node validates its own coherence through a 3-layer stack applied to its git-backed event ledger:

- **Hash chain integrity**: `event[i].prior_hash == hash(event[i-1])` for all events, using SHA-256 over RFC 8785 canonical JSON
- **Schema validation**: Required fields present, valid RFC 3339 timestamps, non-empty hashes
- **Temporal monotonicity**: Timestamps non-decreasing, sequence numbers contiguous

A node that detects its own incoherence reports `pass: false` on its `/health` endpoint. This is the eigenform property: the system is the fixed point of its own validation process. `x = F(x)`.

### 2. O(1) Mutual Verification

Nodes exchange signed heartbeats containing `{node_id, tree_hash, seq, last_hash, timestamp}`. Verification requires:

1. Check ECDSA signature (one crypto op)
2. Verify NodeID matches public key (one hash)
3. Check `seq == last_known_seq + 1` (one comparison)

No event replay, no Merkle proof traversal, no state synchronization. The tree hash of the git events directory serves as a compact state fingerprint — if two nodes agree on the tree hash, they agree on all events. This is temporal coupling, not mechanical coupling.

### 3. Stolen Keys Insufficient for Impersonation

An attacker with a stolen ECDSA private key can sign valid heartbeats, but cannot forge the event history. When the attacker begins broadcasting heartbeats, existing peers observe:

- **Sequence discontinuity**: The attacker's seq counter starts from 1; peers expect `last_known + 1`
- **Identity conflict**: Two different addresses claim the same NodeID within a 30-second window
- **Trust collapse**: The EMA trust score drops below the rejection threshold (0.2)

The key alone is insufficient because trust is coupled to history. You can't impersonate a node without also producing an identical hash-chained event ledger — and the hash chain is computationally irreversible.

## Architecture

### Node Structure

```
Node
├── Identity     ECDSA P-256 keypair, NodeID = SHA-256(pubkey DER)
├── GitStore     go-git in-process repo, events as events/{seq:08d}.json
├── PeerRegistry Known peers, trust scores, identity conflict detection
├── Heartbeat    5s ticker: generate event → commit → sign state → broadcast
└── HTTP Server  6 endpoints for inter-node communication
```

### Heartbeat Protocol

Every 5 seconds, each node:

1. Generates a simulated event and appends it to the ledger
2. Commits the event to git as `events/{seq:08d}.json`
3. Computes the tree hash of the `events/` directory
4. Signs `{node_id, listen_addr, tree_hash, seq, last_hash, timestamp}` with its ECDSA key
5. POSTs the signed heartbeat to all known peers

On receipt, the peer:

1. Verifies the ECDSA signature
2. Verifies that the NodeID matches the public key (prevents relay attacks)
3. Checks sequence consistency (`seq == last_known + 1`)
4. Updates the EMA trust score: `trust = 0.8 * trust + 0.2 * (consistent ? 1.0 : 0.0)`
5. Checks for identity conflicts (same NodeID from different address within 30s)

### Trust Scoring

Trust is tracked per-peer via exponential moving average (EMA) with decay factor 0.8:

| Level | Score | Meaning |
|-------|-------|---------|
| **Trusted** | >= 0.7 | Consistent heartbeat history, peer is reliable |
| **Pending** | >= 0.4 | Insufficient history to judge |
| **Suspect** | >= 0.2 | Recent inconsistencies detected |
| **Rejected** | < 0.2 | Persistent drift or identity conflict |

After 2 consecutive drifts, a **challenge** is issued: the verifying node requests an event range from the suspect peer and re-validates the hash chain locally.

### HTTP Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/heartbeat` | Receive signed state snapshot from peer |
| GET | `/peers` | List all peers with trust scores |
| POST | `/challenge` | Request event range for re-validation |
| POST | `/join` | New node announces itself, receives peer list |
| GET | `/health` | Self-coherence check (3-layer validation) |
| GET | `/state` | Full state dump (node state + peer summaries) |

## Structural Isomorphism: Constellation vs. Blockchain

| Concept | Blockchain | Constellation Protocol |
|---------|-----------|----------------------|
| **Identity** | Public key / address | NodeID = SHA-256(pubkey DER) |
| **State** | Global UTXO set / account trie | Per-node git tree hash |
| **Append-only log** | Block chain (linked list of blocks) | Hash-chained events in git (one file per event) |
| **Tamper evidence** | Merkle root in block header | SHA-256 chain: `event[i].prior_hash = hash(event[i-1])` |
| **State fingerprint** | Merkle Patricia Trie root | Git tree hash of `events/` directory |
| **Consensus** | PoW / PoS / PBFT (O(n) to O(n^2)) | EMA trust scoring from heartbeat consistency (O(1) per peer) |
| **Finality** | Probabilistic (6 confirmations) or expensive (PBFT) | Instant (coherence check = final) |
| **Fork choice rule** | Longest chain / heaviest subtree | Highest coherence score |
| **Sybil resistance** | PoW (energy) / PoS (capital) | Not needed (cooperative threat model) |
| **Threat model** | Adversarial (Byzantine nodes) | Cooperative (nodes drift, not lie) |
| **Challenge mechanism** | Fraud proofs / validity proofs | Event range re-validation on drift |
| **Node discovery** | Gossip protocol (Kademlia DHT) | Join handshake + peer list exchange |
| **Scaling** | Each node increases consensus cost for all | Each node only increases local cost until closure |
| **Thermodynamic cost** | PoW: mass energy per hash | Coherence validation: ln(2) per distinction (Landauer) |

The key divergence: blockchain assumes no trust boundary, requiring expensive global consensus. This protocol assumes cooperative agents that may drift but don't actively deceive, enabling O(1) verification via temporal coupling.

## Running

### Prerequisites

- Go 1.24+
- Docker and Docker Compose (for containerized testing)
- `jq` and `curl` (for test scripts)

### Local (3 processes)

```bash
cd apps/constellation-poc
go build -o constellation-poc .

# Terminal 1: Start 3 nodes
./constellation-poc node --name alpha --port 8101 --hostname localhost \
    --data-dir /tmp/constellation/alpha --peers localhost:8102,localhost:8103 &
./constellation-poc node --name beta  --port 8102 --hostname localhost \
    --data-dir /tmp/constellation/beta  --peers localhost:8101,localhost:8103 &
./constellation-poc node --name gamma --port 8103 --hostname localhost \
    --data-dir /tmp/constellation/gamma --peers localhost:8101,localhost:8102 &

# Wait ~30s for trust to converge, then query:
curl -s http://localhost:8101/peers | jq '.[] | {node_id, trust, trust_level}'
curl -s http://localhost:8101/health | jq .
```

### Docker Compose (3-node constellation)

```bash
cd apps/constellation-poc
docker compose up -d --build

# Query nodes on host ports 8101-8103:
curl -s http://localhost:8101/peers | jq .
curl -s http://localhost:8102/health | jq .
```

### CLI Commands

```bash
# Start a node
constellation-poc node --name NAME --port PORT --hostname HOST \
    --data-dir DIR --peers HOST1:PORT1,HOST2:PORT2

# Query node state
constellation-poc status --target http://localhost:8101

# Tamper info (actual tampering done via file modification or docker exec)
constellation-poc tamper --target http://localhost:8101
```

## Test Scenarios

### Scenario 1: Happy Path — Trust Convergence

Start 3 nodes, wait for ~6 heartbeat cycles (30s), verify all peers reach trusted status.

```bash
bash test/scenario_happy.sh
```

**Expected output:**
```
Port 8101: 2 trusted / 2 total peers
Port 8102: 2 trusted / 2 total peers
Port 8103: 2 trusted / 2 total peers
[PASS] All 3 nodes show 2+ trusted peers
```

**What it demonstrates:** Nodes that maintain consistent hash-chained ledgers converge to mutual trust through temporal coupling alone — no certificate authority, no pre-shared secrets, no consensus protocol.

### Scenario 2: Drift Detection — Tamper Self-Detection

Start 3 nodes, wait for trust, then corrupt an event file in alpha's git repo. Verify alpha's `/health` endpoint detects the tampering.

```bash
bash test/scenario_drift.sh
```

**Expected output:**
```
Alpha's /health reports pass: false
  hash_chain: tampered at seq N: computed abc... != stored def...
[PASS]
```

**What it demonstrates:** The 3-layer coherence validation detects any modification to the event history. The hash chain is self-verifying — each event commits to the hash of all prior events.

### Scenario 3: Key Theft — Stolen Credentials Rejected

Start 3 nodes, wait for trust, copy alpha's private key to an attacker node, start the attacker. Verify that beta and gamma reject the impostor.

```bash
bash test/scenario_theft.sh
```

**Expected output:**
```
Beta:  NodeID a7ecf... → rejected: true, trust: 0
Gamma: NodeID a7ecf... → rejected: true, trust: 0
[PASS]
```

**What it demonstrates:** A stolen ECDSA key can sign valid heartbeats but cannot forge event history. The attacker's heartbeats show sequence discontinuity (seq 1 when peers expect seq N+1), triggering identity conflict detection. Trust is coupled to history, not credentials.

### Scenario 4: Dynamic Join — New Node Achieves Trust

Start 3 nodes, wait for trust, then start delta pointing at alpha. Verify delta discovers all peers through the join handshake and achieves trusted status.

```bash
bash test/scenario_join.sh
```

**Expected output:**
```
Alpha: delta trust 0.84 (trusted)
Delta: alpha trust 0.84 (trusted), beta trust 0.80 (trusted), gamma trust 0.80 (trusted)
[PASS]
```

**What it demonstrates:** Trust is earned through consistent behavior over time, not granted by authority. A new node bootstraps by joining the constellation and building a coherent event history that peers can verify.

### Run All Scenarios

```bash
bash test/run_scenarios.sh
```

## File Structure

```
apps/constellation-poc/
├── go.mod                      # Standalone module, dep: go-git/v5
├── go.sum
├── ledger.go                   # RFC 8785 canonical JSON, SHA-256 hash chain
├── identity.go                 # ECDSA P-256 keygen, NodeID, sign/verify
├── gitstore.go                 # go-git in-process repo, event storage
├── coherence.go                # 3-layer validation (chain, schema, temporal)
├── node.go                     # Node lifecycle, state management
├── protocol.go                 # HTTP handlers (6 endpoints)
├── heartbeat.go                # Background ticker, ECDSA-signed state broadcast
├── constellation.go            # EMA trust scoring, identity conflict detection
├── main.go                     # CLI: node, inject, tamper, status
├── Dockerfile                  # Multi-stage: golang:1.24-alpine → alpine:3.21
├── docker-compose.yml          # 3-node constellation (alpha, beta, gamma)
├── docker-compose.test.yml     # Test overlays (delta join, attacker theft)
└── test/
    ├── scenario_happy.sh       # Trust convergence
    ├── scenario_drift.sh       # Tamper detection
    ├── scenario_theft.sh       # Key theft rejection
    ├── scenario_join.sh        # Dynamic join
    └── run_scenarios.sh        # Run all, report PASS/FAIL
```

## Connection to CogOS

Constellation is the trust organelle in the [CogOS](https://github.com/cogos-dev/cogos) ecosystem — it answers "how does the cell trust?" CogOS externalizes attention and executive function for intelligent systems; Constellation externalizes identity verification and trust scoring across distributed nodes.

In the CogOS cell model, Constellation enables the 4-node topology (laptop, phone, desktop, cloud) where each node maintains its own workspace but verifies peer coherence through temporal coupling. The kernel imports Constellation as a Go library via the `ConstellationBridge` interface — in standalone mode, a `NilBridge` provides healthy defaults with zero overhead.

Each event in the ledger is a CogBlock — the quantum of distinction in the CogOS ontology. Workspace sync uses Syncthing BEP as the transport layer, with signed `SyncEnvelopes` gated by trust score before ingestion.

| Ecosystem | |
|-----------|--|
| [cogos](https://github.com/cogos-dev/cogos) | The kernel — what it IS |
| **constellation** | **Trust — how it TRUSTS** |
| [mod3](https://github.com/cogos-dev/mod3) | Modality — how it ACTS |
| [charts](https://github.com/cogos-dev/charts) | Deployment — how it DEPLOYS |
| [desktop](https://github.com/cogos-dev/desktop) | Interface — how you USE it |

For the full system specification: [CogOS System Spec](https://github.com/cogos-dev/cogos/blob/main/docs/SYSTEM-SPEC.md)
For the research paper thesis: [Paper Thesis](docs/PAPER.md)

## Theoretical Context

The protocol models identity as a fixed point of a self-referential validation process:

- **Self-referential closure** (`x = F(x)`): A node is the eigenform of its own coherence validation
- **Thermodynamic cost** (ln(2) per distinction): Every event that passes validation has paid its Landauer cost
- **Temporal coupling** (not mechanical): Nodes couple through shared timeline, not forced consensus

The key insight: blockchain's O(n^2) consensus cost arises from treating identity as a static credential in an adversarial environment. When identity is instead a dynamical property — coherence with history — verification becomes O(1) per peer and stolen credentials become insufficient for impersonation.
