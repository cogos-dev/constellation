# Constellation

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/cogos-dev/constellation)](https://goreportcard.com/report/github.com/cogos-dev/constellation)

Constellation is the trust substrate of [CogOS](https://github.com/cogos-dev/cogos). This repo is the reference implementation of its L1 projection: a peer-to-peer node protocol where each node maintains a hash-chained event ledger in a git repository, broadcasts ECDSA-signed state snapshots to peers, and scores peers by behavioral consistency over time. The cogos kernel defines a `ConstellationBridge` seam designed to consume this protocol.

## What this repo provides

The L1 trust-node protocol, as a standalone Go module:

- **Hash-chained ledger.** Append-only events stored as `events/{seq:08d}.json` in an in-process git repo (go-git). Each event commits to the prior event's hash. Canonicalization is RFC 8785 over JSON; content hashing is SHA-256.
- **ECDSA P-256 identity.** `NodeID = SHA-256(pubkey DER)`. Keys are local; node IDs are derived, not registered.
- **Signed heartbeats.** Every 5 seconds, each node signs `{node_id, listen_addr, tree_hash, seq, last_hash, timestamp}` and broadcasts to peers. The tree hash of `events/` is a compact state fingerprint: two nodes that agree on it agree on the entire ledger.
- **EMA-weighted peer trust.** Each peer carries an exponentially-weighted moving average score over heartbeat consistency: `trust = 0.8 * trust + 0.2 * (consistent ? 1.0 : 0.0)`. Trust is earned, decays on drift, and gates whether a peer's claims are admitted.
- **Three-layer self-coherence check.** A node validates its own ledger by hash-chain integrity, schema, and temporal monotonicity. The check is idempotent: re-applying it to a consistent ledger leaves it unchanged. A node that fails its own check reports `pass: false` on `/health`.
- **Mutual O(1) verification.** Heartbeat verification is one signature check, one hash, one sequence comparison. No event replay. No Merkle-proof traversal.

## The Constellation substrate

Constellation is one architecture applied to multiple node populations.

The same primitives (RFC 8785 canonical JSON, SHA-256 content hashing, a git-backed `events/{seq:08d}.json` chain with `prior_hash` linking, a tree-hash state fingerprint, and EMA-weighted decay signals over relationships) compose into a substrate that hosts:

| Population | What the node represents | Where it lives |
|---|---|---|
| Peer nodes | Physical machines participating in the trust mesh | This repo |
| Identities | Principals (users, agent personas), OIDC-shaped (iss/sub/aud + claims) | cogos kernel, as a CRD |
| Cogdocs | Memory atoms with frontmatter and refs | cogos kernel, in the workspace overlay |
| Channels | Persistent conversation rooms | cogos kernel, as a CRD |
| Sessions | Live agent or human attachments | cogos kernel, as bus events |
| Agents | Reconciled agent specs | cogos kernel, as a CRD |

Each population gets hash-chained history, EMA-weighted relationship signals, and O(1) verification by being in the constellation. Adding a new population is a schema extension, not a structural rebuild.

This repo specifies and implements the peer-node projection. Other projections live in the [cogos kernel](https://github.com/cogos-dev/cogos), where the generic plan/apply reconciliation loop in `pkg/reconcile` interprets each population's spec.

## Three-layer model

| Layer | What | Where |
|---|---|---|
| **L1 — Node** | Physical peer machine. ECDSA P-256 keypair, NodeID = SHA-256(pubkey DER), signed heartbeats, git-backed ledger. | This repo. |
| **L2 — Identity** | Principal (user or agent persona). OIDC-shaped: iss, sub, aud, claims. Global identity, per-audience expressions. | cogos kernel: `kind: Identity` CRD reconciled by `pkg/reconcile`. L1 node keys sign L2 attestations. |
| **L3 — Presence** | Ephemeral activation of an L2 identity. Spatial shape (current attention distribution) plus temporal pattern (recent action sequence). | Not stored. Query-derived from the kernel's attention table and bus event log. |

L1 is necessary because peer-to-peer trust needs a stable signing key bound to a verifiable history. L2 is necessary because principals are not the same as machines (one user spans many machines; one machine hosts many agents). L3 is emergent because freezing it as state creates stale-presence bugs and blurs the line between pattern and instance.

## Cross-workspace composition

The CogOS workspace model is hierarchical and recursive: a workspace can have an upstream the way a git repo has a remote, and that upstream can have its own upstream, with selective promotion of knowledge between layers. A workspace is just a directory with a `.cog/` overlay, and the overlay is composable across the hierarchy.

That hierarchy needs trust to be safe. Constellation is the mechanism: peer nodes verify each other through hash-chained ledgers and EMA-weighted reputation, and trust scores gate which peers can attest to which knowledge. The substrate is what makes "compose workspaces like git remotes, but recursive" actually work without an authority granting permissions from above.

Status: BEP-based workspace sync currently gates peers by static configuration (per-peer `Trusted` flag). Constellation EMA-weighted gating of sync envelopes is in progress against the `ConstellationBridge` seam in the cogos kernel.

## L1 protocol details

### Node structure

```
Node
├── Identity     ECDSA P-256 keypair, NodeID = SHA-256(pubkey DER)
├── GitStore     go-git in-process repo, events as events/{seq:08d}.json
├── PeerRegistry Known peers, EMA trust scores, identity conflict detection
├── Heartbeat    5s ticker: append event, commit, sign state, broadcast
└── HTTP Server  6 endpoints for inter-node communication
```

### Heartbeat protocol

Every 5 seconds, each node:

1. Generates an event and appends it to the ledger
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

### Trust scoring

Trust is tracked per peer, per node, as an EMA over heartbeat consistency.

| Level | Score | Meaning |
|-------|-------|---------|
| Trusted | >= 0.7 | Consistent heartbeat history, peer is reliable |
| Pending | >= 0.4 | Insufficient history to judge |
| Suspect | >= 0.2 | Recent inconsistencies detected |
| Rejected | < 0.2 | Persistent drift or identity conflict |

After 2 consecutive drifts, the verifier issues a **challenge**: it requests an event range from the suspect peer and re-validates the hash chain locally.

### Why a stolen key is insufficient

An attacker holding a stolen private key can sign valid heartbeats, but cannot forge the event history. When the attacker begins broadcasting, existing peers observe:

- **Sequence discontinuity.** The attacker's seq counter starts from 1; peers expect `last_known + 1`.
- **Identity conflict.** Two different addresses claim the same NodeID within a 30-second window.
- **Trust collapse.** The EMA trust score drops below the rejection threshold (0.2).

The key alone is insufficient because trust is coupled to history, and the hash chain is computationally irreversible. This is the property that distinguishes constellation's trust model from a static-credential PKI: a credential alone is not a vouchable identity; the identity is the credential plus a verifiable behavioral history.

### HTTP endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/heartbeat` | Receive signed state snapshot from peer |
| GET | `/peers` | List all peers with trust scores |
| POST | `/challenge` | Request event range for re-validation |
| POST | `/join` | New node announces itself, receives peer list |
| GET | `/health` | Self-coherence check (3-layer validation) |
| GET | `/state` | Full state dump (node state + peer summaries) |

## Running

### Prerequisites

- Go 1.24+
- Docker and Docker Compose (for containerized testing)
- `jq` and `curl` (for test scripts)

### Local (3 processes)

```bash
go build -o constellation ./cmd/constellation

# Terminal 1: Start 3 nodes
./constellation node --name alpha --port 8101 --hostname localhost \
    --data-dir /tmp/constellation/alpha --peers localhost:8102,localhost:8103 &
./constellation node --name beta  --port 8102 --hostname localhost \
    --data-dir /tmp/constellation/beta  --peers localhost:8101,localhost:8103 &
./constellation node --name gamma --port 8103 --hostname localhost \
    --data-dir /tmp/constellation/gamma --peers localhost:8101,localhost:8102 &

# Wait ~30s for trust to converge, then query:
curl -s http://localhost:8101/peers | jq '.[] | {node_id, trust, trust_level}'
curl -s http://localhost:8101/health | jq .
```

### Docker Compose (3-node constellation)

```bash
docker compose up -d --build

# Query nodes on host ports 8101-8103:
curl -s http://localhost:8101/peers | jq .
curl -s http://localhost:8102/health | jq .
```

### CLI commands

```bash
# Start a node
constellation node --name NAME --port PORT --hostname HOST \
    --data-dir DIR --peers HOST1:PORT1,HOST2:PORT2

# Query node state
constellation status --target http://localhost:8101

# Tamper info (actual tampering is done via file modification or docker exec)
constellation tamper --target http://localhost:8101
```

## Test scenarios

Each scenario exercises one of the protocol's properties end-to-end.

### Trust convergence

Three nodes, ~6 heartbeat cycles (30s), all peers reach trusted status.

```bash
bash test/scenario_happy.sh
```

Expected:
```
Port 8101: 2 trusted / 2 total peers
Port 8102: 2 trusted / 2 total peers
Port 8103: 2 trusted / 2 total peers
[PASS] All 3 nodes show 2+ trusted peers
```

What it verifies: nodes that maintain consistent hash-chained ledgers converge to mutual trust through heartbeat exchange alone. No certificate authority. No pre-shared secrets. No consensus protocol.

### Tamper detection

Three nodes, trust converges, then an event file in alpha's git repo is corrupted on disk. Alpha's `/health` detects it.

```bash
bash test/scenario_drift.sh
```

Expected:
```
Alpha's /health reports pass: false
  hash_chain: tampered at seq N: computed abc... != stored def...
[PASS]
```

What it verifies: the three-layer coherence validation detects any modification to the event history. Each event commits to all prior events' hashes, so tampering is locally observable without involving peers.

### Stolen-key rejection

Three nodes, trust converges, alpha's private key is copied to an attacker node, the attacker is started. Beta and gamma reject the impostor.

```bash
bash test/scenario_theft.sh
```

Expected:
```
Beta:  NodeID a7ecf... → rejected: true, trust: 0
Gamma: NodeID a7ecf... → rejected: true, trust: 0
[PASS]
```

What it verifies: a stolen ECDSA key signs valid heartbeats but cannot forge event history. The attacker's seq starts from 1 when peers expect seq N+1, triggering identity conflict detection. Trust is coupled to history, not credentials.

### Dynamic join

Three nodes, trust converges, delta starts pointing at alpha, delta discovers all peers and earns trusted status.

```bash
bash test/scenario_join.sh
```

Expected:
```
Alpha: delta trust 0.84 (trusted)
Delta: alpha trust 0.84 (trusted), beta trust 0.80 (trusted), gamma trust 0.80 (trusted)
[PASS]
```

What it verifies: a new node bootstraps by joining the constellation and building a coherent event history that peers can verify. Trust is earned over time, not granted by an authority at registration.

### Run all scenarios

```bash
bash test/run_scenarios.sh
```

## Repo layout

```
.
├── go.mod                      # Standalone module, dep: go-git/v5
├── go.sum
├── ledger.go                   # RFC 8785 canonical JSON, SHA-256 hash chain
├── identity.go                 # ECDSA P-256 keygen, NodeID, sign/verify
├── gitstore.go                 # go-git in-process repo, event storage
├── coherence.go                # 3-layer validation (chain, schema, temporal)
├── node.go                     # Node lifecycle, state management
├── protocol.go                 # HTTP handlers (6 endpoints)
├── heartbeat.go                # Background ticker, ECDSA-signed broadcast
├── constellation.go            # EMA trust scoring, identity conflict detection
├── cmd/constellation/          # CLI: node, status, tamper
├── Dockerfile                  # Multi-stage: golang:1.24-alpine → alpine:3.21
├── docker-compose.yml          # 3-node constellation (alpha, beta, gamma)
├── docker-compose.test.yml     # Test overlays (delta join, attacker theft)
└── test/
    ├── scenario_happy.sh       # Trust convergence
    ├── scenario_drift.sh       # Tamper detection
    ├── scenario_theft.sh       # Stolen-key rejection
    ├── scenario_join.sh        # Dynamic join
    └── run_scenarios.sh        # Run all, report PASS/FAIL
```

## Ecosystem

Constellation is one piece of the [CogOS](https://github.com/cogos-dev/cogos) ecosystem.

| Repo | Purpose |
|------|---------|
| [cogos](https://github.com/cogos-dev/cogos) | The kernel daemon. Workspace state, context assembly, multi-provider inference routing, hash-chained ledger, MCP server, agent harness. |
| **constellation** | **L1 trust-node protocol (this repo).** |
| [mod3](https://github.com/cogos-dev/mod3) | Voice channel. Multi-model TTS with queue-aware output. |
| [skills](https://github.com/cogos-dev/skills) | Portable skill definitions for Claude Code and compatible agents. |
| [charts](https://github.com/cogos-dev/charts) | Helm charts for deploying CogOS nodes to Kubernetes. |
| [research](https://github.com/cogos-dev/research) | Notes and the training pipeline behind the kernel's design choices. |

For the research-paper version of this repo's contribution, see [docs/PAPER.md](docs/PAPER.md). For the full system specification, see the [cogos repo](https://github.com/cogos-dev/cogos).

## License

MIT.
