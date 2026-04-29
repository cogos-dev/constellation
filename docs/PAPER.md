# Constellation — Research Paper Thesis

## Title (working)

*The Constellation Substrate: Hash-Chained Trust as a Reusable Primitive (L1 Projection)*

## One-line thesis

If a system maintains a state that is publicly verifiable but privately irreproducible, and that state evolves under a temporally consistent rule, then the system has identity.

## Substrate framing

Constellation is one architecture applied to multiple node populations. The same primitives compose into a substrate that hosts peer nodes, principals (identities), memory atoms (cogdocs), conversation rooms (channels), live attachments (sessions), and reconciled agent specs:

- RFC 8785 canonical JSON for a stable serialization
- SHA-256 content hashing
- A git-backed `events/{seq:08d}.json` chain with `prior_hash` linking
- A tree-hash state fingerprint
- EMA-weighted decay signals over relationships

Each population gets hash-chained history, EMA-weighted relationship signals, and O(1) verification by being in the constellation. The L1 projection covered by this paper is the peer-node protocol: ECDSA-signed heartbeats, signed state snapshots, EMA-weighted peer trust. Other projections (identities, channels, cogdocs) live in the cogos kernel and reuse the same primitives through different reconcilers.

## Three-layer model

| Layer | What | Where |
|---|---|---|
| L1 — Node | Physical peer machine; ECDSA P-256 keypair, NodeID = SHA-256(pubkey DER), signed heartbeats, git-backed ledger | This protocol |
| L2 — Identity | Principal (user or agent persona); OIDC-shaped (iss/sub/aud + claims); global identity, per-audience expressions | cogos kernel: `kind: Identity` CRD reconciled by `pkg/reconcile`. L1 node keys sign L2 attestations |
| L3 — Presence | Ephemeral activation of an L2 identity; spatial shape (current attention) plus temporal pattern (recent actions) | Not stored; query-derived from attention table and bus events |

## Formal definition

A system has identity when its state is:

1. **Publicly verifiable.** Any peer can check it in O(1) per check.
2. **Privately irreproducible.** It cannot be forged without breaking the hash chain.
3. **Temporally coupled.** Trust derives from consistent behavior over time, not from credentials at a point in time.

## Contributions

### 1. Identity as a dynamical property

Traditional systems define identity through static credentials (keys, certificates, tokens). Constellation defines identity as the fixed point of a self-referential validation process: `x = F(x)`. A node IS the fixed point of its own coherence validation, in the standard control-theoretic sense: applying the validation rule to a coherent ledger leaves it unchanged.

The framing generalizes:

- **Biological.** DNA is readable by any cell but copied with mutations.
- **Human.** History is observable but irreproducible.
- **Digital.** A ledger is verifiable by peers but the hash chain is irreversible.
- **AI agent.** Behavior is observable but context-dependent expression is irreproducible.

### 2. O(1) mutual verification

Blockchain consensus requires O(n) to O(n²) communication. Constellation achieves mutual verification in O(1) per peer through temporal coupling: nodes exchange signed state fingerprints (git tree hashes) and verify sequence consistency. No event replay. No Merkle proof traversal. No global consensus.

### 3. Stolen credentials insufficient for impersonation

In traditional PKI, a stolen private key is a stolen identity. In Constellation, a stolen key can sign valid messages but cannot forge event history. Peers detect the impostor through sequence discontinuity and identity conflict detection. Trust is coupled to history, not credentials.

### 4. Alternative to blockchain trust

Blockchain's O(n²) consensus cost arises from the adversarial threat model. Constellation assumes cooperative agents that may drift but don't actively deceive:

| Property | Blockchain | Constellation |
|----------|-----------|--------------|
| Consensus cost | O(n) to O(n²) | O(1) per peer |
| Finality | Probabilistic or expensive | Instant (coherence = final) |
| Scaling | Each node increases cost for all | Each node only increases local cost |
| Threat model | Adversarial (Byzantine) | Cooperative (drift, not deception) |
| Sybil resistance | PoW/PoS (energy/capital) | Not needed (cooperative model) |

### 5. Substrate reusability

The same primitives work for populations beyond peer nodes. Identities, channels, cogdocs, and sessions all reuse RFC 8785 canonicalization, SHA-256 chains, and EMA-weighted decay signals, with population-specific reconcilers binding spec to projection. The L1 trust-node protocol is one instance of a more general pattern; the contribution is both the protocol and the demonstration that it is a projection of a substrate, not a one-off design.

## Proof structure

Each property is demonstrated by an automated test scenario:

| Property | Test scenario | Result |
|----------|--------------|--------|
| Self-referential closure | `scenario_happy.sh` (trust convergence) | Pass |
| O(1) verification | `scenario_happy.sh` (heartbeat exchange) | Pass |
| Stolen keys insufficient | `scenario_theft.sh` (key theft rejection) | Pass |
| Tamper detection | `scenario_drift.sh` (self-detection) | Pass |
| Dynamic trust bootstrapping | `scenario_join.sh` (new node earns trust) | Pass |

## Implementation

The reference implementation is complete:

- Go implementation, standalone module (dep: go-git/v5)
- Docker Compose infrastructure (3-node constellation + attacker)
- 4 automated test scenarios
- EMA trust scoring with configurable decay
- ECDSA P-256 identity, SHA-256 hash chains
- Git-backed event storage with tree-hash fingerprinting

## Venue candidates

- **Distributed systems.** SOSP, OSDI, EuroSys
- **Security.** CCS, USENIX Security
- **Decentralized systems.** Distributed-trust venues
- **Interdisciplinary.** Complex Systems, ALIFE (cross-domain isomorphism)

## Connection to CogOS

CogOS workspaces compose hierarchically and recursively, the way git remotes do but with depth: a workspace can have an upstream, that upstream can have its own upstream, and knowledge promotes selectively across the hierarchy. The user controls what crosses each boundary; nothing leaves a workspace by default.

That hierarchy needs trust to be safe. Constellation is the mechanism. Hash-chained ledgers and EMA-weighted reputation give each node a verifiable history, and trust scores between nodes gate which peers can attest to which knowledge. Selective promotion across the hierarchy is exactly the kind of operation that requires per-edge trust to be cheap to evaluate and hard to forge, which is what O(1) mutual verification plus stolen-key insufficiency provide.

The protocol is designed to stand alone as a reusable architectural pattern, while also serving as the trust substrate for cross-workspace composition in CogOS.
