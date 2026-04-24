# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Commit-message convention: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
(`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`).

## [Unreleased]

### Added

### Changed

### Fixed

## [0.1.0] - 2026-04-14

Proof-of-concept distributed identity and trust protocol for AI agent networks.

### Added

- ECDSA P-256 identity: cryptographic keypairs with NodeID derivation
- EMA trust scoring: decay-based trust with configurable thresholds (0.7 / 0.4 / 0.2)
- 3-layer coherence: hash chain, schema, and temporal monotonicity validation
- Hash-chained ledger: append-only event log with canonical JSON serialization
- HTTP protocol: heartbeat, peer discovery, challenge, join endpoints
- Standalone binary via `go install github.com/cogos-dev/constellation/cmd/constellation@v0.1.0`

[Unreleased]: https://github.com/cogos-dev/constellation/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cogos-dev/constellation/releases/tag/v0.1.0
