# Contributing to Constellation

Thanks for your interest in the Constellation identity protocol. This document covers local development, testing, and PR workflow.

## Development setup

```sh
git clone https://github.com/cogos-dev/constellation.git
cd constellation
go mod download
go build ./...
```

Requirements: Go 1.24+.

## Running tests

```sh
go vet ./...
golangci-lint run
go test ./... -race
```

CI runs lint + race-enabled tests on every PR (`.github/workflows/ci.yml`).

## Project layout

- `cmd/constellation/` — CLI entry point
- `internal/` — protocol primitives: ledger, signatures, peer state
- `pkg/` — public API surface (import stable)
- `testdata/` — fixtures for scenario tests

## Submitting changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run lint + tests above
4. Update `CHANGELOG.md` under the Unreleased section if user-visible
5. Open a pull request using the org PR template

Commit messages: conventional-commits (`feat:`, `fix:`, `chore:`, etc.) preferred.

## Reporting issues

Use the org-level [Bug Report](https://github.com/cogos-dev/constellation/issues/new?template=bug.yml) or [Feature Request](https://github.com/cogos-dev/constellation/issues/new?template=feature.yml) forms.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
