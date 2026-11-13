# Contributing to Sonaraim Node

Thank you for contributing to `sonaraim-node`! This repository implements the decentralized P2P store-and-forward relay node, Key Transparency Merkle log, UDP/QUIC gossip transport, and Private Set Intersection (PSI) service for the Sonaraim ecosystem.

To protect network availability, privacy guarantees, and zero-knowledge invariants, all contributions must comply with the following standards.

---

## 1. Branching & Git Workflow

- **`develop` Branch**: The primary integration branch. All feature and fix branches must branch from and merge into `develop`.
- **`main` Branch**: Reserved strictly for production releases (`vMAJOR.MINOR.PATCH`). Direct merges to `main` are disallowed.
- **Branch Naming**:
  - Feature branches: `feature/<feature-name>` (e.g., `feature/quic-udp-gossip`)
  - Fix branches: `fix/<issue-description>` (e.g., `fix/wal-compaction-bounds`)
- **Pull Requests**: Target `develop`. Every PR must pass all CI/CD quality checks and maintain 100% test pass rates before merge review.

---

## 2. Test-Driven Development (TDD) Mandatory

All code changes in `sonaraim-node` must follow strict Test-Driven Development:

1. **Red**: Write a failing integration or unit test reproducing the defect or specifying the new route/subsystem before writing production code.
2. **Green**: Write the minimal code necessary to make the test pass.
3. **Refactor**: Clean up and optimize the implementation while keeping all tests passing.
4. **Coverage**: Every route, storage operation, cryptographic proof, and network frame parsing must be verified by automated tests.

---

## 3. Code Standards & Architecture Guidelines

- **File Length Limit**: Every source file must remain under 300 lines. Decompose large modules into cohesive, single-responsibility files.
- **Mandatory Documentation**: Every public struct, enum, function, and method must have Rustdoc comments (`///`) describing its behavior, arguments, errors, and side effects. Complex logic blocks must have inline comments explaining *why*.
- **Zero-Hardcode Policy**: Never embed default hostnames, IP addresses, ports, timeouts, or tokens in source code. All settings must load via `NodeConfig::from_env()` or explicit environment variables (`NODE_API_AUTH_TOKEN`, `NODE_SIGNING_KEY_PATH`, `REDIS_URL`, etc.).
- **Error Handling**: Do not use `unwrap()` or `expect()` in server request dispatching or production code paths. Use typed errors and return appropriate HTTP status codes (400, 401, 404, 500).

---

## 4. Conventional Commits

All commit messages must follow the Conventional Commits format and reference an issue number:

```text
<type>(<scope>): <subject> (Ref #N)
```

- **Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`.
- **Scopes**: `relay`, `merkle`, `gossip`, `p2p`, `psi`, `storage`, `auth`, `http`.
- **Issue Reference**: Always reference the tracked issue using `Ref #N`.

Example:

```text
feat(storage): add S3 object uploader and atomic WAL compaction (Ref #9)
```

---

## 5. Tooling, Verification & Quality Gates

Run and verify the following commands before committing:

```bash
# 1. Format check
cargo fmt --check

# 2. Static analysis
cargo clippy --all-targets -- -D warnings

# 3. Test execution
cargo test

# 4. Markdown linting
npx --yes markdownlint-cli2 "*.md" "docs/*.md"
```

All 4 commands must execute with zero errors.

---

## 6. Documentation & Architecture Standards

- **Language**: English only for code, documentation, comments, and commit messages.
- **Mermaid Diagrams**: Mermaid diagrams belong **exclusively** inside `docs/DIAGRAMS.md`. Never place ```` ```mermaid ```` code blocks in `README.md` or `ARCHITECTURE.md` (use text or ASCII art instead).
- **Markdown Quality**: All markdown documents must pass `markdownlint` without errors.
