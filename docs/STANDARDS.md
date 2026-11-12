# Development Standards (`sonaraim-node`)

> Engineering, Code Quality, Testing, and Security Guidelines

## Language and Toolchain

- **Language**: Rust (latest stable edition, `cargo` toolchain).
- **Formatting**: `rustfmt` (`cargo fmt --check` must pass with zero diffs).
- **Static Analysis**: `clippy` (`cargo clippy -- -D warnings` must pass with zero warnings).
- **Module Size Limit**: Every source file under `src/` and `tests/` must remain under 300 lines with a single clear responsibility.

## Zero-Hardcode Policy

- Source files must never embed fallback hosts, ports, timeouts, TTLs, or node identifiers.
- All runtime parameters are loaded exclusively via `NodeConfig::from_env()` in `src/config.rs`.
- Missing or malformed environment variables return explicit, typed `ConfigError` values.

## Documentation and Comments

- Every public struct, enum, trait, function, and method must include a Rust doc comment (`///`) describing its purpose, parameters, return values, and error conditions.
- Markdown files must pass `markdownlint` validation cleanly.
- `docs/ARCHITECTURE.md` uses text and ASCII diagrams only; all Mermaid diagrams reside exclusively in `docs/DIAGRAMS.md`.

## Testing Methodology (TDD)

- Write failing unit and integration tests in `tests/node_test.rs` before implementing production logic (Red -> Green -> Refactor).
- All tests must be deterministic and isolated from external network state.
- Run `cargo test` before every commit.

## Git and Issue Workflow

- Conventional Commits mandatory: `<type>(<scope>): <subject> (#issue)` with `Ref #N` in the commit footer.
- Every code change corresponds to a tracked GitHub issue with `priority::*` and `type::*` labels.
- Issues move to `status::review` once all acceptance criteria are verified.
