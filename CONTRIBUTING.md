# Contributing

Thank you for helping. This is the reference node of Open Brand Exchange, written in Rust. Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- Bugs and ideas: open an issue. Security problems: see [SECURITY.md](SECURITY.md), never a public issue.
- Protocol changes start in [openbrandexchange/spec](https://github.com/openbrandexchange/spec); this repository follows the spec.
- Admin screens live in [admin-ui](https://github.com/openbrandexchange/admin-ui) and are vendored here in `ui/dist` with `scripts/update-ui.sh`.

## Development

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test                      # unit and HTTP integration tests (SQLite)
scripts/conformance.sh          # the OBX conformance suite of obx-go against a fresh node
```

- Tests test behaviour (HTTP in, HTTP out, database state), never source text.
- Schema changes are a new entry at the end of `src/db/migrations.rs` (forward-only: never edit a released migration).
- Code, comments, commit messages and docs are English; user-facing texts come from admin-ui in 25 languages.
- Keep dependencies few and permissively licensed (`cargo deny check licenses`).

## Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Sign off every commit (`git commit -s`). You keep the copyright in your contribution; there is no contributor licence agreement.

## Pull requests

- One logical change per pull request, with tests and docs updated.
- CI must be green: format, clippy, tests, conformance, Docker build.
- User-visible changes get a line in `CHANGELOG.md` under "Unreleased".
