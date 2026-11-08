# Contributing to advisory-radar

Thanks for considering a contribution. This project is public and
contribution-friendly; the rules below keep it safe for everyone.

## Workflow

1. Fork the repository and create a topic branch (`feat/...`, `fix/...`).
2. Commit with [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, ...). One logical change per
   commit; no force-push after review starts.
3. Open a pull request against `main`. Describe the change, the reason, and how
   you tested it. `main` is protected: CI must be green and the `review` status
   must be green — an approving review at the exact head commit, or (for a
   Dependabot dependency update that touches only manifests) no review required,
   as `README.md` describes under "Review and merge automation".
4. Keep PRs small and focused; a reviewer should be able to judge the whole
   diff in one read.

## Checks (run locally before pushing)

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv run python scripts/check_no_estate_identifiers.py   # CI guard, must pass
```

CI additionally runs a secret scan (gitleaks). Never commit secrets, tokens,
webhook URLs, internal hostnames or IPs — the CI guard and the secret scan
both fail the build on them.

## Code style

- Python 3.13+, standard-library-first for the core pipeline (HTTP via
  `urllib`), FastAPI only for the web layer.
- Explicit, boring, reversible code. No clever abstractions without a second
  real consumer.
- Tests next to the behavior they pin (`tests/`); property-style fixtures over
  mocks where practical.
- New source/enricher/notifier plugins implement the protocol in
  `advisory_radar/plugins/` and register in the built-in registry; add tests
  with synthetic fixtures only (no real credentials, no live estate data).

## Reporting security issues

See [SECURITY.md](SECURITY.md) — use private vulnerability reporting, not
public issues.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
