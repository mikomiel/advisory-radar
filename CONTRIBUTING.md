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
- A new source plugin takes four edits: a builder (and its `SOURCE_BUILDERS`
  entry) in `advisory_radar/sources.py`, one `SourceSpec` in
  `advisory_radar/catalogue.py`, one row in the README `## Sources` table, and a
  fixture test in `tests/`. The config key allowlist, the `/sources` page and
  `advisory-radar sources list` are derived from the catalogue; the README row is
  written by hand, and `tests/test_catalogue.py` fails if any kind, summary or key
  differs, so the registry stays the one owner of those facts.
  `advisory-radar sources test <id>` fetches a configured source and prints its
  items and truncation flag without delivering or saving anything — useful while
  you are writing that fixture. A `webhook` source always prints nothing there:
  the command gives the source an empty inbox, so it checks the configuration, not
  the live intake. Notifier plugins implement
  `advisory_radar.plugins.Notifier` and are registered in `notifiers.py`. Tests
  use synthetic fixtures only (no real credentials, no live estate data).

## Reporting security issues

See [SECURITY.md](SECURITY.md) — use private vulnerability reporting, not
public issues.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
