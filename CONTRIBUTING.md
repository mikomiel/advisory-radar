# Contributing to advisory-radar

Thanks for considering a contribution. This project is public and
contribution-friendly; the rules below keep it safe for everyone.

## Workflow

1. Fork the repository and create a topic branch (`feat/...`, `fix/...`).
2. Commit with [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, ...). One logical change per
   commit; no force-push after review starts.
3. For a behaviour change, open an issue first; a small fix can go straight to a
   pull request. Describe the change, the reason and how you tested it. `main` is
   protected: the required checks must be green and the `review` status must
   approve the exact head commit — or the pull request is one of the two shapes
   that need no review: a Dependabot update that touches only manifests, or the
   release pull request release-please generates (see [Releases](#releases)). The
   full policy is in [docs/review-and-merge.md](docs/review-and-merge.md).
4. Keep PRs small and focused; a reviewer should be able to judge the whole
   diff in one read.

## Required checks

`main` requires these contexts on the pull request's head, all strict:

| Context | What it proves |
| --- | --- |
| `ci` | Lint, tests, the image smoke test and the secret scan passed. |
| `gate` | The trusted default-branch workflow published the gate status. |
| `review` | An approving review exists at this exact commit, or the update is an exempt Dependabot manifest change. |
| `dependency-review` | The change does not add a dependency with a known vulnerability. |

If you rename a job, update the required contexts in the same change: renaming a
context blocks every pull request until the protection is updated.

## Checks (run locally before pushing)

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv run python scripts/check_no_estate_identifiers.py   # CI guard, must pass
```

CI additionally runs a secret scan (gitleaks) over the **complete intended commit range**: the
checkout fetches full history and the job proves the event's `base..head` range (or `--all` for a
new branch) before it scans, so a secret added and removed earlier in the branch is still
detected. That is **post-push detection, not a substitute for pre-push prevention**: once a
secret is pushed it is already exposed and must be revoked. Never commit secrets, tokens, webhook
URLs, internal hostnames or IPs, and scan your branch locally before pushing — for example
`gitleaks git --config .gitleaks.toml --log-opts="origin/main..HEAD" .`. The CI guard and the
secret scan both fail the build on what they find.

## Review automation

The merge automation, the review-status rule and the sensitive-path guard live
in this repository. `ci-burst` and `agent-chat` carry adapted copies of parts of
this policy; they are separate implementations because each repository's guard
and allowlist differ, not a shared library. Consolidation, if ever wanted, is a
separate change that must go through the guard and its tests.

## Releases

Releases are automated by
[release-please](https://github.com/googleapis/release-please). It keeps one
release pull request open against `main`: the next version in `pyproject.toml`
and `src/advisory_radar/__init__.py`, the generated `CHANGELOG.md` section, and
`.release-please-manifest.json`.

- Write conventional commit subjects. They become the changelog, and while the
  project is `0.x` a `feat` bumps the minor version (`bump-minor-pre-major`).
- Do not bump a version or edit `CHANGELOG.md` by hand; the release pull request
  owns both. A change to `release-please-config.json` or
  `.release-please-manifest.json` is release policy and is merged by a person.
- Merging the release pull request is the release decision. It always changes
  `pyproject.toml` and the manifest, so the merge automation never takes it: a
  person merges it. Its `review` status is published as `success` without an
  independent App review, because release-please opens it from the token owner's
  account and no authoring session exists to request one. That exemption is
  recognised by the generator's exact output — branch, author, the five release
  files and a diff that is only the version bump — and is described in
  [docs/review-and-merge.md](docs/review-and-merge.md).
- The merge creates the `vX.Y.Z` tag and the GitHub Release. The tag starts the
  `release` workflow, which pushes `linux/amd64` and `linux/arm64` to
  `ghcr.io/mikomiel/advisory-radar` under the version tag and, for a stable
  `vX.Y.Z`, `latest`, with build provenance and an SBOM attestation bound to the
  pushed digest.

## Code style

- Python 3.13 and 3.14 are supported and tested (the range is declared in
  `pyproject.toml`), standard-library-first for the core pipeline (HTTP via
  `urllib`), FastAPI only for the web layer.
- Explicit, boring, reversible code. No clever abstractions without a second
  real consumer.
- Tests next to the behavior they pin (`tests/`); property-style fixtures over
  mocks where practical.
- A new source plugin takes four edits: a builder (and its `SOURCE_BUILDERS`
  entry) in `advisory_radar/sources.py`, one `SourceSpec` in
  `advisory_radar/catalogue.py`, one row in the `docs/sources.md` catalogue table, and a
  fixture test in `tests/`. The config key allowlist, the `/sources` page and
  `advisory-radar sources list` are derived from the catalogue; the docs row is
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
