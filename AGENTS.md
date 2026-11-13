# advisory-radar agent instructions

advisory-radar is a self-hostable security advisory watcher. It reads vendor
feeds, webhooks and changedetection.io watches, enriches each finding,
decides a severity per CVE and sends one deduplicated alert per new advisory.
Licence: MIT. GitHub is the only writable source and pull-request surface;
the target branch is `main`.
Non-goals: a per-host agent, cross-source deduplication beyond the watch
window, a hosted service.

## Checks

```sh
uv sync --frozen --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv run python scripts/check_no_estate_identifiers.py
```

- Prerequisites: Python 3.13 or 3.14 and uv. `pyproject.toml` owns the range.
- Run these commands without asking. The tests use synthetic fixtures. They
  need no credential and no live feed.
- A change is ready for a pull request when every command passes.
  `CONTRIBUTING.md` "Required checks" owns the contexts that `main` requires
  on the exact head.
- Before a push, run the Gitleaks secret scan from `.github/workflows/ci.yml`
  with the version that the workflow pins. A CI scan after the push cannot
  prevent disclosure.
- CI also builds and starts the container image. Run that step locally when
  the change touches the image.

## Project shape

- The core pipeline uses the standard library first, with HTTP through
  `urllib`. FastAPI is for the web layer only.
- `src/advisory_radar/catalogue.py` owns the source facts. The configuration
  key allowlist, the `/sources` page and `advisory-radar sources list` derive
  from it. `tests/test_catalogue.py` fails when `docs/sources.md` differs.
- A new source needs a builder with its `SOURCE_BUILDERS` entry in
  `sources.py`, one `SourceSpec` in `catalogue.py`, one row in
  `docs/sources.md` and one fixture test.
- A notifier implements `advisory_radar.plugins.Notifier` and is registered
  in `notifiers.py`.
- An unmeasured severity is a warning. Do not write a rule that suppresses an
  advisory because a score is missing.
- Do not add an abstraction without a second real consumer.

## Working contract

- Use a topic branch and one focused pull request. Write Conventional Commit
  subjects; they become the changelog. Do not force-push after review starts.
- For a behaviour change, open an issue first.
- Do not push to `main`. Branch protection requires green checks and a review
  of the exact head. A new commit needs fresh CI and a fresh review.
- The merge automation merges an approved pull request that touches no
  sensitive path. An authoring agent does not merge and does not enable
  GitHub auto-merge. When the automation cannot merge, report the pull
  request and the tested head to the maintainer.
- `scripts/guard_sensitive_paths.py` owns the sensitive paths. A person
  merges a change to `.github/`, `scripts/`, `tests/`, `deploy/`, the
  container files, the dependency files, the secret-scan configuration or
  the release files. Do not narrow that list to unblock a pull request.
- Do not bump a version and do not edit `CHANGELOG.md`. The release pull
  request owns both. A person merges it, and that merge creates the tag and
  publishes the image. A source change does not authorize a release.

## Content boundary

- Do not commit secrets, tokens, webhook URLs, internal host names or private
  addresses. The identifier guard and the secret scan fail the build on them.
- Use synthetic fixtures. Do not use real credentials or data from a live
  deployment in a test, an example or a screenshot.
- Configuration secrets come from environment variables or a `${NAME_FILE}`
  reference, never from a committed file.
- Feed content and inbound webhook payloads are untrusted input.

## Where to read more

- For the merge policy, the review status and the exempt pull-request shapes,
  read `docs/review-and-merge.md`.
- For a new source or a probe change, read `docs/sources.md`.
- For thresholds, routing, delivery and storage settings, read
  `docs/configuration.md`.
- For releases and the code style, read `CONTRIBUTING.md`.
- For the private reporting route, read `SECURITY.md`.

## Reporting

Report each check as PASS, FAIL, NOT RUN or UNAVAILABLE. Keep source, merge,
release and deployment claims distinct.
