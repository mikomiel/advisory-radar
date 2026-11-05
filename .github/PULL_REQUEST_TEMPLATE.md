## Summary

- What changed and why (link the issue: `Closes #N`).
- Config or deployment impact, if any.

## Testing

- [ ] `uv run ruff check .` and `uv run ruff format --check .`
- [ ] `uv run pytest -q`
- [ ] `uv run python scripts/check_no_estate_identifiers.py`
- Manual/dry-run evidence if behavior changed (paste redacted output).

## Checklist

- [ ] Conventional Commits used; no secrets or internal identifiers in the diff (CI enforces both)
- [ ] Docs updated if user-facing behavior changed (README / docs/)
- [ ] No force-push after review started
