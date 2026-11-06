"""Typed reader for the single packaged Security Advisor scope owner."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .state import SourceError

WATCHLIST = Path("watchlist.json")  # default; config.py passes the real path


@dataclass(frozen=True)
class Product:
    id: str
    aliases: tuple[str, ...]
    domains: tuple[str, ...]
    metadata_only: bool


@dataclass(frozen=True)
class Policy:
    debian_source_packages: tuple[str, ...]
    excluded_products: tuple[str, ...]
    products: tuple[Product, ...]


def _strings(value: object, *, empty: bool = False) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not value and not empty)
        or any(not isinstance(item, str) or not item.strip() or item != item.strip() for item in value)
    ):
        raise SourceError("watchlist requires nonempty string arrays")
    if len(value) != len(set(value)):
        raise SourceError("watchlist contains duplicate values")
    return tuple(value)


def load_policy(path: Path = WATCHLIST) -> Policy:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SourceError("watchlist cannot be read") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "debian_source_packages", "excluded_products", "products"}
        or document["schema"] != "security-watchlist.v1"
    ):
        raise SourceError("watchlist schema is invalid")
    rows = document["products"]
    if not isinstance(rows, list):
        raise SourceError("watchlist products are invalid")
    products = []
    ids = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or not {"id", "aliases", "domains"} <= row.keys()
            or set(row) - {"id", "aliases", "domains", "metadata_only"}
        ):
            raise SourceError("watchlist product fields are invalid")
        identifier = row["id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9-]+", identifier) or identifier in ids:
            raise SourceError("watchlist product identity is invalid")
        metadata_only = row.get("metadata_only", False)
        if type(metadata_only) is not bool:
            raise SourceError("watchlist metadata policy is invalid")
        domains = _strings(row["domains"], empty=True)
        if any(not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)+", domain) for domain in domains):
            raise SourceError("watchlist domain is invalid")
        products.append(Product(identifier, _strings(row["aliases"]), domains, metadata_only))
        ids.add(identifier)
    packages = _strings(document["debian_source_packages"])
    excluded = _strings(document["excluded_products"], empty=True)
    if any(not re.fullmatch(r"\*|[a-z0-9][a-z0-9.+-]*\*?", package) for package in packages):
        raise SourceError("watchlist package pattern is invalid")
    return Policy(packages, excluded, tuple(products))


def default_policy(path: Path | None = None) -> Policy:
    """The packaged default; config.py passes the configured path."""
    return load_policy(path or WATCHLIST)
