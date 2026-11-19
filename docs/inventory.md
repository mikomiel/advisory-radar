# Installed software: inventory and scan evidence

An advisory that mentions a product you watch is not yet an advisory that affects the version you
run. The watchlist decides the first question from text. An imported inventory answers the second
one from versions, and shows it as evidence on the advisory page and in a `/alerts` filter. It is
evidence only: **classification, routing, priority, digests and notifications are unchanged**, and
an installation with no inventory behaves exactly as before and writes no extra state.

## What you can import

One inventory is stored at a time. A new import replaces the previous one as a whole, and a
refused import changes nothing.

| Input | Format read | What it gives |
|---|---|---|
| SBOM | CycloneDX JSON (`bomFormat: CycloneDX`; the subject in `metadata.component` and nested `components` included) | every component that has a package URL |
| SBOM | SPDX 2.x JSON (`spdxVersion: SPDX-2.x`), a package URL in `externalRefs` | every package that has one |
| Scan result | OSV-Scanner v2 JSON (`results[].packages[]`) | the installed packages the scanner reported, the vulnerabilities it matched to them, and its reachability analysis when it ran one; it can confirm that an advisory applies, never that it does not |

Two ways in, both through the same code:

- **Web upload.** `/inventory` has an upload form. It needs a signed-in session and the form
  token like every other state-changing request, accepts one `multipart/form-data` file, and the
  page is never cached.
- **A file in a directory.** Set `inventory.dir` (see [configuration](configuration.md#inventory))
  and write the JSON there from a scheduled job. At the start of each pass the newest `*.json` file
  is read; it is imported when its content differs from the file the last pass handled, so an
  unchanged file does not undo a later upload.

advisory-radar never runs a scanner, never opens a repository or a container image, and needs no
Docker socket. Run the scanner where the code or the image is (in CI, or from cron on the build
host), write its JSON output to a file, and let the file reach advisory-radar by either way above.
Nothing in an imported file is executed, fetched or followed: it is decoded as UTF-8 JSON with the
standard library and read field by field.

### The scanner this version reads

The scan reader is written for the JSON output of **OSV-Scanner v2**. Each entry of
`results[].packages[]` carries `package` (`name`, `version`, `ecosystem`), `vulnerabilities[]` (OSV
records with `id`, `aliases` and `affected`) and, when call analysis ran, `groups[]` whose
`experimentalAnalysis` member (also read as `experimental_analysis`) maps an id to
`{"called": true|false}`. A document that is none of the three formats is refused, and so is a
member of the scan's own structure with the wrong type (`results`, `packages`, `package`,
`vulnerabilities`, `groups`, an id or an alias), with a message that names the field. Two things are
read only to decorate a finding and are never a reason to refuse the file: the OSV record's
`affected` data, where a part that is missing or has another type (for example `ranges`) is skipped
and the finding then shows no fixed version, and a call-analysis entry whose `called` is not `true`
or `false`, which reads as no analysis. A member under another name is not
an error: a scan that names `packages` or its call analysis differently imports with no findings or
no reachability, so check that `/inventory` shows the counts you expect. A default scan lists only
the packages it found something in, so it can confirm that an advisory applies but never clear one:
an absent package is **unknown**, and so is a listed package at a fixed version, because another
installed version of it can be missing from the scan.

**What is and is not verified.** The tests read hand-written fixtures of this layout, not captured
scanner output, and the exact release of the scanner is not pinned. Import the first real scan
from your own pipeline and check what `/inventory` and the advisory pages show before relying on it.

## What the advisory page shows

`/advisories/<id>` gains an **Inventory evidence** row once an inventory exists, apart from the
**Matched products** row that records text relevance. It is one of three results:

| Result | Meaning |
|---|---|
| **applies** (installed X, fixed in Y) | the inventory lists the package at a version inside an affected range of the advisory's OSV record, or a scan reported this advisory for the installed version |
| **not affected** | the inventory is an SBOM (a scan cannot clear an advisory), it lists the package, its version can be compared, the advisory's affected data was read in full and covers every CVE and GHSA id the advisory names, and the version is at or after the fix or before the first affected version |
| **unknown** | anything else, with the reason in the row |

An unknown never claims safety. Its reasons are: no matching component (the inventory does not
list the package, and an SBOM or a scan can omit packages), a component with no version or one that
is not comparable, an ecosystem without a comparator, no comparable affected-version data for the
advisory (or none for every id it names), an inventory too old to confirm that the advisory does
not apply, or a scan, which lists only what it found something in and so cannot rule out another
installed version.

- **Versions are compared** for npm, Go modules and crates.io (semantic versioning) and PyPI (PEP
  440). Another ecosystem is listed but its versions are not compared. A version that does not parse
  completely is unknown, not guessed. Two things in an advisory's own data are not read either, because
  neither shows a version as outside it: a range with no `introduced` event (no event at all, or only
  fixes), and an affected version listed in text that does not parse, which may be the installed one.
  Either never clears an advisory, and the advisory's stored data is marked incomplete, like a cut list
  of versions. Another range or a listed version can still show that the installed version is affected.
- **An advisory that names several packages** is judged by the strongest evidence: one installed
  affected version makes it "applies"; otherwise any version that cannot be compared keeps it
  "unknown". A package an SBOM does not list is taken as not installed only when the import skipped
  no component (one without a package URL, or of a type not read, may be that package) and the
  package's ecosystem is one whose versions are compared; otherwise it stays "unknown".
- **A component the reader cannot place** (no package URL, or a type not read) is counted as skipped
  and shown on `/inventory`, but it is never compared. It can be another copy of a package the SBOM
  lists at a fixed version, so "not affected" says that the listed versions are fixed, not that no
  other copy exists. The subject of a CycloneDX SBOM (`metadata.component`, the software the document
  describes) is read like a component. When it has no readable package URL, it is skipped like any
  other, so an SBOM with such a subject cannot say that a package it does not list is not installed.
- **An SBOM that contradicts itself** (a `version` that differs from the package URL's) records no
  version for that component.
- **Staleness.** After `inventory.max_age_days` (default 30) the inventory can no longer clear an
  advisory: "not affected" becomes "unknown (stale)". An "applies" stays "applies" and says how old
  the inventory is.
- **Reachability** from a scan is shown beside an "applies" as extra evidence: "called", "not
  called", or "unknown" when the scan carries no call analysis for it (a language the scanner could
  not analyse stays unknown, never "not called"). It never turns an "applies" into "not affected"
  and never hides an advisory, including one listed in the KEV catalog, whose alert is delivered
  as before. An SBOM has no reachability to show.
- **Provenance** is shown with every result: the format, the file name, and when it was imported.

`/alerts` gets an **Inventory** filter (`inventory=applies`, `not_affected` or `unknown`) while an
inventory exists. It selects by this evidence and combines with the other filters.

### Where the advisory's affected versions come from

The versions an advisory affects are read from the OSV record the pass fetches for a GHSA id, and
kept in the state (`affected`) from the moment an inventory exists: at most the 1000 newest
advisories, each reduced to its packages, ranges and listed versions, plus the CVE ids the record
aliases. Five consequences:

- **Only an advisory whose GHSA record the pass fetched after the import has comparable data.** The
  pass looks a record up when it classifies a new item that names the GHSA id. An item whose ids
  were all delivered earlier never reaches the lookup, and a record cached in the last 24 hours
  (`CACHE_TTL` in `core.py`) is not fetched again, so it is not stored. Advisories delivered before
  the first import therefore stay "unknown" until a scan names them or a later item names them
  again beside an id that was not delivered yet. Nothing backfills them.
- An advisory known only by a CVE id has no stored record and is **unknown** unless a scan names it.
- **Every id must be covered.** "not affected" needs each CVE and GHSA id the advisory names to be
  the id of a stored record or a CVE that record aliases. A message that also names an advisory
  nothing was stored for, or a CVE the record does not alias, is "unknown": the data of one
  advisory cannot clear its sibling. It can still say "applies". Other identifiers (a vendor's, a
  feed item's guid) name no vulnerability here and do not count.
- A record that lists more than 64 affected versions for a package is cut. Its ranges still count,
  so "applies" still works, but a cut list cannot show that a version is outside it, so that
  advisory cannot say "not affected".
- **The data is a snapshot** of the record at the moment the pass fetched it, and it is not
  refreshed on its own. An advisory that upstream amends later keeps its old affected versions
  here until the pass fetches the record again (see the first point).

## The Inventory page

`/inventory` shows what is stored: format, file name (its last path segment only), SHA-256, size,
import time, whether it came from the upload or the drop directory, the time the document states
about itself, the number of components, findings and skipped entries, whether the inventory claims to
list everything (an SBOM) or only what a scan found, and its age. It also shows the form that
replaces it and the state of the drop directory: the last file looked at and its outcome.

## Limits

An import is refused whole, with a message that names the limit or the field and never the
offending value, when:

| Limit | Value |
|---|---|
| File size | 8 MiB (an upload body may carry 64 KiB of form framing on top) |
| Components of an SBOM (a CycloneDX subject and its nested components included) | 20,000 |
| Packages, findings and call-analysis groups of a scan | 20,000 each, over the whole file |
| Nesting of CycloneDX components (a subject counts as the first level) | 12 levels |
| Package name, package URL, version | 256, 512 and 128 characters |
| Identifiers per finding | 32 |

A scan's packages, findings (the records of `vulnerabilities[]`) and call-analysis groups (`groups[]`)
are counted as the file lists them, repeats included: the same package in two lockfiles, or the same
record twice, counts each time. Each list is counted before it is read, so a file over a bound is
refused before any of that list is processed. The groups of a package are read once, however many
vulnerabilities the package lists, so what a scan costs follows what it lists and not the product of
two of its lists.

An SBOM with no component that has a package URL of a supported type is refused as empty rather than
stored. Package URL types read: `npm`, `pypi`, `golang`, `cargo`, `maven`, `gem`, `nuget` and
`composer`; a component of any other type (an operating-system package, a container image) is
counted as skipped.

A file that trips a fault the reader did not foresee is refused like any other, by either way in:
the message names only the kind of error, never the content of the file, the previous inventory
stays, and neither the pass nor the upload page fails.

At most 1000 entries of the drop directory are examined. Dotfiles, files that do not end in
`.json`, directories and links are ignored, and the chosen file is opened without following a link.
A file that is refused or too large is logged once (not on every pass), the previous inventory
stays, and the pass is not failed. A file that parses but cannot be stored is tried again on the
next pass. A dry run does not look at the directory.

## Where it is stored

The imported document is `inventory.json` beside `state_path`, mode `0600`, written atomically. Like
`settings.json` and the KEV cache it is a file beside `state_path` and not part of the state
document, so it is not shared between instances that share a database. An import replaces the file
whole, so the configuration is refused at start when `state_path` is named `inventory.json` or a
`storage: sqlite:///` path resolves to that file, as it is for the KEV cache, the settings overlay and
the default watchlist. The drop directory's last outcome (`inventory_drop`) and the advisory data
above (`affected`) are in the state document. Deleting `inventory.json` returns the installation to
text-only matching; the recorded advisory data stays in the state and is ignored.

## Keeping it fresh

Write the scan or the SBOM on a schedule shorter than `inventory.max_age_days`, for example from the
pipeline that builds the image, and drop it where the pass reads it. The page shows the age and turns
it into a warning once the inventory is stale.
