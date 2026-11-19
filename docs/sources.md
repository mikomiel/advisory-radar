# Sources
Five source types are built in, and the table below is the whole catalogue: a
**required** key has no default, an **optional** one may be left out. The same
catalogue is on the `/sources` page of the web UI and in
`advisory-radar sources list`, which needs no config file.

`advisory-radar sources test <id>` fetches one *configured* source, prints its
items, one `problem:` line for each part of its input the source could not read, and
whether its window was truncated. It exits non-zero when the window was truncated, when
a problem was printed, or when the fetch failed. It sends no notification and writes no
state, so it is safe to run while the service is polling. A `webhook` source is read from an
empty inbox, so it prints no items: the command checks configuration, not intake.

The same probe is a button. `/config` can add a source without touching the file:
pick a type, fill the keys it declares, and press **Test the new source** — the
probe performs the fetch a pass performs, shows the entry count, the first entries
or the error, a warning for any part of its input the source could not read, and writes
nothing. A probe of an unsaved source reports a missing
`${NAME}` by name, never its value, and offers to save the source it just fetched.
Every configured row has its own **Test** button, and `/sources` shows one health
line per enabled source — the last attempt, the last success, the entries in that
window and the error that attempt reported — with the same numbers exported as
metrics (see `deployment.md`).

An `rss` source is one URL and needs no format key. RSS 2.0, Atom, RSS 1.0 (RDF) and
JSON Feed are recognised from the document itself, and JSON Feed is told apart from the
FreshRSS GReader export by its `version` URL rather than by having an items list. A URL
that answers an HTML page instead is followed through that page's
`<link rel="alternate">` autodiscovery exactly once; the page is not crawled, and no
validator is stored for it, because a page's `ETag` says nothing about the feed behind
it. Conditional GET still applies to a feed that answers directly. The advertised feed
is held to two rules, both checked **before** it is fetched and neither relaxed by
`allow_private_sources`: it must share the page's own origin — the same scheme, host and
port — and it must not resolve to a loopback or private address. The first is the
containment: the page's own host is the one the operator already chose, so discovery
cannot redirect the reader to a host an attacker picked, and a feed genuinely served from
another host is configured directly. The second keeps the existing guard rail against a
router page or the metadata service, because the page — not the operator — chose that URL.

A feed is read whole, so what a publisher can make this reader spend is bounded. A body above
8 MiB is refused unread, a feed or a page alike and whatever format it claims, a FreshRSS
export included (the HTTP layer itself stops any response at 64 MiB). Markup nested more than
100 levels deep inside an entry, and an OPML folder tree that deep, is refused as an
unreadable document instead of followed. A document refused for either reason fails that
source's pass and is reported on `/sources`, like any other feed this reader cannot read. A
date that names no zone (an ISO 8601 date without an offset, a bare date, an RFC 822 date
without a zone or with `-0000`) is read as UTC, never in the host's local zone, so the same
feed is dated the same way on every host.

Every source may carry `interval: 30m` (the same `<n><s|m|h>` spelling as
`poll_interval`, and at most `168h`, seven days, for both, so a typo cannot park the scheduler)
to be fetched at its own pace; without one it follows the global
interval. The interval throttles the fetch only: re-evaluation, escalation and delivery
still run for every source on every pass, so a slow feed never delays an alert. A fetch
that fails is retried on the next pass instead of waiting out the interval, so one
transient error cannot become an outage. `interval` is accepted by every kind in
addition to the keys in the table.

Every HTTP request the program makes, a source fetch as much as a lookup or a notification sent
over HTTP, ends when one network operation (connect, TLS handshake, send, one receive) waits 30
seconds, and when the server's answer is still not complete 120 seconds after the connection
attempt began. The second limit is the one that matters for a server that answers a few bytes
at a time: the first never trips for it, and the pass, with the state lock it holds, would wait
as long as the server liked. A request ended this way is an unreachable source for that pass,
like any other network error. Every wait for the server's answer is cut at what is left of the
120 seconds: the status line, each header, the size line and the trailer of a chunked body, and
the body itself. A server that sends any of those a few bytes at a time is therefore ended at
120 seconds, and so is one that says nothing. The connection attempt (the TCP connect and the
TLS handshake) and the sending of the request are not waits for the answer: they have the
30-second limit alone, and a connection attempt that has used up the whole budget ends the
request at its first wait for the answer.

A document is read whole or not at all: a source or a lookup whose body cannot be received in
full is unreachable for that pass. A notification is judged by its status alone, so a receiver
that has answered and then stalls or resets while sending its body keeps its status: reporting
it as unreachable would make the same message go out again. Email through SMTP is not an HTTP
request and has the 30-second limit alone.

A pasted OPML 2.0 subscription list is imported with **Add feeds from OPML** in the same
section: every `<outline>` with an `xmlUrl` becomes an `rss` source, folders are
descended into, and a feed already configured or repeated in the document is skipped and
counted. Each URL is checked exactly as a single add is, and a document that cannot be
read, holds no feed, or names one unusable address is refused without writing anything.
The outline title is not stored: the existing URL-host id derivation and the watch tag
keep the meanings they already have. A document is someone else's text, so it is judged first:
one import takes at most 100 feeds (split a larger list and import the parts), and a feed URL
that contains `$` refuses the whole document, because an imported `${NAME}` would read a secret out
of the environment on the strength of a pasted file. A literal `$` is written `%24`. Each
distinct feed URL is resolved at most once, before the settings lock is taken, so a slow lookup
does not stall other saves.

A source added on that page may carry `$` in its `url` only as one whole `${NAME}` reference
that the YAML lists under `overlay_references`; any other `$` is refused (write it as `%24`), as
`configuration.md` explains. It may not point into a private network either: the form refuses
an address that resolves to loopback or to an internal range, unless the YAML sets
`allow_private_sources: true`. A configured YAML source is never subject to the
check, so a FreshRSS or changedetection.io instance on the LAN stays a supported
target, and a probe of a source the page added is judged whether or not that source
is enabled — switching it off is allowed without the check, probing it is not.

That check is a guard rail against pointing this instance at a router page by
mistake, not an isolation boundary. The pass resolves the name again when it
fetches, so a name whose answer changes is followed, and the UI token is a
full-trust credential besides: it can read every advisory, rewrite every
notification target and run a pass. Anyone who must not reach the internal network
must not hold it, and the isolation that does hold is a network one: run the
container where it has no route to what it must not reach.

Every origin the two pages show — a probe's answer and a configured source on
`/sources` — every title a probe shows, and every id are all restricted: the origins
and titles are redacted against the secrets the configuration resolved, and an id is
a name. The validator refuses a whole `${NAME}` reference in one, and refuses an id
composed from a variable that supplies a credential anywhere in the same
configuration (`id: feed-${CD_TOKEN}` beside `api_key: ${CD_TOKEN}`, or beside
`url: …?token=${CD_TOKEN}`), because an id
appears in routes, logs, the state and — for a source — a metric label on the
unauthenticated `/metrics` endpoint. A name composed from a naming variable
(`tenant-${X}`) stays allowed, and the value it composes is what those places show.
An id the overlay adds must be literal text, since there is no file to read it
from.

| Kind | Summary | Required keys | Optional keys |
|---|---|---|---|
| `rss` | Any RSS 2.0, Atom, RSS 1.0 or JSON Feed URL, or a page that advertises one, read in one conditional GET. | `url` | `tag`, `enabled` |
| `freshrss` | A FreshRSS shared query, read through its GReader JSON export. | `url`, `token` | `user`, `enabled` |
| `changedetection` | Poll a changedetection.io instance; every watch whose page changed becomes one item. | `url`, `api_key` | `tag`, `enabled` |
| `webhook` | Items pushed to this instance's `/webhooks/<id>` endpoint, read from the state inbox. | — | `tag`, `enabled` |
| `csaf` | A vendor's CSAF 2.0 provider directory, read through its `changes.csv`; each new or revised advisory becomes one item of vendor statements. | `url` | `enabled` |

An accepted key is not always read by every kind: `tag` scopes a
changedetection.io poll to one watch tag and the other kinds ignore it, so the
column is only meaningful there; `user` names the FreshRSS account; `interval`
thins that source's polling; and `enabled: false` keeps an entry in the file
without building it. Disabling is not removing: a disabled source keeps the work it already
captured -- carried candidates, feed validators, changedetection.io cursors and CSAF cursors -- and
resumes from them when it is enabled again, while deleting the entry discards that stored work deliberately,
cursors included, so a re-added source is read afresh. A declared id that cannot be resolved (its
`${NAME}` reference has no value) keeps stored work rather than assuming removal, because the pass
cannot tell which stored source the entry stands for. An RSS/Atom/JSON Feed and a changedetection.io poll return
the whole response, so the FreshRSS GReader export is the only built-in that
reports a truncated window. A `csaf` source reports what it could not read instead, as
[described below](#csaf-directories).

## CSAF directories

A `csaf` source reads one provider directory of the Common Security Advisory Framework (CSAF)
2.0, the JSON advisory format a vendor publishes for machines. `url` is the directory that
holds `changes.csv` and the documents it lists; a missing trailing slash is added.

```yaml
sources:
  - id: redhat-csaf
    type: csaf
    url: https://security.access.redhat.com/data/csaf/v2/advisories/
```

**What is pinned.** The standard is CSAF 2.0, OASIS Standard of 18 November 2022, and a
document must declare `csaf_version` `2.0`. Two profiles are read, `csaf_security_advisory`
and `csaf_vex`; any other `document.category` (`csaf_base`, for one) is refused, because it
may carry no product status at all. Every document is checked against the standard's JSON
schema before anything in it is used. The schema is part of the package, and so are the three
FIRST CVSS schemas it points to; none is fetched at run time. They live in
`src/advisory_radar/csaf_schema/`, unmodified, with their licence texts in `NOTICE.md`, and
`tests/test_csaf.py` pins each by its sha256. Retrieved on 2026-11-19:

- `csaf_json_schema.json` from
  `https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json`,
  sha256 `29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262`
- `cvss-v2.0.json` from `https://www.first.org/cvss/cvss-v2.0.json`,
  sha256 `cd1a7c0815b7a47dc12fb7dded10622b96d562841f7bc6d2d8765c5d937a28f2`
- `cvss-v3.0.json` from `https://www.first.org/cvss/cvss-v3.0.json`,
  sha256 `b2b587e5dfa6d9a4be89e25cb593df04f14e7ffbe8fe5b167ceee17b6097d919`
- `cvss-v3.1.json` from `https://www.first.org/cvss/cvss-v3.1.json`,
  sha256 `77ff3df106e4588e2bb5c9cf0237f962c62d35c5002443c4bf7cc7ca16ee171f`

**The first provider is Red Hat.** Its provider metadata, at
`https://security.access.redhat.com/data/csaf/v2/provider-metadata.json` (role
`csaf_trusted_provider`), lists two directories. Configure the first:

- `https://security.access.redhat.com/data/csaf/v2/advisories/`: one
  `csaf_security_advisory` document per erratum. This is the one to use.
- `https://security.access.redhat.com/data/csaf/v2/vex/`: one `csaf_vex` document per CVE, much
  more of them and each larger. It is read the same way, but it is the likelier of the two to
  report that it is behind ([what one pass reads](#csaf-directories)).

When these were read on 2026-11-17, `advisories/changes.csv` listed 31,966 documents (1.7 MB) and
`vex/changes.csv` listed 76,771 (4.2 MB). Over the newest 14 days that list anything, the
advisories index named a median of 1,140 documents a day and 9,940 on its busiest day; the `vex`
index a median of 887 and 16,525. On 2026-11-19, 80 advisories spread over the newest 20,000 rows of
the advisories index had a median size of 90 KiB, a mean of 0.74 MiB and a largest of 8.6 MiB, and
each took 0.1 s to download on average. Two of the 80 were above the 8 MiB cap, so a document
that large is a problem like any other ([what fails](#csaf-directories)); one advisory among the
newest rows was 22.5 MiB (`RHSA-2026:92510`), and with the cap lifted for a test the reader parsed
and checked it in 1.1 s at a peak of 127 MiB of memory. The cap is `csaf.MAX_DOCUMENT_BYTES`. The
synthetic fixtures in `tests/` are the tests; real documents were parsed offline, to check the
reader against the provider's real layout. The `csaf_vex` one (`CVE-2026-110859`, revision 3) defines
32 of its 1,882 product ids more than once, each time with the same name. The standard forbids
that; the reader accepts it, and refuses an id that has two names.

**What the first provider writes into a document.** Checked on 2026-11-19 in 12 advisories (the
oldest from 2020) and in the one VEX document: `version` is `3` in every one, and
`revision_history` has exactly three entries whose summaries are `Initial version`, then
`Last updated version` (advisory) or `Current version` (VEX), then `Last generated version`.
`current_release_date`, the date of `generator` and the date of the last entry are one and the same
instant, the time the provider's generator wrote the file. That instant fell on 2026-11-19 for all
12 advisories (2026-11-18 for the VEX document), while the middle entry was dated 2020-07-28 in one,
2024-10-01 in another and 2026-11-11 to 2026-11-13 in nine more. So neither the version nor
`current_release_date` says when an advisory changed, and the reader does not use them for that
([what identifies and dates an item](#csaf-directories)).

**What one pass reads.** It reads `changes.csv` once, then the documents it has not read, oldest
first: at most 200, and it starts no new one after 120 seconds, counted from its first request, so
a slow provider cannot hold a pass for long. The first document of a pass is always read, so a
provider that answers slowly still makes progress. A new source starts at the newest 20 documents
the index lists, because older ones are history and not news
([first sight](configuration.md#first-sight-backlog-and-outages)). What a pass does not reach is read
by the next one, in order, and nothing is skipped. A document the vendor revises is listed again
with a later time and is read again. Rows listed at one second are all read, and a row listed late
within a second already read is still read. The cursor, the document being retried and the documents
given up on are kept in the state under `csaf`, keyed by a digest of the directory URL, which is
never written there; pointing a source id at another directory starts it over.

**Falling behind is reported.** The limit is 200 because 20 was too few. The advisories index of
2026-11-19 lists 24,719 documents last changed from 2026-11-05 on, 8,758 of them in the single
hour from 05:00 UTC on 2026-11-07. Replayed through passes every 15 minutes (the default
`poll_interval`), 20 documents a pass ended 70% of the passes more than 12 hours behind, with a
median wait of 57 hours and a longest of 6.1 days, while 200 a pass never left a document waiting
more than 10.2 hours. Passes an hour apart do not keep up even with 200 (a longest wait of 45
hours), so keep the default interval for a `csaf` source. A source whose oldest unread document was
listed more than 12 hours ago says so: `behind: <n> listed document(s) not read yet, the oldest
listed <age> ago` is the first line of its problems, and the source is down in the ways described
under [what fails](#csaf-directories) until a pass leaves nothing older than that unread. A source
that was disabled for a while reads what was listed meanwhile at the same pace, and says it is
behind until it has caught up.

The limit of 12 hours is half of the day by which the pipeline still counts an item as news after an
outage ([first sight](configuration.md#first-sight-backlog-and-outages)), and it is the reason a late
read is not lost. A source that is down keeps the time of its last success. An item is history only
when it is older than 7 days and was published more than a day before that time, so a document read
a week and more after it was listed is still delivered, as long as the source was down all that
time. `tests/test_csaf_source.py` runs this through whole passes, and pins the limit to at most
half of that day.

**What identifies and dates an item.** An item is identified by the document's id and a 16-digit
hexadecimal digest of the statements it carries, the same however the vendor orders them. A revision
that says something else is a new item, and a file the provider rewrites to say the same thing is
not. The vendor's version number is shown in the summary and relied on for nothing. An item is
dated by when the vendor last changed the document. That is `current_release_date`, except for a
document whose `revision_history` ends in an entry with the summary `Last generated version`, the
first provider's own mark: such a document is dated by the entry before it. Without this, every
advisory the provider rewrites, from 2020 or last week, would arrive dated that minute, and one
the source had not seen before would be delivered as news, although an item first seen more than 7
days after its date is history ([first sight](configuration.md#first-sight-backlog-and-outages)).
If the date to use is not an RFC 3339 date-time with a zone, the document is refused as
`schema: <where>: not an RFC 3339 date-time with a zone`.

**What an item says.** The title is the document's title. The summary is written in the
[message language](configuration.md#message-language):
`Vendor statements, revision <version> of <id>; not a check of your installed versions.`, then the
statements, in the vendor's own status words, for each CVE the document concerns, for example
`CVE-2026-0001: fixed: Widget 2.0 (2); known_not_affected (1)`. A name is a product, a component
of a product is listed under the product it belongs to, and the number is how many product ids of
the document stand behind that name. The statements are cut at 300 characters. The source line
names the publisher and the exact URL of the document read; the link is the document's own `self`
web reference when it has one.

**Vendor statements are not local matches.** An item reports what the vendor says about its own
products. This source compares no version with anything installed or configured here, so an item
is never a finding that something you run is affected. The watchlist scope judges an item by its
title, summary and publisher like any other source's, so a product name in the statements can bring
a document into scope, and one that only appears after the 300-character cut cannot.

**A not-affected statement affects nothing else.** A document claims only the CVEs it says
something other than `known_not_affected` about. A `known_not_affected` statement therefore never
raises an alert for its CVE and never takes the place of another source's alert for it (an alert is
raised once per CVE, for the first item that names it). A document that says only that makes no
item and is not read again. Not-affected products are counted in the statements and never named,
and a status only ever applies to the vulnerability it sits under.

**What fails, and how it shows.** A source never turns a failure into an empty window.

- An index that cannot be read or trusted fails the pass and leaves the cursor where it was:
  unreachable, any status but 200, over 16 MiB, not UTF-8, not two-column CSV, a path that is not a
  plain relative `.json` name below the directory, a time that is not an RFC 3339 date-time with a
  zone or lies more than 10 minutes ahead, a path listed twice, or no rows at all. The whole index
  is refused rather than read around, since a skipped row is a document that is never read.
- A document that cannot be read or validated (`HTTP <status>`, unreachable, over 8 MiB, not a JSON
  object, `schema: <where>: <what>`, another profile, a product id used but not defined, one id
  defined with two names, or a relationship's product defined a second time) stops the pass at that
  document, and the next pass reads it again, up to 3 attempts. The third failure gives up on that
  revision, and the pass goes on with the documents after it. The documents read before it are
  delivered in the same window.
- A source that has fallen behind (see above) is down in the same ways, with its `behind:` line
  first.
- Either way the source is down in `/sources`, in `advisory_radar_source_up`, in the exit code
  of the pass and in `sources test`, with one line per document, for example
  `2026/example-2026_0002.json: schema: document: 'title' is a required property (given up after 3
  attempt(s))`. A given-up document stays listed until the vendor publishes a newer revision of it
  or 30 days pass; five are named and the rest counted. A source that is down is fetched on every
  pass, whatever its `interval`.

**Safety of what is read.** A path comes from the index and is only ever appended to the configured
directory, so a provider cannot make this source read anywhere else, and no redirect is followed.
Document text is untrusted: it is checked, size-capped (an index at 16 MiB, a document at 8 MiB) and
parsed as data, and a title, publisher or product name is cut and shown without control characters.
The exact URL of a document is printed in alerts, so the directory URL may not carry a credential: a
user name or password, a query and a fragment are refused when the source is built, and a secret
inside the path cannot be told from the rest of it and would be printed.

**What checking a document costs.** The time to check a document is in proportion to its size. The
schema asks for unique elements in several arrays, and the library compares objects one pair at a
time, which took 258 seconds for 32,000 ids (a 3 MB document) and would have taken hours at the
cap. That one check is replaced by a set of canonical texts (`csaf._unique_items`), which accepts
and refuses the same arrays (the arrays the schema asks to be unique hold strings, or objects of
strings). Measured on a developer machine with a real document padded to
size: 32,000 distinct ids take 0.4 s, a document of 7.6 MB 1.2 s, and 400,000 short product ids in
one array (5.5 MB) 3 s, which is about 5 s at the cap. A pass that meets its time limit stops
before the next document, so one pass takes at most the limit plus one document.

**Not done.** This source does not verify OpenPGP signatures or checksums, discover providers
through provider metadata or ROLIE (configure the directory), keep the statements after the pass,
or compare them with an inventory. It reads only the vulnerabilities that name a CVE, and does not
interpret CPE or purl identifiers, flags or threats. It sends no conditional request, so each pass
reads the whole index. An alert is raised once per CVE, so a revision that only changes the
statements about a CVE already reported is read but does not report it again.

## Inbound webhook payloads

`/webhooks/<id>` accepts a JSON object in the generic form (`title`, plus
`summary`/`text`/`body`, `link`/`url`, `guid`, `source`, `ids`) or the
changedetection.io native form, recognised by `watch_uuid` or `watch_url`
(`watch_title`, `watch_url`, `diff`, `ids`). The generic form requires a
non-empty `title`; the native form titles itself from `watch_title`, then
`watch_url`, then `change`. That `change`, and the summary `page changed` of a native payload
with no `diff`, are the service's own words and follow the
[message language](configuration.md#message-language).

`ids` is optional in both forms and may be omitted, `null` or empty. A non-empty
value must be a list of strings, and each element must be exactly one identifier
in the grammar the text extractor already applies: a CVE (`CVE-<year>-<number>`),
a GitHub advisory (`GHSA-xxxx-xxxx-xxxx`) or a Proxmox advisory
(`PSA-<year>-<number>-<revision>`). Case is ignored and the value is normalised;
duplicates and ids already present in the text are dropped. The validated ids are
merged with the ids extracted from the title, summary/diff and link, and the
queued entry carries the union in `explicit_ids`. The pass reads that field as
the item's identifiers, so a CVE declared only in `ids` receives the same
enrichment, scoring and ID routing as one written in the text.

The endpoint refuses, with a `{"error": ...}` body and before it reads or writes
the state document: a body that is not UTF-8 JSON (400); a body nested more
than 100 levels deep, including a deeply nested value inside an object (400); a
body that is not a JSON object -- a list, string, number or `null` (400); a
text field carrying an unpaired surrogate, which cannot be encoded for the
default-guid hash (400); and an `ids` value that is not a list of strings,
holds a string that is not exactly one supported identifier, or holds a
non-string (400). A JSON object with no `title` is 422. `guid` is kept verbatim
and escaped when rendered, so a legacy sender that supplies a lone surrogate
there keeps working. The bearer secret, the 64 KiB body bound and the inbox
limit are unchanged.

Two answers say nothing about the payload: they mean "not queued, try again". While a pass
holds the state lock (it holds it for its whole transaction, so for as long as the pass runs)
the endpoint answers `503` with `{"error": "busy, retry"}` and `Retry-After: 30`, and when the
inbox is full it answers `429` with `Retry-After: 60` until a pass has processed some entries.
Neither response queues anything and this side keeps no copy, so the retry belongs to the
sender: a sender that treats a `503` or a `429` as final loses that advisory. Retry after the
`Retry-After` interval. A `400`, `401`, `404`, `413` or `422` will not succeed when the same
request is sent again.

