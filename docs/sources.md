# Sources
Four source types are built in, and the table below is the whole catalogue: a
**required** key has no default, an **optional** one may be left out. The same
catalogue is on the `/sources` page of the web UI and in
`advisory-radar sources list`, which needs no config file.

`advisory-radar sources test <id>` fetches one *configured* source, prints its
items and whether its window was truncated, and exits non-zero when it was or
when the fetch failed. It sends no notification and writes no state, so it is
safe to run while the service is polling. A `webhook` source is read from an
empty inbox, so it prints no items: the command checks configuration, not intake.

The same probe is a button. `/config` can add a source without touching the file:
pick a type, fill the keys it declares, and press **Test the new source** — the
probe performs the fetch a pass performs, shows the entry count, the first entries
or the error, and writes nothing. A probe of an unsaved source reports a missing
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
120 seconds, and so is one that says nothing. The connection attempt shares the same 120
seconds: a host name that resolves to several addresses is tried one address after another,
each for at most 30 seconds or what is left of the 120, and the TLS handshake gets what the
connect left. Several unreachable addresses therefore cannot hold a request for 30 seconds
each. Resolving the host name is a wait no limit here covers, because the system resolver
offers none. The sending of the request is not a wait for the answer: it keeps the 30-second
limit and is not cut at the 120 seconds.

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

An accepted key is not always read by every kind: `tag` scopes a
changedetection.io poll to one watch tag and the other kinds ignore it, so the
column is only meaningful there; `user` names the FreshRSS account; `interval`
thins that source's polling; and `enabled: false` keeps an entry in the file
without building it. Disabling is not removing: a disabled source keeps the work it already
captured -- carried candidates, feed validators and changedetection.io cursors -- and resumes from
them when it is enabled again, while deleting the entry discards that stored work deliberately,
cursors included, so a re-added source is read afresh. A declared id that cannot be resolved (its
`${NAME}` reference has no value) keeps stored work rather than assuming removal, because the pass
cannot tell which stored source the entry stands for. An RSS/Atom/JSON Feed and a changedetection.io poll return
the whole response, so the FreshRSS GReader export is the only built-in that
reports a truncated window.

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

