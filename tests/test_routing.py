"""Routing tests: the pure matcher, the configuration validator and the queued-entry plumbing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisory_radar import core, pipeline, routing
from advisory_radar.config import DEFAULT_THRESHOLDS, ConfigError, Thresholds, load_config
from advisory_radar.sources import RssSource
from advisory_radar.watchlist import Policy, load_policy

NOW = 1792600000
FEED_URL = "https://feeds.example.com/a"
ENABLED = ["discord", "matrix", "phone"]


def test_a_message_tag_is_one_of_the_levels_the_router_accepts():
    """The closed set the config validator uses must be the set a message can actually carry."""
    assert set(core.LEVEL_LABEL) == routing.SEVERITY_TAGS


class TestSelect:
    """The matcher is a pure function: no state, plugins or HTTP."""

    def test_first_match_wins_rather_than_the_most_specific_rule(self):
        routes = [
            {"match": {"tag": "critical"}, "notifiers": ["phone"]},
            {"match": {"source": "php-releases"}, "notifiers": ["matrix"]},
        ]
        entry = {"tag": "critical", "source_id": "php-releases", "ids": ["CVE-2026-1"]}
        assert routing.select(entry, routes, ["discord"], ENABLED) == (["phone"], "route 1")

    def test_rule_order_is_the_configuration_order(self):
        routes = [
            {"match": {"ids": "CVE-2026-*"}, "notifiers": ["discord"]},
            {"match": {"ids": "CVE-*"}, "notifiers": ["phone"]},
        ]
        assert routing.select({"tag": "warning", "ids": ["CVE-2026-1"]}, routes, (), ENABLED) == (
            ["discord"],
            "route 1",
        )
        assert routing.select({"tag": "warning", "ids": ["CVE-2025-1"]}, routes, (), ENABLED) == (["phone"], "route 2")

    def test_source_matches_the_recorded_source_id(self):
        routes = [{"match": {"source": "php-releases"}, "notifiers": ["matrix"]}]
        entry = {"source_id": "php-releases", "tag": "warning"}
        assert routing.select(entry, routes, (), ENABLED) == (["matrix"], "route 1")
        # An entry without a source id (an escalation, an Adobe bulletin) never matches a source rule.
        assert routing.select({"tag": "warning"}, routes, ["discord"], ENABLED) == (["discord"], "default")
        assert routing.select({"source_id": "other", "tag": "warning"}, routes, (), ENABLED) == (ENABLED, "all")

    def test_tag_matches_exactly(self):
        routes = [{"match": {"tag": "critical"}, "notifiers": ["phone"]}]
        assert routing.select({"tag": "critical"}, routes, (), ENABLED) == (["phone"], "route 1")
        assert routing.select({"tag": "warning"}, routes, (), ENABLED) == (ENABLED, "all")

    def test_product_matches_a_recorded_watchlist_product(self):
        routes = [{"match": {"product": "magento"}, "notifiers": ["matrix"]}]
        assert routing.select({"products": ["magento", "php"]}, routes, (), ENABLED) == (["matrix"], "route 1")
        assert routing.select({"products": ["php"]}, routes, (), ENABLED) == (ENABLED, "all")

    def test_all_four_keys_in_one_rule_must_match(self):
        entry = {"source_id": "php", "tag": "critical", "products": ["magento"], "ids": ["CVE-2026-1"]}
        route = [
            {
                "match": {"source": "php", "tag": "critical", "product": "magento", "ids": "cve-2026-*"},
                "notifiers": ["phone"],
            }
        ]
        assert routing.select(entry, route, ("discord",), ENABLED) == (["phone"], "route 1")
        for key, changes in (
            ("source", {"source_id": "nodejs"}),
            ("tag", {"tag": "warning"}),
            ("product", {"products": ["php"]}),
            ("ids", {"ids": ["GHSA-1"]}),
        ):
            changed = {**entry, **changes}
            assert routing.select(changed, route, ("discord",), ENABLED) == (["discord"], "default"), key

    def test_ids_match_a_wildcard_case_insensitively(self):
        routes = [{"match": {"ids": "cve-2026-*"}, "notifiers": ["phone"]}]
        assert routing.select({"ids": ["CVE-2026-4242"]}, routes, (), ENABLED) == (["phone"], "route 1")
        assert routing.select({"ids": ["GHSA-aaaa-bbbb-cccc"]}, routes, (), ENABLED) == (ENABLED, "all")

    def test_every_key_in_one_rule_must_match(self):
        routes = [{"match": {"tag": "critical", "product": "magento"}, "notifiers": ["phone"]}]
        assert routing.select({"tag": "critical", "products": ["magento"]}, routes, (), ENABLED) == (
            ["phone"],
            "route 1",
        )
        assert routing.select({"tag": "warning", "products": ["magento"]}, routes, (), ENABLED) == (ENABLED, "all")

    def test_default_applies_when_no_route_matches(self):
        routes = [{"match": {"tag": "critical"}, "notifiers": ["phone"]}]
        entry = {"tag": "warning", "source_id": "php-releases"}
        assert routing.select(entry, routes, ["discord"], ENABLED) == (["discord"], "default")

    def test_no_match_and_no_default_reaches_every_enabled_notifier(self):
        routes = [{"match": {"tag": "critical"}, "notifiers": ["phone"]}]
        assert routing.select({"tag": "warning"}, routes, (), ENABLED) == (ENABLED, "all")

    def test_no_routes_reaches_every_enabled_notifier(self):
        assert routing.select({"tag": "critical"}, [], (), ENABLED) == (ENABLED, "all")
        # A default alone does not change that: without a route the feature is off, exactly as before.
        assert routing.select({"tag": "critical"}, [], ["discord"], ENABLED) == (ENABLED, "all")

    def test_min_cvss_reads_the_highest_reported_score(self):
        routes = [{"match": {"min_cvss": 9.0}, "notifiers": ["phone"]}]
        entry = {"tag": "critical", "scores": {"CVE-2026-1": 7.0, "CVE-2026-2": 9.8}}
        assert routing.select(entry, routes, (), ENABLED) == (["phone"], "route 1")
        assert routing.select({"scores": {"CVE-2026-1": 8.9, "CVE-2026-2": None}}, routes, (), ENABLED) == (
            ENABLED,
            "all",
        )

    def test_epss_gte_reads_the_highest_reported_probability(self):
        routes = [{"match": {"epss_gte": 0.3}, "notifiers": ["phone"]}]
        entry = {"epss": {"CVE-2026-1": 0.2, "CVE-2026-2": 0.35}}
        assert routing.select(entry, routes, (), ENABLED) == (["phone"], "route 1")
        assert routing.select({"epss": {"CVE-2026-1": 0.2}}, routes, (), ENABLED) == (ENABLED, "all")

    def test_a_message_without_a_measured_score_never_matches_a_numeric_predicate(self):
        routes = [
            {"match": {"min_cvss": 0.1}, "notifiers": ["phone"]},
            {"match": {"epss_gte": 0.1}, "notifiers": ["phone"]},
        ]
        for entry in (
            {},
            {"scores": None},
            {"scores": []},
            {"scores": {}},
            {"scores": {"CVE-1": None}},
            {"epss": "0.9"},
        ):
            assert routing.select(entry, routes, (), ENABLED) == (ENABLED, "all"), entry
        # A measured zero is a measurement: it is compared rather than ignored, and the bar is above it.
        zeros = [{"scores": {"CVE-1": 0.0}}, {"epss": {"CVE-1": 0.0}}]
        for entry in zeros:
            assert routing.select(entry, routes, (), ENABLED) == (ENABLED, "all"), entry

    def test_kev_matches_the_messages_measured_membership(self):
        routes = [
            {"match": {"kev": True}, "notifiers": ["phone"]},
            {"match": {"kev": False}, "notifiers": ["matrix"]},
        ]
        assert routing.select({"kev": True}, routes, (), ENABLED) == (["phone"], "route 1")
        assert routing.select({"kev": False}, routes, (), ENABLED) == (["matrix"], "route 2")
        # An unmeasured membership -- an unreadable catalogue, or an entry written before the key existed --
        # satisfies neither predicate: the rule describes a fact the message does not have.
        for entry in ({"kev": None}, {}):
            assert routing.select(entry, routes, (), ENABLED) == (ENABLED, "all"), entry

    def test_a_predicate_combines_with_the_string_keys(self):
        entry = {"tag": "critical", "scores": {"CVE-2026-1": 9.8}, "epss": {"CVE-2026-1": 0.4}, "kev": True}
        route = [{"match": {"tag": "critical", "min_cvss": 9.5, "epss_gte": 0.3, "kev": True}, "notifiers": ["phone"]}]
        assert routing.select(entry, route, ("discord",), ENABLED) == (["phone"], "route 1")
        for key, changes in (
            ("tag", {"tag": "warning"}),
            ("min_cvss", {"scores": {"CVE-2026-1": 9.0}}),
            ("epss_gte", {"epss": {"CVE-2026-1": 0.2}}),
            ("kev", {"kev": False}),
        ):
            changed = {**entry, **changes}
            assert routing.select(changed, route, ("discord",), ENABLED) == (["discord"], "default"), key

    def test_a_malformed_predicate_never_matches(self):
        """A hand-built route is not the validator's output: it must not raise, and it must not match."""
        entry = {"scores": {"CVE-2026-1": 9.8}, "epss": {"CVE-2026-1": 0.5}}
        matches = (
            {"min_cvss": "9.0"},
            {"min_cvss": True},
            {"min_cvss": float("nan")},
            {"epss_gte": None},
            {"kev": "yes"},
        )
        for match in matches:
            assert routing.select(entry, [{"match": match, "notifiers": ["phone"]}], (), ENABLED) == (ENABLED, "all"), (
                match
            )

    def test_a_malformed_entry_does_not_raise(self):
        routes = [
            {"match": {"source": "php-releases"}, "notifiers": ["matrix"]},
            {"match": {"product": "magento"}, "notifiers": ["matrix"]},
        ]
        # No source id, a numeric source id, a string products, a number, and no ids at all.
        for entry in ({}, {"source_id": 7}, {"products": "magento"}, {"products": 7}, {"ids": None}):
            assert routing.select(entry, routes, (), ENABLED) == (ENABLED, "all")
        # A bare string ids is not iterated as characters, so "C*" cannot match "CVE-2026-1".
        assert routing.select(
            {"ids": "CVE-2026-1"}, [{"match": {"ids": "C*"}, "notifiers": ["phone"]}], (), ENABLED
        ) == (ENABLED, "all")
        # A malformed rule with no usable match key never swallows a message.
        assert routing.select({"tag": "critical"}, [{"match": {}}, {"notifiers": ["phone"]}], (), ENABLED) == (
            ENABLED,
            "all",
        )


def write_config(tmp_path: Path, extra: str = "") -> Path:
    """A config with three enabled notifiers and one disabled, plus the extra YAML block."""
    path = tmp_path / "config.yml"
    path.write_text(
        "sources: []\n"
        "notifiers:\n"
        "  - id: discord\n    type: webhook\n    url: https://hooks.example.com/d\n"
        "  - id: matrix\n    type: webhook\n    url: https://hooks.example.com/m\n"
        "  - id: phone\n    type: webhook\n    url: https://hooks.example.com/p\n"
        "  - id: disabled-channel\n    type: webhook\n    url: https://hooks.example.com/o\n    enabled: false\n"
        f"{extra}"
    )
    return path


@pytest.mark.parametrize(
    "block",
    [
        'routes:\n  - match: {tag: critical}\n    notifiers: ["${HOOK}"]\n',
        'default: ["${HOOK}"]\n',
    ],
)
def test_a_secret_in_a_selection_is_never_echoed(tmp_path, caplog, block):
    # A selection value can be a reference that expanded to a credential. The configuration error and the CLI
    # log both happen before any redaction filter exists, so neither may contain the value.
    import logging

    from advisory_radar import cli

    secret = "https://hooks.example.net/SUPERSECRET-SELECTION"
    path = write_config(tmp_path, "  - id: hook\n    type: webhook\n    url: ${HOOK}\n" + block)
    environment = {"HOOK": secret}
    with pytest.raises(ConfigError) as caught:
        load_config(path, environment)
    assert secret not in str(caught.value)
    assert "position 1" in str(caught.value)
    with caplog.at_level(logging.ERROR, logger="advisory_radar"):
        assert cli.main(["--config", str(path), "once"], env=environment) == 1
    assert secret not in caplog.text
    assert "not an enabled notifier" in caplog.text


def test_a_route_to_an_overlay_added_notifier_does_not_block_state_recovery(tmp_path):
    from advisory_radar import cli

    path = write_config(
        tmp_path,
        f"  - id: hook\n    type: webhook\n    url: https://hooks.example.com/h\n"
        "routes:\n"
        "  - match: {tag: critical}\n"
        "    notifiers: [ops]\n"
        f"state_path: {tmp_path}/state.json\n",
    )
    overlay = {"notifiers": [{"id": "ops", "type": "webhook", "url": "${OPS_HOOK}"}]}
    # The merged configuration is what startup and reload validate, so the overlay-only id is accepted.
    merged = load_config(path, {"OPS_HOOK": "https://hooks.example.com/o"}, settings=overlay)
    assert merged.routes[0]["notifiers"] == ("ops",)
    # The state-only recovery commands read the YAML without the overlay: they still load, because recovery
    # needs the state path and not a delivery target.
    assert load_config(path, {}, lenient=True).routes[0]["notifiers"] == ("ops",)
    assert cli.main(["--config", str(path), "release-parked"], env={}) in {0, 1}
    assert cli.main(["--config", str(path), "drop-parked"], env={}) in {0, 1}


def test_a_valid_block_loads_into_the_config(tmp_path):
    cfg = load_config(
        write_config(
            tmp_path,
            "routes:\n"
            "  - match: {source: php-releases}\n"
            "    notifiers: [matrix]\n"
            "  - match: {tag: critical}\n"
            "    notifiers: [phone, discord]\n"
            "default: [discord]\n",
        ),
        {},
    )
    assert cfg.routes == (
        {"match": {"source": "php-releases"}, "notifiers": ("matrix",)},
        {"match": {"tag": "critical"}, "notifiers": ("phone", "discord")},
    )
    assert cfg.default_notifiers == ("discord",)


def test_an_empty_default_is_no_default(tmp_path):
    # The overlay clears a YAML default by storing []; that must load as "no fallback", not as an error.
    cfg = load_config(write_config(tmp_path, "default: []\n"), {})
    assert cfg.default_notifiers == ()


def test_an_absent_or_empty_block_changes_nothing(tmp_path):
    for extra in ("", "routes: []\n"):
        cfg = load_config(write_config(tmp_path, extra), {})
        assert cfg.routes == () and cfg.default_notifiers == ()
        assert cfg.notifiers and all(notifier["id"] != "disabled-channel" for notifier in cfg.notifiers)


def test_a_predicate_block_loads_with_typed_values(tmp_path):
    cfg = load_config(
        write_config(
            tmp_path, "routes:\n  - match: {min_cvss: 9, epss_gte: 0.5, kev: false}\n    notifiers: [discord]\n"
        ),
        {},
    )
    assert cfg.routes[0]["match"] == {"min_cvss": 9.0, "epss_gte": 0.5, "kev": False}
    assert isinstance(cfg.routes[0]["match"]["min_cvss"], float), "a whole number is stored as the number it is"


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (
            "routes:\n  - match: {min_cvss: high}\n    notifiers: [discord]\n",
            "routes[1]: match.min_cvss must be a number",
        ),
        (
            "routes:\n  - match: {min_cvss: true}\n    notifiers: [discord]\n",
            "routes[1]: match.min_cvss must be a number",
        ),
        (
            "routes:\n  - match: {min_cvss: 0}\n    notifiers: [discord]\n",
            "routes[1]: match.min_cvss must be above 0 and at most 10",
        ),
        (
            "routes:\n  - match: {min_cvss: 10.5}\n    notifiers: [discord]\n",
            "routes[1]: match.min_cvss must be above 0 and at most 10",
        ),
        (
            "routes:\n  - match: {epss_gte: 0}\n    notifiers: [discord]\n",
            "routes[1]: match.epss_gte must be above 0 and at most 1",
        ),
        (
            "routes:\n  - match: {epss_gte: 1.5}\n    notifiers: [discord]\n",
            "routes[1]: match.epss_gte must be above 0 and at most 1",
        ),
        (
            "routes:\n  - match: {kev: 'yes'}\n    notifiers: [discord]\n",
            "routes[1]: match.kev must be true or false",
        ),
        (
            "routes:\n  - match: {kev: 1}\n    notifiers: [discord]\n",
            "routes[1]: match.kev must be true or false",
        ),
    ],
)
def test_a_bad_predicate_is_refused_by_its_key(tmp_path, extra, message):
    with pytest.raises(ConfigError) as caught:
        load_config(write_config(tmp_path, extra), {})
    assert str(caught.value) == message


@pytest.mark.parametrize(
    "extra",
    [
        "routes:\n  - match: {severity: critical}\n    notifiers: [discord]\n",  # unknown match key
        "routes:\n  - match: {}\n    notifiers: [discord]\n",  # empty match
        "routes:\n  - notifiers: [discord]\n",  # match missing
        "routes:\n  - match: {tag: critical}\n",  # notifiers missing
        "routes:\n  - match: {tag: critical}\n    notifiers: []\n",  # empty list
        "routes:\n  - match: {tag: critical}\n    notifiers: [nope]\n",  # unknown notifier
        "routes:\n  - match: {tag: critical}\n    notifiers: [disabled-channel]\n",  # disabled notifier
        "routes:\n  - match: {tag: ''}\n    notifiers: [discord]\n",  # empty matcher value
        "routes:\n  - match: {tag: critical}\n    notifiers: [discord]\n    extra: 1\n",  # unknown route key
        "routes: {}\n",  # not a list
        "default: [disabled-channel]\n",  # disabled default
    ],
)
def test_an_invalid_routing_block_is_refused(tmp_path, extra):
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, extra), {})


def product_policy(tmp_path: Path):
    watch = tmp_path / "watchlist.json"
    watch.write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [{"id": "magento", "aliases": ["magento"], "domains": ["vendor.example.com"]}],
            }
        )
    )
    return load_policy(watch)


def test_classify_new_records_the_source_id_and_matched_products(tmp_path):
    policy = product_policy(tmp_path)
    state = core.new_state()
    feed_item = core.Item("g1", "Magento security note", "https://vendor.example.com/a1", "notes", NOW - 60, ())
    # The item names no CVE, so the pipeline never calls a lookup this stub would have to answer.
    intel = core.Intel(None, {}, lambda: 0.0, lambda seconds: None)
    core.classify_new(
        state,
        [feed_item],
        intel,
        frozenset(),
        True,
        NOW,
        "vendor.example.com",
        policy,
        source_id="php-releases",
        thresholds=DEFAULT_THRESHOLDS,
    )
    queued = state["pending"][0]
    assert queued["source_id"] == "php-releases"
    assert queued["products"] == ["magento"]


def feed(guid: str, title: str, link: str) -> bytes:
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        "<link>https://feeds.example.com/</link>"
        f"<item><title>{title}</title><link>{link}</link><guid>{guid}</guid>"
        "<description>notes</description><pubDate>Wed, 21 Oct 2026 10:00:00 +0000</pubDate></item>"
        "</channel></rss>"
    ).encode()


def http_for(feed_body: bytes):
    def http(method, url, headers, body):
        if url == FEED_URL:
            return 200, {}, feed_body
        if "cisa.gov" in url:
            return 200, {}, json.dumps({"vulnerabilities": []}).encode()
        return 404, {}, b""

    return http


class RecordingNotifier:
    """Records what it was asked to send and answers with its configured status."""

    def __init__(self, notifier_id: str, status: int = 200) -> None:
        self.id = notifier_id
        self.status = status
        self.sent: list[dict] = []

    def send(self, entry, http) -> int:
        self.sent.append(entry)
        return self.status


class FailingNotifier(RecordingNotifier):
    """Fails delivery, so the queued message stays in the state file where a test can read it back."""

    def __init__(self) -> None:
        super().__init__("fake", status=500)


def pass_config(tmp_path: Path, extra: str = ""):
    """One RSS source, two webhook notifiers and a product watchlist, plus the extra YAML block."""
    watch = tmp_path / "watchlist.json"
    watch.write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [{"id": "magento", "aliases": ["magento"], "domains": ["vendor.example.com"]}],
            }
        )
    )
    path = tmp_path / "config.yml"
    path.write_text(
        "sources:\n"
        f"  - id: php-releases\n    type: rss\n    url: {FEED_URL}\n"
        "notifiers:\n"
        "  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        "  - id: matrix\n    type: webhook\n    url: https://hooks.example.com/m\n"
        f"state_path: {tmp_path}/state.json\n"
        f"watchlist: {watch}\n"
        f"{extra}"
    )
    return load_config(path, {})


def test_the_pipeline_records_the_configured_source_id_on_a_queued_message(tmp_path):
    cfg = pass_config(tmp_path)
    notifier = FailingNotifier()
    code = pipeline.run_pass(
        cfg,
        [RssSource("php-releases", FEED_URL)],
        [notifier],
        http=http_for(feed("g1", "Magento security note", "https://vendor.example.com/a1")),
        clock=lambda: float(NOW),
        sleep=lambda seconds: None,
    )
    assert code == 1
    pending = json.loads(cfg.state_path.read_text())["pending"]
    assert pending[0]["source_id"] == "php-releases"
    assert pending[0]["products"] == ["magento"]


def test_the_pipeline_delivers_through_the_configured_routes(tmp_path):
    cfg = pass_config(
        tmp_path,
        "routes:\n  - match: {source: php-releases}\n    notifiers: [matrix]\ndefault: [fake]\n",
    )
    accepted, routed = RecordingNotifier("fake"), RecordingNotifier("matrix")
    code = pipeline.run_pass(
        cfg,
        [RssSource("php-releases", FEED_URL)],
        [accepted, routed],
        http=http_for(feed("g1", "Magento security note", "https://vendor.example.com/a1")),
        clock=lambda: float(NOW),
        sleep=lambda seconds: None,
    )
    assert code == 0
    assert len(routed.sent) == 1, "the route selects the source's channel"
    assert accepted.sent == [], "a channel the route does not select receives nothing"
    assert json.loads(cfg.state_path.read_text())["pending"] == []


# --- what a predicate reads on a real queue entry -----------------------------------------------


class Facts:
    """A deterministic Intel for ``classify_new``: one answer per CVE, no cache, no network."""

    def __init__(self, **answers: core.CveFacts) -> None:
        self.answers = {key.replace("_", "-"): value for key, value in answers.items()}

    def cves(self, cves, **ignored):
        # ``**ignored``: ``classify_new`` passes its own lookup limit, which this stub has no use for.
        return {cve: self.answers.get(cve, core.CveFacts(None, None, None, None, False)) for cve in cves}


def classified(kev: frozenset[str] = frozenset(), *, kev_known: bool = True) -> dict:
    """One item naming a remote CVE, classified by a stub that measures CVSS 9.8 and EPSS 0.4."""
    state = core.new_state()
    item = core.Item(
        "g1", "CVE-2026-7777 remote bug", "https://vendor.example.net/a", "notes", NOW - 60, ("CVE-2026-7777",)
    )
    intel = Facts(CVE_2026_7777=core.CveFacts(9.8, None, 0.4, None, True, remote_unauth=True))
    core.classify_new(
        state,
        [item],
        intel,
        kev,
        kev_known,
        NOW,
        "vendor.example.net",
        Policy((), (), ()),
        source_id="php-releases",
        thresholds=DEFAULT_THRESHOLDS,
    )
    return state


def test_a_queued_message_carries_the_facts_a_predicate_reads():
    """Only what the classification measured is recorded: no score is ever invented for a predicate."""
    queued = classified(frozenset({"CVE-2026-7777"}))["pending"][0]
    assert queued["scores"] == {"CVE-2026-7777": 9.8}
    assert queued["epss"] == {"CVE-2026-7777": 0.4}
    assert queued["kev"] is True
    # A catalogue that was read, and names no CVE of this message, is a measured "false".
    assert classified()["pending"][0]["kev"] is False
    # An unreadable catalogue measured no membership, so neither predicate may claim it.
    assert classified(kev_known=False)["pending"][0]["kev"] is None


def test_delivery_routes_on_a_measured_score():
    routes = [{"match": {"min_cvss": 9.5, "epss_gte": 0.3, "kev": True}, "notifiers": ("matrix",)}]
    state = core.new_state()
    state["pending"].append(
        {
            "kind": "new",
            "tag": "critical",
            "title": "T",
            "body": "b",
            "ids": ["CVE-2026-1"],
            "cves": ["CVE-2026-1"],
            "levels": {"CVE-2026-1": "critical"},
            "scores": {"CVE-2026-1": 9.8},
            "epss": {"CVE-2026-1": 0.5},
            "kev": True,
            "source": "adv",
            "link": "",
            "source_id": "php-releases",
            "products": [],
        }
    )
    accepted, routed = RecordingNotifier("fake"), RecordingNotifier("matrix")
    assert core.deliver(state, [accepted, routed], None, NOW, routes=routes)
    assert len(routed.sent) == 1 and accepted.sent == [], "the route selects the predicate's channel"

    # The same rule does not take a message that measured less: it falls to every enabled notifier.
    state["pending"].append(
        {**routed.sent[0], "scores": {"CVE-2026-1": 9.0}, "ids": ["CVE-2026-2"], "cves": ["CVE-2026-2"]}
    )
    assert core.deliver(state, [accepted, routed], None, NOW, routes=routes)
    assert len(routed.sent) == 2 and len(accepted.sent) == 1


def test_the_pass_judges_each_source_with_its_own_thresholds(tmp_path, monkeypatch):
    """``pipeline`` hands each source the block resolved for it, never the global one by default."""
    path = tmp_path / "config.yml"
    later = "https://feeds.example.com/later"
    path.write_text(
        "sources:\n"
        f"  - id: php-releases\n    type: rss\n    url: {FEED_URL}\n    thresholds: {{critical_cvss: 7.0}}\n"
        f"  - id: later\n    type: rss\n    url: {later}\n"
        "notifiers:\n"
        "  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        f"state_path: {tmp_path}/state.json\n"
    )
    cfg = load_config(path, {})
    seen: dict[str, Thresholds] = {}

    def spy(state, items, intel, kev, kev_known, now, feed_host, policy, *, source_id="", thresholds=None, **kwargs):
        seen[source_id] = thresholds
        return []

    monkeypatch.setattr(core, "classify_new", spy)

    def http(method, url, headers, body):
        if url in (FEED_URL, later):
            return 200, {}, feed("g1", "Magento security note", "https://vendor.example.com/a1")
        if "cisa.gov" in url:
            return 200, {}, json.dumps({"vulnerabilities": []}).encode()
        return 404, {}, b""

    code = pipeline.run_pass(
        cfg,
        [RssSource("php-releases", FEED_URL), RssSource("later", later)],
        [RecordingNotifier("fake")],
        http=http,
        clock=lambda: float(NOW),
        sleep=lambda seconds: None,
    )

    assert code == 0
    assert seen == {"php-releases": Thresholds(critical_cvss=7.0), "later": DEFAULT_THRESHOLDS}
