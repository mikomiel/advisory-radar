"""Core parsing, routing and rendering tests (synthetic fixtures only)."""

from __future__ import annotations

from advisory_radar import core


class TestIds:
    def test_extract_ids_normalises(self):
        assert core.extract_ids("CVE-2026-1234 and ghsa-abcd-efgh-ijkl, PSA-2026-00001-1") == (
            "CVE-2026-1234",
            "GHSA-abcd-efgh-ijkl",
            "PSA-2026-00001-1",
        )

    def test_dsa_id(self):
        assert core.dsa_id("DSA-6558-1 curl - security update") == "DSA-6558-1"
        assert core.dsa_id("some other title") is None

    def test_php_release_requires_php_host(self):
        assert core.php_release("PHP 8.4.26 released!", "https://www.php.net/releases/8.4.26.php") == "8.4.26"
        assert core.php_release("PHP 8.4.26 released!", "https://evil.example.com/x") is None

    def test_nodejs_slug(self):
        slug = core.nodejs_slug(
            "Wednesday, October 21, 2026 Security Releases",
            "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
        )
        assert slug == "october-2026-security-releases"
        assert core.nodejs_slug("OpenSSL assessment", "https://nodejs.org/en/blog/vulnerability/x") is None

    def test_headline_strips_repeated_summary(self):
        assert core.headline("Title", "Title repeated body") == ("Title", "repeated body")


class TestNeutralise:
    def test_escapes_markdown_and_control_chars(self):
        out = core.neutralise("**bold** [link](https://x.example) \u202e bidi")
        assert "**" not in out.replace("\\*", "")
        assert "\u202e" not in out
        assert "https\\://" in out

    def test_md_collapses_to_one_line(self):
        assert core._md("a\nb\t c") == core.neutralise("a b c")

    def test_cap_never_ends_in_lone_backslash(self):
        assert not core._cap("x" * 50 + "\\", 10).endswith("\\…")

    def test_public_https(self):
        assert core._public_https("https://example.com/a?b=1")
        assert not core._public_https("http://example.com")
        assert not core._public_https("https://user@example.com")
        assert not core._public_https("https://exa mple.com")


class TestFactsParsing:
    def test_cve_org_cna_wins_over_adp(self):
        document = {
            "containers": {
                "cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}}]},
                "adp": [
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {"cvssV3_1": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:L"}},
                            {"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "active"}]}}},
                        ],
                    }
                ],
            }
        }
        cvss, ssvc, remote = core.cve_org_facts(document)
        assert cvss == 9.8 and ssvc == "active" and remote is True

    def test_nvd_prefers_primary(self):
        document = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {"type": "Primary", "cvssData": {"baseScore": 5.0, "vectorString": "AV:L"}},
                                {"type": "Secondary", "cvssData": {"baseScore": 9.0, "vectorString": "AV:N/PR:N/UI:N"}},
                            ]
                        }
                    }
                }
            ]
        }
        assert core.nvd_facts(document) == (5.0, False)

    def test_remote_unauth_token_exact(self):
        assert core.remote_unauth("CVSS:3.1/AV:N/AC:L/PR:N/UI:N")
        assert not core.remote_unauth("CVSS:3.1/AV:NX/PR:N/UI:N")
        assert not core.remote_unauth("CVSS:3.1/AV:N/AC:L/PR:N")  # UI missing
        assert not core.remote_unauth(None)

    def test_parse_php_changelog(self):
        page = (
            '<section class="version" id="8.4.26"><h3><time class="releasedate" datetime="2026-10-21">'
            "2026-10-21</time></h3> Fixed CVE-2026-1111, CVE-2026-2222 and GHSA-aaaa-bbbb-cccc. </section>"
        )
        sections = core.parse_php_changelog(page)
        assert sections["8.4.26"] == ("2026-10-21", ("CVE-2026-2222", "CVE-2026-1111"), ("GHSA-aaaa-bbbb-cccc",))

    def test_parse_nodejs_page(self):
        page = (
            "Updates are now available for the 26.x, 24.x Node.js release lines. Fixed CVE-2026-9999 and cve-2026-1000."
        )
        release = core.parse_nodejs_page(page)
        assert release.cves == ("CVE-2026-9999", "CVE-2026-1000")
        assert release.lines == ("26.x", "24.x")


class TestRouting:
    def facts(self, cvss=None, ssvc=None, epss=None, complete=True, remote=False, skipped=False):
        return core.CveFacts(cvss, ssvc, epss, None, complete, skipped=skipped, remote_unauth=remote)

    def test_critical_reasons_order(self):
        assert core.critical_reason(self.facts(), kev=True) == "kev"
        assert core.critical_reason(self.facts(ssvc="active"), kev=False) == "ssvc"
        assert core.critical_reason(self.facts(cvss=9.5, remote=True), kev=False) == "remote"
        assert core.critical_reason(self.facts(cvss=9.5, epss=0.5), kev=False) == "epss"
        assert core.critical_reason(self.facts(cvss=9.5), kev=False) is None

    def test_level_suppression_needs_complete_data(self):
        assert core.level_of(self.facts(cvss=3.0), kev=False, kev_known=True) == ("suppressed", None)
        assert core.level_of(self.facts(cvss=3.0, complete=False), kev=False, kev_known=True) == ("warning", None)
        assert core.level_of(self.facts(), kev=False, kev_known=False) == ("warning", None)

    def test_judge_picks_deciding_cve(self):
        facts = {"CVE-2026-1": self.facts(cvss=5.0), "CVE-2026-2": self.facts(cvss=9.8, remote=True)}
        verdict = core.judge(["CVE-2026-1", "CVE-2026-2"], facts, frozenset(), True, None)
        assert verdict.tag == "critical"
        assert "CVE-2026-2" in verdict.line

    def test_judge_suppressed_and_warning(self):
        facts = {"CVE-2026-1": self.facts(cvss=2.0)}
        assert core.judge(["CVE-2026-1"], facts, frozenset(), True, None).tag == "suppressed"
        facts = {"CVE-2026-1": self.facts(cvss=6.0)}
        assert core.judge(["CVE-2026-1"], facts, frozenset(), True, None).tag == "warning"

    def test_judge_unscored_never_suppressed(self):
        facts = {"CVE-2026-1": self.facts(complete=False, skipped=True)}
        assert core.judge(["CVE-2026-1"], facts, frozenset(), True, None).tag == "warning"

    def test_metrics_line_english(self):
        line = core.metrics_line(9.8, 0.42, 0.99, "active", True)
        assert "CVSS 9.8" in line and "EPSS 0.42 (p99)" in line and "SSVC active" in line and "KEV" in line


class TestRender:
    def test_render_blocks_and_caps(self):
        title, body = core.render(
            "critical",
            "Some advisory",
            ["CVE-2026-1"],
            "CVSS 9.8",
            "note",
            "https://vendor.example.com/advisory",
            "Vendor **text** with markdown",
            1760000000,
            "feeds.example.com",
            "Vendor Feed",
            "https://feeds.example.com/rss",
        )
        assert title.startswith("CRITICAL:")
        assert "- **Severity:** CVSS 9.8" in body
        assert "- **IDs:** CVE-2026-1" in body
        assert "- **Advisory:** <https://vendor.example.com/advisory>" in body
        assert "- **Source:**" in body
        assert "> " in body  # blockquote excerpt
        assert "Vendor \\*\\*text\\*\\*" in body  # neutralised


class TestState:
    def test_delivered_marks_seen_and_watch(self):
        state = core.new_state()
        entry = {
            "kind": "new",
            "ids": ["CVE-2026-1"],
            "levels": {"CVE-2026-1": "critical"},
            "scores": {"CVE-2026-1": 9.8},
            "source": "s",
            "link": "https://x.example",
        }
        core._delivered(state, entry, 100)
        assert state["seen"]["CVE-2026-1"]["outcome"] == "delivered"
        assert state["watch"]["CVE-2026-1"]["cvss"] == 9.8

    def test_suppressed_records(self):
        state = core.new_state()
        item = core.Item("g", "t", "https://x.example", "s", None, ("CVE-2026-1",))
        verdict = core.Verdict("suppressed", (("CVE-2026-1", "suppressed"),), "CVSS 2.0", "")
        core._suppressed(state, ["CVE-2026-1"], verdict, item, {"CVE-2026-1": 2.0}, 100)
        assert state["seen"]["CVE-2026-1"]["outcome"] == "suppressed"
        assert "CVE-2026-1" in core._claimed(state)


def test_kev_load_fresh_and_fallback():
    from advisory_radar.kev import load_kev

    catalog = b'{"catalogVersion": "x", "vulnerabilities": [{"cveID": "cve-2026-1234"}]}'

    def http_ok(method, url, headers, body):
        assert "If-None-Match" not in headers
        return 200, {"ETag": "e1"}, catalog

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        from pathlib import Path

        cache = Path(tmp) / "kev.json"
        kev, known = load_kev(http_ok, cache, save=True)
        assert known and kev == frozenset({"CVE-2026-1234"})

        # 304 path
        def http_304(method, url, headers, body):
            assert headers.get("If-None-Match") == "e1"
            return 304, {}, b""

        kev2, known2 = load_kev(http_304, cache, save=True)
        assert known2 and kev2 == kev
        # failure with cache falls back
        kev3, known3 = load_kev(lambda *a: (0, {}, b""), cache, save=True)
        assert known3 and kev3 == kev
