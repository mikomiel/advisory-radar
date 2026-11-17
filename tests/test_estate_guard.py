"""The estate-identifier guard fails closed: what it cannot read or classify is a failure, not a pass.

The guard is a public repository's last check against internal host names, addresses and credential-store names
reaching a commit. Each test runs a copy of the script inside a throwaway repository, so the exit code and the
message are the contract that CI sees. The fixtures assemble every identifier at run time: this file is tracked
too, and a literal identifier in it would fail the guard that it tests.
"""

from __future__ import annotations

import codecs
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_no_estate_identifiers.py"

#: One sample per pattern, built from fragments so that no line of this file matches the guard's patterns.
SAMPLES = {
    "private domain": "kicia" + "team" + ".eu",
    "private IPv4 range": ".".join(("192", "168", "7", "9")),
    "internal container id": "CT" + "123",
    "live webhook URL": "discord" + ".com/api/webhooks/1/token",
    "credential store name": "infi" + "sical",
    "internal secret path": "/etc/ops" + "-notify/token",
    "internal proxy host": "agent" + "-vault",
}
CONTAINER = SAMPLES["internal container id"]
#: The byte order mark each wide encoding starts with when a Windows tool writes it (PowerShell's redirection writes
#: UTF-16LE with one). Without the mark the same text is just as valid, and the guard must read it as well.
BYTE_ORDER_MARKS = {
    "utf-16-le": codecs.BOM_UTF16_LE,
    "utf-16-be": codecs.BOM_UTF16_BE,
    "utf-32-le": codecs.BOM_UTF32_LE,
    "utf-32-be": codecs.BOM_UTF32_BE,
}


def environment(home: Path) -> dict[str, str]:
    """No inherited ``GIT_*`` variable (a hook would set ``GIT_DIR``) and no user or system git configuration."""
    clean = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    clean.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / "xdg"),
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
    )
    return clean


class Repository:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.env = environment(root.parent)
        (root / "scripts").mkdir(parents=True)
        shutil.copy(SCRIPT, root / "scripts" / SCRIPT.name)
        self.git("init", "-q")

    def git(self, *args: str, stdin: bytes | None = None) -> str:
        done = subprocess.run(
            ["git", "-C", str(self.root), *args], input=stdin, capture_output=True, env=self.env, check=True
        )
        return done.stdout.decode()

    def track(self, name: str, content: bytes | str = "") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        self.git("add", "--", name)
        return path

    def link(self, name: str, target: str) -> None:
        (self.root / name).symlink_to(target)
        self.git("add", "--", name)

    def run(self, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", str(self.root / "scripts" / SCRIPT.name)],
            cwd=self.root,
            env=self.env if env is None else env,
            capture_output=True,
            text=True,
        )


@pytest.fixture
def repo(tmp_path: Path) -> Repository:
    repository = Repository(tmp_path / "work")
    repository.track("README.md", "a clean file\n")
    return repository


def test_a_clean_repository_passes(repo: Repository):
    done = repo.run()
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("OK: no internal identifiers in ")


@pytest.mark.parametrize("label", sorted(SAMPLES))
def test_every_pattern_is_reported_with_its_file_and_line(repo: Repository, label: str):
    repo.track("notes.txt", f"first line\nreach it at {SAMPLES[label]} today\n")
    done = repo.run()
    assert done.returncode == 1
    assert f"notes.txt:2: {label}" in done.stderr


def test_a_path_name_that_carries_an_identifier_fails(repo: Repository):
    repo.track(f"docs/{CONTAINER}-runbook.md", "nothing sensitive inside\n")
    done = repo.run()
    assert done.returncode == 1
    assert "internal container id" in done.stderr and "path name" in done.stderr


def test_a_symlink_target_is_read(repo: Repository):
    # a link is stored as its target text; following it on disk would find nothing, or the wrong file
    repo.link("current", SAMPLES["internal secret path"])
    done = repo.run()
    assert done.returncode == 1
    assert "current:1: internal secret path" in done.stderr


def test_a_file_that_is_not_utf8_is_still_scanned(repo: Repository):
    repo.track("latin1.txt", b"caf\xe9 " + SAMPLES["private domain"].encode() + b"\n")
    done = repo.run()
    assert done.returncode == 1
    assert "latin1.txt:1: private domain" in done.stderr


def test_a_svg_is_scanned_like_any_other_text(repo: Repository):
    repo.track("docs/diagram.svg", f"<svg><text>{SAMPLES['private IPv4 range']}</text></svg>\n")
    done = repo.run()
    assert done.returncode == 1
    assert "docs/diagram.svg:1: private IPv4 range" in done.stderr


def test_a_nul_byte_does_not_make_a_blob_binary(repo: Repository):
    # Every blob is read as text, image data included: it passes while its bytes spell no identifier and fails when
    # they do. The guard used to skip the UTF-8 reading of any blob with a NUL byte, and image data was the case it
    # accepted as clean. The identifier here is delimited by NUL bytes, the way text is delimited by spaces.
    header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    identifier = SAMPLES["credential store name"].encode()
    repo.track("docs/real.png", header + bytes(range(256)))
    done = repo.run()
    assert done.returncode == 0, done.stderr
    repo.track("docs/real.png", header + b"\x00" + identifier + b"\x00" + bytes(range(256)))
    done = repo.run()
    assert done.returncode == 1
    assert "docs/real.png:" in done.stderr and "credential store name" in done.stderr
    # the suffix is not what decides either way: text that is merely named like an image is read
    repo.track("docs/fake.png", b"credentials live in " + identifier + b"\n")
    done = repo.run()
    assert done.returncode == 1
    assert "docs/fake.png:1: credential store name" in done.stderr


#: Text with one NUL byte in it and the identifier on line 2. A NUL byte is not a line break and not a word character,
#: so it leaves the line numbers and the ``\b`` boundary of the identifier where they were.
NUL_LAYOUTS = {
    "on another line": b"first\x00 line\nreach it at %b today\n",
    "right before the identifier": b"first line\nreach it at \x00%b today\n",
    "right after the identifier": b"first line\nreach it at %b\x00 today\n",
    "at the end of the file": b"first line\nreach it at %b today\n\x00",
    "beside bytes that are not UTF-8": b"caf\xe9\x00 line\nreach it at %b today\n",
}


@pytest.mark.parametrize("layout", sorted(NUL_LAYOUTS))
def test_a_stray_nul_byte_does_not_hide_ascii_text(repo: Repository, layout: str):
    # One NUL byte anywhere used to switch the blob to the UTF-16 and UTF-32 readings only, so the text around it was
    # never read as the UTF-8 or ASCII that it is, and the file passed with an identifier in it.
    repo.track("notes.txt", NUL_LAYOUTS[layout] % CONTAINER.encode())
    done = repo.run()
    assert done.returncode == 1, "an identifier next to a NUL byte is still an identifier"
    assert "notes.txt:2: internal container id" in done.stderr
    assert "\x00" not in done.stderr, "a control character from a file must reach the log escaped"


@pytest.mark.parametrize("with_mark", [True, False], ids=["with-mark", "without-mark"])
@pytest.mark.parametrize("encoding", sorted(BYTE_ORDER_MARKS))
def test_text_in_utf16_or_utf32_is_scanned_with_or_without_a_byte_order_mark(
    repo: Repository, encoding: str, with_mark: bool
):
    # Every ASCII character of these encodings carries NUL bytes, so the NUL test alone used to skip the whole file.
    # CRLF, as the Windows tools that write such files write it: the line number must still count the lines.
    text = f"first line\r\nreach it at {SAMPLES['private domain']} today\r\n"
    repo.track("notes.txt", (BYTE_ORDER_MARKS[encoding] if with_mark else b"") + text.encode(encoding))
    done = repo.run()
    assert done.returncode == 1
    assert "notes.txt:2: private domain" in done.stderr


def test_wide_text_with_characters_outside_latin_1_is_scanned(repo: Repository):
    # A rule that wanted a zero byte at every second position would miss this file: the ł of Polish text is two
    # non-zero bytes in UTF-16, so the file holds fewer NUL bytes than characters.
    text = f"Zażółć gęślą jaźń: {CONTAINER}\n"
    repo.track("notes.txt", text.encode("utf-16-le"))
    done = repo.run()
    assert done.returncode == 1
    assert "notes.txt:1: internal container id" in done.stderr


def test_clean_text_in_a_wide_encoding_passes(repo: Repository):
    repo.track("notes.txt", "nothing to report\r\n".encode("utf-16"))
    done = repo.run()
    assert done.returncode == 0, done.stderr


def test_only_the_guard_itself_is_skipped_for_its_content(repo: Repository):
    # The script lists the strings it looks for, so its own text matches two of its patterns and that one file may
    # not be read. Any other path that holds the same text is an ordinary file.
    repo.git("add", "--", f"scripts/{SCRIPT.name}")
    done = repo.run()
    assert done.returncode == 0, done.stderr
    repo.track("tests/copy_of_the_guard.py", SCRIPT.read_text())
    done = repo.run()
    assert done.returncode == 1
    assert "tests/copy_of_the_guard.py:" in done.stderr


@pytest.mark.parametrize(
    ("name", "line"),
    [
        # a lock generated against a private index names that index in every package entry it resolved there
        ("uv.lock", 'source = { registry = "https://pypi.' + SAMPLES["private domain"] + '/simple" }'),
        (".gitleaks.toml", "# " + SAMPLES["internal proxy host"]),
    ],
    # the line holds an assembled identifier, and pytest would print it as the test id
    ids=["uv.lock", ".gitleaks.toml"],
)
def test_an_identifier_in_the_lock_or_the_secret_scan_configuration_is_reported(repo: Repository, name: str, line: str):
    repo.track(name, f"{line}\n")
    done = repo.run()
    assert done.returncode == 1
    assert f"{name}:1: " in done.stderr


def test_a_submodule_pointer_is_not_a_read_error(repo: Repository):
    repo.git("update-index", "--add", "--cacheinfo", "160000", "1" * 40, "vendor/lib")
    done = repo.run()
    assert done.returncode == 0, done.stderr


def test_an_intent_to_add_entry_is_an_empty_file_not_a_read_error(repo: Repository):
    (repo.root / "later.txt").write_text("")
    repo.git("add", "--intent-to-add", "later.txt")
    done = repo.run()
    assert done.returncode == 0, done.stderr


def test_a_missing_object_fails_the_scan_instead_of_skipping_the_file(repo: Repository):
    repo.track("notes.txt", "a line that no object database can serve any more\n")
    object_id = repo.git("rev-parse", ":notes.txt").strip()
    (repo.root / ".git" / "objects" / object_id[:2] / object_id[2:]).unlink()
    done = repo.run()
    assert done.returncode == 2, "a blob that cannot be read is not a clean file"
    assert object_id in done.stderr


def test_a_scan_that_cannot_run_git_fails(repo: Repository):
    done = repo.run(env={"PATH": "", "HOME": str(repo.root.parent)})
    assert done.returncode == 2
    assert "could not complete" in done.stderr


def test_an_empty_index_is_not_a_clean_scan(tmp_path: Path):
    empty = Repository(tmp_path / "empty")
    done = empty.run()
    assert done.returncode == 2, "a scan that covered nothing proves nothing"


def test_a_large_file_and_identical_blobs_are_attributed_to_the_right_paths(repo: Repository):
    big = b"x" * (2 * 1024 * 1024) + b"\n" + SAMPLES["internal proxy host"].encode() + b"\n"
    repo.track("data/big.txt", big)
    repo.track("data/copy-one.txt", "same bytes\n")
    repo.track("data/copy-two.txt", "same bytes\n")
    repo.track("data/last.txt", f"{SAMPLES['private domain']}\n")
    done = repo.run()
    assert done.returncode == 1
    assert "data/big.txt:2: internal proxy host" in done.stderr
    assert "data/last.txt:1: private domain" in done.stderr
    assert "copy-one" not in done.stderr and "copy-two" not in done.stderr


def test_every_stage_of_an_unmerged_path_is_scanned(repo: Repository):
    clean = repo.git("hash-object", "-w", "--stdin", stdin=b"fine\n").strip()
    dirty = repo.git("hash-object", "-w", "--stdin", stdin=f"{SAMPLES['private domain']}\n".encode()).strip()
    index = f"100644 {clean} 1\tmerge.txt\n100644 {clean} 2\tmerge.txt\n100644 {dirty} 3\tmerge.txt\n"
    repo.git("update-index", "--index-info", stdin=index.encode())
    done = repo.run()
    assert done.returncode == 1
    assert "merge.txt:1: private domain" in done.stderr


def test_a_path_name_cannot_forge_a_log_line(repo: Repository):
    # a name with a line break must not start a line of its own: CI reads a line that begins with two colons
    name = "x\n::error::forged " + CONTAINER
    repo.track(name, "clean\n")
    done = repo.run()
    assert done.returncode == 1
    assert not any(line.startswith("::") for line in done.stderr.splitlines())
