"""The lock-file grammar has two implementations: scripts/lib/common.sh (what the installers run) and
tools/check_pins.py (what CI runs). If they ever disagree, a file can pass CI and then mean something else — or
nothing — to the script that installs a root-executed binary from it. These tests run both on the same inputs and
demand identical verdicts, key order and values: first on a hand-written corpus of tricky files, then on a few
hundred random ones (seeded, so a failure is reproducible).
"""

from __future__ import annotations

import random
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

import check_pins

COMMON = Path(__file__).resolve().parents[2] / "scripts/lib/common.sh"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

# (id, bytes). Each is run through both parsers; the verdict (accepted or refused), the keys and the values must match.
CORPUS: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("only-a-newline", b"\n"),
    ("only-comments", b"# a\n  # b\n\t#c\n"),
    ("simple", b"A=1\nB=two\n"),
    ("no-trailing-newline", b"A=1"),
    ("crlf", b"A=1\r\nB=2\r\n"),
    ("trailing-comment", b"A=1 # why\n"),
    ("hash-inside-value-starts-a-comment", b"A=b#c\n"),
    ("surrounding-whitespace", b"  A=1  \n\tB=2\t\n"),
    ("vertical-tab-and-form-feed-around-a-line", b"\x0bA=1\x0c\n"),
    ("empty-value", b"A=\n"),
    ("unset", b"A=UNSET\n"),
    ("every-allowed-character", b"A=aZ09._:/@+=,-\n"),
    ("value-with-equals", b"A=b=c\n"),
    ("digit-first-key", b"1A=2\n"),
    ("underscore-key", b"_=2\n"),
    ("keys-differ-by-case", b"a=1\nA=2\n"),
    ("digest", b"BASE_DIGEST_x=sha256:" + b"0" * 64 + b"\n"),
    ("no-equals", b"A\n"),
    ("empty-key", b"=x\n"),
    ("only-an-equals-sign", b"=\n"),
    ("space-in-key", b"A B=1\n"),
    ("space-before-equals", b"A =1\n"),
    ("space-after-equals", b"A= 1\n"),
    ("two-words", b"A=1 2\n"),
    ("tab-inside-value", b"A=1\t2\n"),
    ("double-quotes", b'A="x"\n'),
    ("single-quotes", b"A='x'\n"),
    ("dollar", b"A=$X\n"),
    ("command-substitution", b"A=$(id)\n"),
    ("backticks", b"A=`id`\n"),
    ("semicolon", b"A=x;y\n"),
    ("pipe", b"A=x|y\n"),
    ("ampersand", b"A=x&y\n"),
    ("parens", b"A=x(y)\n"),
    ("glob-star", b"A=*\n"),
    ("question-mark", b"A=?\n"),
    ("tilde", b"A=~\n"),
    ("bang", b"A=!x\n"),
    ("backslash", b"A=x\\y\n"),
    ("angle-brackets", b"A=<x>\n"),
    ("braces", b"A={x}\n"),
    ("duplicate-key", b"A=1\nA=2\n"),
    ("duplicate-key-same-value", b"A=1\nA=1\n"),
    ("duplicate-key-far-apart", b"A=1\nB=2\nC=3\nA=4\n"),
    ("garbage-after-a-valid-line", b"A=1\nthis is garbage\n"),
    ("garbage-before-a-valid-line", b"garbage\nA=1\n"),
    ("lone-carriage-return-inside-a-line", b"A=1\rB=2\n"),
    ("nul-byte", b"A=1\x00\n"),
    ("nul-byte-in-a-comment", b"# a\x00b\nA=1\n"),
    ("invalid-utf-8", b"A=\xff\n"),
    ("non-ascii-value", "A=é\n".encode()),
    ("non-ascii-key", "é=1\n".encode()),
    ("no-break-space-after-value", b"A=1\xc2\xa0\n"),
    ("line-separator-character", "A=1\u2028B=2\n".encode()),
    ("very-long-line", b"A=" + b"x" * 20000 + b"\n"),
    ("many-keys", b"".join(f"K{i}={i}\n".encode() for i in range(300))),
    ("comment-with-everything", b'# "quoted" $x ; | & ` \' \\ \x01\nA=1\n'),
]


def _python_verdict(path: Path) -> list[tuple[str, str]] | None:
    try:
        return list(check_pins.read_lock(path).items())
    except check_pins.PinError:
        return None


RUNNER = r"""
source "$1"
dir=$2
for f in "$dir"/*.lock; do
    name=${f##*/}
    if keys="$(lock_keys "$f" 2>/dev/null)"; then
        printf 'OK %s\n' "$name"
        while IFS= read -r k; do
            [[ -n "$k" ]] || continue
            printf 'KV %s=%s\n' "$k" "$(lock_get "$f" "$k")"
        done <<<"$keys"
    else
        printf 'BAD %s\n' "$name"
    fi
done
"""


def _shell_verdicts(run: Runner, directory: Path) -> dict[str, list[tuple[str, str]] | None]:
    result = run(["bash", "-c", RUNNER, "runner", COMMON, directory])
    assert result.returncode == 0, result.stderr
    out: dict[str, list[tuple[str, str]] | None] = {}
    current: str | None = None
    for line in result.stdout.split("\n"):
        if line.startswith("OK "):
            current = line[3:]
            out[current] = []
        elif line.startswith("BAD "):
            out[line[4:]] = None
            current = None
        elif line.startswith("KV ") and current is not None:
            key, _, value = line[3:].partition("=")
            verdict = out[current]
            assert verdict is not None
            verdict.append((key, value))
    return out


def _compare(run: Runner, directory: Path, cases: dict[str, bytes]) -> None:
    for name, data in cases.items():
        (directory / f"{name}.lock").write_bytes(data)
    shell = _shell_verdicts(run, directory)
    assert set(shell) == {f"{n}.lock" for n in cases}
    disagreements = []
    for name, data in cases.items():
        python = _python_verdict(directory / f"{name}.lock")
        if python != shell[f"{name}.lock"]:
            disagreements.append(f"{name}: {data[:80]!r}\n    python: {python}\n    shell:  {shell[f'{name}.lock']}")
    assert not disagreements, "the two lock parsers disagree:\n" + "\n".join(disagreements)


def test_both_parsers_agree_on_every_case_in_the_corpus(run: Runner, tmp_path: Path) -> None:
    _compare(run, tmp_path, dict(CORPUS))


def test_the_corpus_exercises_both_verdicts_and_the_shell_really_refuses_the_dangerous_ones(
    run: Runner, tmp_path: Path
) -> None:
    """Agreement on a corpus where everything is accepted (or everything refused) would prove nothing."""
    for name, data in CORPUS:
        (tmp_path / f"{name}.lock").write_bytes(data)
    verdicts = _shell_verdicts(run, tmp_path)
    accepted = {n.removesuffix(".lock") for n, v in verdicts.items() if v is not None}
    refused = {n.removesuffix(".lock") for n, v in verdicts.items() if v is None}
    assert len(accepted) >= 15
    assert len(refused) >= 25
    for must_refuse in (
        "command-substitution",
        "backticks",
        "dollar",
        "semicolon",
        "duplicate-key",
        "nul-byte",
        "garbage-after-a-valid-line",
    ):
        assert must_refuse in refused, must_refuse
    for must_accept in ("simple", "crlf", "no-trailing-newline", "trailing-comment", "digest", "unset"):
        assert must_accept in accepted, must_accept


@pytest.mark.parametrize("seed", [20261013, 1, 2])
def test_both_parsers_agree_on_random_files(run: Runner, tmp_path: Path, seed: int) -> None:
    rng = random.Random(seed)
    # An alphabet that keeps most files near the grammar's edges: valid pieces, separators and a few hazards.
    pieces = [
        "A",
        "B",
        "key",
        "K_1",
        "=",
        "=",
        "=",
        " ",
        " ",
        "\t",
        "\n",
        "\n",
        "\n",
        "\r",
        "\r\n",
        "#",
        "# ",
        "1",
        "UNSET",
        "sha256:",
        "0",
        "a/b",
        "-",
        ".",
        ",",
        "+",
        "@",
        ":",
        '"',
        "'",
        "$",
        "`",
        ";",
        "(",
        ")",
        "*",
        "é",
        "\x0b",
        "\x0c",
    ]
    cases: dict[str, bytes] = {}
    for i in range(120):
        n = rng.randint(0, 24)
        text = "".join(rng.choice(pieces) for _ in range(n))
        cases[f"r{seed}_{i}"] = text.encode()
    # Bias a third of them towards well-formed files so the accepted path gets real coverage too.
    for i in range(80):
        lines = []
        for _ in range(rng.randint(0, 6)):
            key = rng.choice(["A", "B", "C", "BASE_REF_x", "KERNEL_SHA256_x86_64", "K1"])
            value = rng.choice(["", "UNSET", "1", "v1.17.0", "sha256:" + "ab" * 32, "a/b:c@d", "x=y"])
            comment = rng.choice(["", "", " # note", "#x"])
            pad = rng.choice(["", " ", "\t"])
            lines.append(f"{pad}{key}={value}{comment}")
        cases[f"w{seed}_{i}"] = ("\n".join(lines) + rng.choice(["", "\n", "\r\n"])).encode()
    _compare(run, tmp_path, cases)
