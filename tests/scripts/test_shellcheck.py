"""Every shell script this repository ships passes ShellCheck at its strictest severity (style).

ShellCheck comes from the ``shellcheck-py`` wheel in the tooling environment (``uv sync`` installs it), so CI and a
contributor's machine run the same version. The repository's ``.shellcheckrc`` turns on ``external-sources`` so that
``source lib/common.sh`` is followed rather than guessed at.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

SCRIPTS = [
    *sorted((REPO / "scripts").glob("*.sh")),
    REPO / "scripts/acf-setup-cgroup",
    REPO / "scripts/lib/common.sh",
    REPO / "images/overlay/usr/local/sbin/acf-init",
]

pytestmark = pytest.mark.skipif(
    shutil.which("shellcheck") is None, reason="shellcheck is not installed (uv sync installs it)"
)


def test_the_list_covers_every_shell_script_in_the_repository() -> None:
    """A script added without a test is a script nobody lints: find shell files by shebang, not by name."""
    found: set[Path] = set()
    for path in REPO.rglob("*"):
        if (
            path.is_file()
            and not path.is_symlink()
            and not {"target", ".venv", "node_modules", "dist"} & set(path.relative_to(REPO).parts)
        ):
            try:
                head = path.open("rb").read(64)
            except OSError:
                continue
            first = head.split(b"\n", 1)[0]
            if first.startswith(b"#!") and (b"sh" in first.split(b"/")[-1] or b"bash" in first):
                found.add(path)
    found |= set((REPO / "scripts/lib").glob("*.sh"))
    assert found == set(SCRIPTS), (
        f"unlisted: {sorted(found - set(SCRIPTS))}; listed but not shell: {sorted(set(SCRIPTS) - found)}"
    )


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.relative_to(REPO).as_posix())
def test_shellcheck_has_nothing_to_say(script: Path) -> None:
    result = subprocess.run(
        ["shellcheck", "--severity=style", "--external-sources", str(script)],
        capture_output=True, text=True, cwd=REPO, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stdout + result.stderr
