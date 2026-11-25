"""``--help`` for the program and for every command in it, and what help text must never do.

The tree of commands is found by reading the help itself, so a command that is added is covered without
anyone remembering to. Help text is a document people act on: it may name no package to fetch from a
registry, because the names of this project's packages are not registered anywhere yet, and whatever
answers to such a name today is not this project's.
"""

from __future__ import annotations

import re

import pytest

from agentcompute_cli._version import __version__
from support import Cli

#: Ways of fetching a package from a registry, and the names someone could try to fetch.
FORBIDDEN = re.compile(
    r"pip3? install|pipx|uvx|uv tool|npx|npm (install|i)\b|agent-compute|agentcompute", re.IGNORECASE
)
GROUPS = {
    (): {"auth", "policy", "info", "sandbox", "exec", "snapshot", "operation", "mcp"},
    ("auth",): {"login", "logout", "agent-key"},
    ("auth", "agent-key"): {"create", "list", "revoke"},
    ("policy",): {"inspect"},
    ("sandbox",): {"create", "list", "inspect", "start", "stop", "destroy"},
    ("exec",): {"run", "status", "cancel", "output"},
    ("snapshot",): {"create", "list", "restore", "delete"},
    ("operation",): {"get", "list"},
}


def commands_in(text: str) -> set[str]:
    """The names listed under ``Commands:`` in a help page."""
    listed = text.partition("\nCommands:\n")[2]
    return {line.split()[0] for line in listed.splitlines() if line.startswith("  ") and line.strip()}


def tree(cli: Cli, path: tuple[str, ...] = ()) -> dict[tuple[str, ...], str]:
    """Every command path of the program with its help page, found by following the help itself."""
    run = cli.run([*path, "--help"])
    assert run.exit_code == 0, f"acf {' '.join(path)} --help: {run.stderr}"
    pages = {path: run.stdout}
    for name in commands_in(run.stdout):
        pages.update(tree(cli, (*path, name)))
    return pages


@pytest.fixture
def pages(cli: Cli) -> dict[tuple[str, ...], str]:
    return tree(cli)


def test_the_tree_of_commands_is_the_published_one(pages: dict[tuple[str, ...], str]) -> None:
    groups = {path: commands_in(page) for path, page in pages.items() if commands_in(page)}
    assert groups == GROUPS


def test_every_command_has_a_help_page_that_says_what_it_does(pages: dict[tuple[str, ...], str]) -> None:
    assert len(pages) == 32
    for path, page in pages.items():
        name = " ".join(("acf", *path))
        assert page.startswith(f"Usage: {name}"), name
        described = page.partition("\n\n")[2].partition("\n\n")[0].strip()
        assert len(described) > 20, f"{name} has no description"
        assert "-h, --help" in page


def test_no_help_page_names_a_package_to_fetch(pages: dict[tuple[str, ...], str], cli: Cli) -> None:
    version = cli.run(["--version"])
    for name, text in [("--version", version.stdout), *((" ".join(path), page) for path, page in pages.items())]:
        found = FORBIDDEN.search(text)
        assert found is None, f"acf {name} says {found.group(0) if found else ''!r}"


def test_no_help_page_offers_a_way_to_put_a_key_on_the_command_line(pages: dict[tuple[str, ...], str]) -> None:
    for path, page in pages.items():
        assert "--api-key" not in page, path
        assert "--key " not in page, path
        assert "--token" not in page, path


def test_help_is_plain_text(pages: dict[tuple[str, ...], str]) -> None:
    for path, page in pages.items():
        assert "\x1b" not in page, path
        assert page.isascii(), f"{path}: help is read in every terminal"


def test_version(cli: Cli) -> None:
    run = cli.run(["--version"])
    assert run.exit_code == 0
    assert run.stdout.startswith(f"acf {__version__} (SDK ")
    assert run.stdout.count("\n") == 1


def test_no_arguments_shows_the_help_and_is_a_usage_error(cli: Cli) -> None:
    run = cli.run([])
    assert run.exit_code == 2
    assert "Usage: acf" in run.stdout + run.stderr


def test_the_first_page_says_what_the_exit_status_means(cli: Cli) -> None:
    page = cli.run(["--help"]).stdout
    for word in ("0 done", "2 usage", "3 refused", "5 outcome unknown", "8", "9 outcome lost", "10 still running"):
        assert word in " ".join(page.split()), word


def test_help_is_given_without_a_key_and_asks_nobody(cli: Cli) -> None:
    run = cli.run(["sandbox", "create", "--help"], env={"ACF_API_KEY": None, "ACF_BASE_URL": None})
    assert run.exit_code == 0
    assert run.requests == []
