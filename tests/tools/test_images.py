"""images/: the recipes, the init and the places that must agree with them (policy, host config, scripts, docs)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

BEGIN = "# >>> ACF GUEST LAYER"
END = "# <<< ACF GUEST LAYER"
RECIPES = ("base", "python", "node", "browser")
FORBIDDEN_INSTRUCTIONS = (
    "ENV",
    "USER",
    "WORKDIR",
    "ENTRYPOINT",
    "CMD",
    "EXPOSE",
    "VOLUME",
    "HEALTHCHECK",
    "SHELL",
    "ONBUILD",
    "LABEL",
)


def dockerfile(repo: Path, name: str) -> str:
    return (repo / "images" / name / "Dockerfile").read_text()


def guest_layer(text: str) -> str:
    start = text.index(BEGIN)
    return text[start : text.index(END, start) + len(END)]


def instructions(text: str) -> list[str]:
    """Dockerfile instruction keywords, with comments and `\\` continuations skipped."""
    out: list[str] = []
    continued = False
    for raw in text.splitlines():
        line = raw.strip()
        if continued:
            continued = line.endswith("\\")
            continue
        if not line or line.startswith("#"):
            continue
        out.append(line.split(None, 1)[0].upper())
        continued = line.endswith("\\")
    return out


def test_the_recipes_on_disk_are_exactly_the_four_the_plan_names(repo: Path) -> None:
    on_disk = sorted(p.parent.name for p in (repo / "images").glob("*/Dockerfile"))
    assert on_disk == sorted(RECIPES)


@pytest.mark.parametrize("name", RECIPES)
def test_every_recipe_has_the_guest_layer_exactly_once(repo: Path, name: str) -> None:
    text = dockerfile(repo, name)
    assert text.count(BEGIN) == 1
    assert text.count(END) == 1
    assert text.index(BEGIN) < text.index(END)


def test_the_guest_layer_is_byte_identical_in_every_recipe(repo: Path) -> None:
    layers = {name: guest_layer(dockerfile(repo, name)) for name in RECIPES}
    reference = layers["base"]
    for name, layer in layers.items():
        assert layer == reference, f"images/{name}/Dockerfile's guest layer differs from images/base/Dockerfile's"


@pytest.mark.parametrize("name", RECIPES)
def test_a_recipe_takes_its_base_from_the_pinned_build_argument_and_nothing_else(repo: Path, name: str) -> None:
    kinds = instructions(dockerfile(repo, name))
    assert kinds[:2] == ["ARG", "FROM"], (
        "BASE_REF is declared before FROM so that a missing value is an error, not `latest`"
    )
    assert kinds.count("FROM") == 1, "one stage: the exported tarball must be the final filesystem"
    text = dockerfile(repo, name)
    assert re.search(r"^ARG BASE_REF$", text, re.MULTILINE), "BASE_REF must have no default"
    assert re.search(r"^FROM \$\{BASE_REF\}$", text, re.MULTILINE)


@pytest.mark.parametrize("name", RECIPES)
def test_no_instruction_that_is_silently_dropped_by_the_tar_export(repo: Path, name: str) -> None:
    used = set(instructions(dockerfile(repo, name)))
    assert not used & set(FORBIDDEN_INSTRUCTIONS), (
        f"{used & set(FORBIDDEN_INSTRUCTIONS)} have no effect on an exported filesystem"
    )


@pytest.mark.parametrize("name", RECIPES)
def test_nothing_in_a_recipe_floats(repo: Path, name: str) -> None:
    text = dockerfile(repo, name)
    assert "latest" not in re.sub(r"#.*", "", text), "a Dockerfile must not name `latest`"
    assert "@sha256" not in text, "digests live in images/images.lock, where scripts/pin-images.sh maintains them"


def test_the_guest_user_is_the_one_the_default_policy_runs_commands_as(repo: Path) -> None:
    policy = (repo / "policies" / "default.yaml").read_text()
    uid = int(re.search(r"^\s*guest_uid:\s*(\d+)", policy, re.MULTILINE).group(1))  # type: ignore[union-attr]
    gid = int(re.search(r"^\s*guest_gid:\s*(\d+)", policy, re.MULTILINE).group(1))  # type: ignore[union-attr]
    layer = guest_layer(dockerfile(repo, "base"))
    assert f"getent group {gid} " in layer
    assert f"groupadd --gid {gid} " in layer
    assert f"getent passwd {uid} " in layer
    assert f"useradd --uid {uid} --gid {gid} " in layer
    assert f"install -d -m 0755 -o {uid} -g {gid} /workspace" in layer
    build = (repo / "scripts" / "build-image.sh").read_text()
    assert f"--owner /workspace={uid}:{gid}" in build, "build-image.sh must verify the ownership the policy depends on"


def test_the_images_the_default_policy_offers_are_the_images_that_can_be_built(repo: Path) -> None:
    policy = (repo / "policies" / "default.yaml").read_text()
    offered = re.search(r"^\s*images:\s*\[([^\]]*)\]", policy, re.MULTILINE)
    assert offered is not None
    assert sorted(n.strip() for n in offered.group(1).split(",")) == sorted(RECIPES)


def test_the_paths_init_the_dockerfile_and_the_build_script_agree_on(repo: Path) -> None:
    init = (repo / "images" / "overlay" / "usr" / "local" / "sbin" / "acf-init").read_text()
    layer = guest_layer(dockerfile(repo, "base"))
    build = (repo / "scripts" / "build-image.sh").read_text()

    assert "AGENT=/usr/local/bin/acf-guest-agent" in init
    assert "/usr/local/bin/acf-guest-agent" in layer
    assert "/usr/local/bin/acf-guest-agent" in build

    assert "CLOCK_EPOCH_FILE=/usr/local/share/acf/clock-epoch" in init
    assert "/usr/local/share/acf/clock-epoch" in layer

    assert "/usr/local/sbin/acf-init" in layer
    assert "ln -sf /usr/local/sbin/acf-init /usr/sbin/init" in layer
    assert "--exec /sbin/init" in build
    assert (repo / "images" / "overlay" / "usr" / "local" / "sbin" / "acf-init").is_file()


def test_init_needs_nothing_the_guest_layer_does_not_guarantee(repo: Path) -> None:
    """Every external program init calls is checked for in the image build."""
    init = (repo / "images" / "overlay" / "usr" / "local" / "sbin" / "acf-init").read_text()
    layer = guest_layer(dockerfile(repo, "base"))
    code = "\n".join(ln for ln in init.splitlines() if not ln.lstrip().startswith("#"))
    used = {
        w
        for w in ("mount", "resize2fs", "ip", "date", "readlink", "ln", "mkdir", "chmod")
        if re.search(rf"(^|[\s(`$|;&]){w}\s", code)
    }
    # ln, mkdir and chmod are coreutils (essential in Debian); the rest are checked or installed by the layer.
    for tool in used - {"ln", "mkdir", "chmod"}:
        assert re.search(rf"\b{tool}\b", layer), f"init calls `{tool}`; the guest layer must make sure it exists"


def test_the_default_path_the_agent_gives_a_command_is_the_one_init_uses(repo: Path) -> None:
    exec_rs = (repo / "execution" / "guest-agent" / "src" / "exec.rs").read_text()
    init = (repo / "images" / "overlay" / "usr" / "local" / "sbin" / "acf-init").read_text()
    rust = re.search(r'pub const DEFAULT_PATH: &str = "([^"]+)";', exec_rs)
    shell = re.search(r"^PATH=(\S+)$", init, re.MULTILINE)
    assert rust is not None
    assert shell is not None
    assert rust.group(1) == shell.group(1)


def test_the_boot_arguments_the_readme_quotes_are_the_ones_the_host_uses(repo: Path) -> None:
    config_rs = (repo / "execution" / "host-agent" / "src" / "config.rs").read_text()
    readme = (repo / "images" / "README.md").read_text()
    fn = re.search(r'pub fn default_boot_args\(\) -> String \{\s*"([^"]+)"', config_rs)
    assert fn is not None
    quoted = " ".join(re.search(r"command line is `([^`]+)`", readme, re.DOTALL).group(1).split())  # type: ignore[union-attr]
    assert quoted == fn.group(1)
    assert "pci=off" in fn.group(1)
    assert "nomodule" in fn.group(1)


def test_the_example_config_and_the_boot_default_do_not_set_root_because_firecracker_does(repo: Path) -> None:
    assert (
        "root="
        not in (repo / "execution" / "host-agent" / "src" / "config.rs")
        .read_text()
        .split("pub fn default_boot_args")[1]
        .split("}")[0]
    )


def test_every_shipped_shell_script_is_executable_and_has_a_shebang(repo: Path) -> None:
    for path in [
        *(repo / "scripts").glob("*.sh"),
        repo / "scripts" / "acf-setup-cgroup",
        repo / "images" / "overlay" / "usr" / "local" / "sbin" / "acf-init",
    ]:
        assert path.stat().st_mode & 0o111, f"{path} is not executable"
        assert path.read_text().startswith("#!"), f"{path} has no shebang"
    for path in (repo / "tools").glob("*.py"):
        assert path.stat().st_mode & 0o111, f"{path} is not executable"
        assert path.read_text().startswith("#!/usr/bin/env python3"), f"{path} has no shebang"
