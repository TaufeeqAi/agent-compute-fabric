"""scripts/build-image.sh — pins, kernel, guest agent, container build, rootfs, manifest, install.

Three layers, cheapest first:

* the checks that run BEFORE the build needs root (usage, pins, kernel, guest agent, build time) — no privileges;
* the whole pipeline with ``--rootfs-tar`` (no container engine) — needs root, because the rootfs keeps real ownership;
* the container path, with a stub ``docker`` that records what it was asked to build and hands back a tarball.

What the real build adds on top — a registry, BuildKit, a real kernel and a real musl guest agent — cannot run here;
docs/VERIFICATION_STATUS.md says so.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from acf_testkit import (
    config_text,
    good_kernel,
    host_machine,
    kernel_image,
    kernel_without_config,
    make_elf,
    rootfs_tarball,
    static_agent,
)

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

ARCH = host_machine()
pytestmark = pytest.mark.skipif(not ARCH, reason="ACF supports x86_64 and aarch64 hosts only")

EPOCH = "1700000000"
DIGEST = "sha256:" + "ab" * 32


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def set_pins(tree: Path, **values: str) -> None:
    lock = tree / "images/images.lock"
    text = lock.read_text()
    for key, value in values.items():
        text, n = re.subn(rf"^{key}=.*$", f"{key}={value}", text, flags=re.MULTILINE)
        assert n == 1, key
    lock.write_text(text)


class Rig:
    """A repository copy plus the inputs one build needs."""

    def __init__(self, run: Runner, tree: Path, tmp_path: Path) -> None:
        self.run = run
        self.tree = tree
        self.tmp = tmp_path
        self.out_root = tmp_path / "out"
        self.kernel = good_kernel(tmp_path / "vmlinux", ARCH)
        self.agent = static_agent(tmp_path / "acf-guest-agent", ARCH)
        self.tarball = rootfs_tarball(tmp_path / "rootfs.tar")

    def pin_everything(self, image: str = "python") -> None:
        set_pins(self.tree, **{f"BASE_DIGEST_{image}": DIGEST, f"KERNEL_SHA256_{ARCH}": sha256(self.kernel)})

    def build(
        self, *args: str | Path, image: str = "python", env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            ["bash", self.tree / "scripts/build-image.sh", "--image", image, "--kernel", self.kernel, "--arch", ARCH,
             "--out-root", self.out_root, "--source-date-epoch", EPOCH, *args],
            env=env,
        )  # fmt: skip

    def with_rootfs_tar(self, *args: str | Path, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return self.build("--rootfs-tar", self.tarball, *args, **kwargs)  # type: ignore[arg-type]


@pytest.fixture
def rig(run: Runner, tree: Path, tmp_path: Path) -> Rig:
    return Rig(run, tree, tmp_path)


def manifest_of(image_dir: Path) -> dict[str, object]:
    data = json.loads((image_dir / "manifest.json").read_text())
    assert isinstance(data, dict)
    return data


def verify(tree: Path, image_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(tree / "tools/write_image_manifest.py"), "verify", "--dir", str(image_dir)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip


# ------------------------------------------------------------------------------------- usage (no root)


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "--image and --kernel are required"),
        (["--image", "python"], "--image and --kernel are required"),
        (["--kernel", "k"], "--image and --kernel are required"),
        (["--image", "Python", "--kernel", "k"], "--image must be a short lower-case name"),
        (["--image", "../python", "--kernel", "k"], "--image must be a short lower-case name"),
        (["--image", "-python", "--kernel", "k"], "--image must be a short lower-case name"),
        (["--image", "a" * 40, "--kernel", "k"], "--image must be a short lower-case name"),
        (["--image", "nope", "--kernel", "k"], "no such image: images/nope/Dockerfile (available: "),
        (["--image", "python", "--kernel", "k", "--slack-mib", "lots"], "--slack-mib must be a non-negative integer"),
        (
            ["--image", "node", "--kernel", "k", "--requirements", "r.txt"],
            "--requirements applies to the python and browser images only",
        ),
        (["--image", "python", "--kernel", "k", "--arch", "riscv64"], "--arch must be x86_64 or aarch64"),
        (["--bogus"], "unknown option"),
    ],
)
def test_usage_errors_exit_2(rig: Rig, args: list[str], message: str) -> None:
    result = rig.run(["bash", rig.tree / "scripts/build-image.sh", *args])
    assert result.returncode == 2, result.stderr
    assert message in result.stderr


def test_the_available_images_are_listed_in_the_error_for_an_unknown_one(rig: Rig) -> None:
    result = rig.run(["bash", rig.tree / "scripts/build-image.sh", "--image", "nope", "--kernel", "k"])
    for name in ("base", "browser", "node", "python"):
        assert name in result.stderr


def test_a_non_numeric_min_free_is_a_usage_error(rig: Rig) -> None:
    result = rig.with_rootfs_tar("--allow-unpinned", env={"ACF_MIN_FREE_MIB": "lots"})
    assert result.returncode == 2
    assert "ACF_MIN_FREE_MIB must be a non-negative integer" in result.stderr


def test_requirements_must_exist_and_carry_hashes(rig: Rig, tmp_path: Path) -> None:
    missing = rig.build("--requirements", tmp_path / "absent.txt")
    assert missing.returncode == 1
    assert "not a file" in missing.stderr
    unhashed = tmp_path / "requirements.txt"
    unhashed.write_text("requests==2.32.0\n# --hash=sha256:" + "0" * 64 + "\n")  # the only hash is inside a comment
    result = rig.build("--requirements", unhashed)
    assert result.returncode == 1
    assert "has no --hash=sha256:... entries" in result.stderr


def test_help_goes_to_stdout(rig: Rig) -> None:
    result = rig.run(["bash", rig.tree / "scripts/build-image.sh", "--help"])
    assert result.returncode == 0
    assert "Usage: build-image.sh" in result.stdout
    assert "--allow-unpinned" in result.stdout


# --------------------------------------------------------------------------- pins fail closed (no root)


def test_an_unset_base_digest_is_exit_3_with_the_way_to_fix_it(rig: Rig) -> None:
    set_pins(rig.tree, **{f"KERNEL_SHA256_{ARCH}": sha256(rig.kernel)})
    result = rig.build("--guest-agent", rig.agent)
    assert result.returncode == 3, result.stderr
    assert "NOT PINNED: BASE_DIGEST_python is UNSET in images/images.lock" in result.stderr
    assert "scripts/pin-images.sh" in result.stderr
    assert "--allow-unpinned" in result.stderr


def test_an_unset_kernel_pin_is_exit_3_even_when_the_base_does_not_matter(rig: Rig) -> None:
    result = rig.with_rootfs_tar()
    assert result.returncode == 3, result.stderr
    assert f"KERNEL_SHA256_{ARCH} is UNSET" in result.stderr
    assert "sha256" in result.stderr


def test_an_external_rootfs_does_not_need_a_base_digest(rig: Rig) -> None:
    set_pins(rig.tree, **{f"KERNEL_SHA256_{ARCH}": sha256(rig.kernel)})
    result = rig.with_rootfs_tar("--source-date-epoch", "not-a-number")  # stops later, at the epoch check: pins passed
    assert result.returncode == 2
    assert "the build time must be seconds since the epoch" in result.stderr


def test_a_kernel_that_does_not_match_its_pin_is_refused_with_both_hashes(rig: Rig) -> None:
    set_pins(rig.tree, **{"BASE_DIGEST_python": DIGEST, f"KERNEL_SHA256_{ARCH}": "0" * 64})
    result = rig.build("--guest-agent", rig.agent)
    assert result.returncode == 1
    assert f"the kernel hashes to {sha256(rig.kernel)}" in result.stderr
    assert f"KERNEL_SHA256_{ARCH}={'0' * 64}" in result.stderr


def test_allow_unpinned_gets_past_the_pin_checks(rig: Rig) -> None:
    result = rig.build("--allow-unpinned", "--guest-agent", rig.tmp / "no-such-agent")
    assert result.returncode == 1  # ...and stops at the next stage, not at the pins
    assert "no guest agent at" in result.stderr
    assert "NOT PINNED" not in result.stderr


def test_a_pin_the_lock_does_not_even_mention_is_an_error_not_a_silent_skip(rig: Rig) -> None:
    lock = rig.tree / "images/images.lock"
    lock.write_text(
        "\n".join(line for line in lock.read_text().splitlines() if not line.startswith("BASE_REF_python")) + "\n"
    )
    result = rig.build("--allow-unpinned", "--guest-agent", rig.agent)
    assert result.returncode == 1
    assert "key not found: BASE_REF_python" in result.stderr


# ---------------------------------------------------------------------------------- kernel (no root)


def test_a_missing_kernel_or_a_symlink_to_one_is_refused(rig: Rig) -> None:
    rig.pin_everything()
    rig.kernel.rename(rig.tmp / "real-vmlinux")
    missing = rig.build("--guest-agent", rig.agent)
    assert missing.returncode == 1
    assert "the kernel must be a regular file (not a symlink)" in missing.stderr
    rig.kernel.symlink_to(rig.tmp / "real-vmlinux")
    linked = rig.build("--guest-agent", rig.agent)
    assert linked.returncode == 1
    assert "not a symlink" in linked.stderr


def test_a_kernel_missing_required_options_is_refused_and_the_options_are_named(rig: Rig, tmp_path: Path) -> None:
    from acf_testkit import ARM_REQUIRED, X86_REQUIRED  # noqa: PLC0415 - only this test needs the lists

    options = X86_REQUIRED if ARCH == "x86_64" else ARM_REQUIRED
    rig.kernel.write_bytes(kernel_image(config_text(options, drop=("CONFIG_VSOCKETS",))))
    rig.pin_everything()
    result = rig.build("--guest-agent", rig.agent)
    assert result.returncode == 1
    assert "MISSING CONFIG_VSOCKETS" in result.stderr
    assert "does not meet ACF's requirements" in result.stderr


def test_a_kernel_for_the_other_architecture_is_refused(rig: Rig) -> None:
    other = "aarch64" if ARCH == "x86_64" else "x86_64"
    good_kernel(rig.kernel, other)
    rig.pin_everything()
    result = rig.build("--guest-agent", rig.agent)
    assert result.returncode == 1
    assert f"configured for {other}, but the image is for {ARCH}" in result.stderr


def test_a_kernel_without_an_embedded_config_is_a_warning_not_a_failure(rig: Rig) -> None:
    kernel_without_config(rig.kernel)
    rig.pin_everything()
    result = rig.build("--guest-agent", rig.tmp / "no-such-agent")
    assert "carries no embedded configuration" in result.stderr
    assert "tests/integration boots it for real" in result.stderr
    assert "no guest agent at" in result.stderr, "the build went on to the next stage"


# ------------------------------------------------------------------------------ guest agent (no root)


def test_a_missing_or_symlinked_guest_agent_is_refused_with_the_way_to_build_it(rig: Rig) -> None:
    rig.pin_everything()
    missing = rig.build("--guest-agent", rig.tmp / "absent")
    assert missing.returncode == 1
    assert "make guest-agent" in missing.stderr
    link = rig.tmp / "agent-link"
    link.symlink_to(rig.agent)
    assert rig.build("--guest-agent", link).returncode == 1


def test_the_default_agent_path_is_the_musl_release_build_for_the_architecture(rig: Rig) -> None:
    rig.pin_everything()
    result = rig.build()
    assert result.returncode == 1
    assert f"target/{ARCH}-unknown-linux-musl/release/acf-guest-agent" in result.stderr


@pytest.mark.parametrize(
    ("agent_bytes", "why"),
    [
        (lambda arch: make_elf(interpreter="/lib64/ld-linux-x86-64.so.2"), "dynamic"),
        (lambda arch: make_elf(machine=183 if arch == "x86_64" else 62), "other architecture"),
        (lambda arch: b"#!/bin/sh\necho not an ELF\n", "not ELF"),
    ],
)
def test_a_dynamic_foreign_or_non_elf_guest_agent_is_refused(
    rig: Rig, agent_bytes: Callable[[str], bytes], why: str
) -> None:
    rig.pin_everything()
    rig.agent.write_bytes(agent_bytes(ARCH))
    result = rig.build("--guest-agent", rig.agent)
    assert result.returncode == 1, why
    assert f"the guest agent is not a static {ARCH} executable" in result.stderr


# ------------------------------------------------------------ the whole pipeline with --rootfs-tar (root)


@pytest.mark.needs_root
def test_a_build_from_a_rootfs_tarball_produces_a_verified_image_directory(rig: Rig) -> None:
    rig.pin_everything()
    result = rig.with_rootfs_tar()
    assert result.returncode == 0, result.stderr
    image_dir = rig.out_root / "python"
    assert sorted(p.name for p in image_dir.iterdir()) == ["manifest.json", "rootfs.ext4", "vmlinux"]
    for p in image_dir.iterdir():
        assert stat.S_IMODE(p.stat().st_mode) in (0o644, 0o600), p
    assert verify(rig.tree, image_dir).returncode == 0
    assert (image_dir / "vmlinux").read_bytes() == rig.kernel.read_bytes()

    manifest_bytes = (image_dir / "manifest.json").read_bytes()
    image_id = f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
    assert result.stdout == f"image_id={image_id}\n", "stdout carries the image id and nothing else"
    assert f"image id {image_id}" in result.stderr

    manifest = manifest_of(image_dir)
    assert manifest["name"] == "python"
    assert manifest["architecture"] == ARCH
    assert manifest["guest_agent_version"] == "0.1.0"
    assert manifest["kernel"] == {"file": "vmlinux", "sha256": sha256(rig.kernel), "size": rig.kernel.stat().st_size}
    assert manifest["rootfs"] == {
        "file": "rootfs.ext4",
        "sha256": sha256(image_dir / "rootfs.ext4"),
        "size": (image_dir / "rootfs.ext4").stat().st_size,
    }


@pytest.mark.needs_root
def test_the_provenance_says_exactly_what_the_image_was_built_from(rig: Rig) -> None:
    rig.pin_everything()
    assert rig.with_rootfs_tar().returncode == 0
    provenance = str(manifest_of(rig.out_root / "python")["provenance"])
    fields = dict(part.split("=", 1) for part in provenance.split("; ")[1:])
    assert provenance.startswith("acf-image-build/1; ")
    assert fields == {
        "image": "python",
        "arch": ARCH,
        "base": f"external-rootfs-tarball sha256:{sha256(rig.tarball)}",
        "kernel_sha256": sha256(rig.kernel),
        "agent_sha256": "external",
        "source_date_epoch": EPOCH,
        "git": "none",
        "pinned": "external-rootfs",
    }


@pytest.mark.needs_root
def test_an_unpinned_build_is_marked_unpinned_in_the_manifest_and_warned_about(rig: Rig) -> None:
    result = rig.with_rootfs_tar("--allow-unpinned")
    assert result.returncode == 0, result.stderr
    provenance = str(manifest_of(rig.out_root / "python")["provenance"])
    assert f"pinned=no; unpinned=KERNEL_SHA256_{ARCH}" in provenance
    assert "NOT fully pinned" in result.stderr
    assert "do not ship it" in result.stderr


@pytest.mark.needs_root
def test_a_build_from_an_external_rootfs_is_flagged_even_when_every_pin_is_set(rig: Rig) -> None:
    rig.pin_everything()
    result = rig.with_rootfs_tar()
    assert result.returncode == 0, result.stderr
    assert "came from an external tarball" in result.stderr
    assert "NOT fully pinned" not in result.stderr, "nothing is UNSET: that warning is for missing pins"


@pytest.mark.needs_root
def test_rebuilding_replaces_the_image_and_leaves_no_staging_directories(rig: Rig) -> None:
    rig.pin_everything()
    first = rig.with_rootfs_tar()
    assert first.returncode == 0, first.stderr
    rig.kernel.write_bytes(rig.kernel.read_bytes() + b"x")  # a different kernel: a different image
    rig.pin_everything()
    second = rig.with_rootfs_tar()
    assert second.returncode == 0, second.stderr
    assert first.stdout != second.stdout
    assert sorted(p.name for p in rig.out_root.iterdir()) == ["python"], (
        "no .stage.* or *.old.* left in the output root"
    )
    assert verify(rig.tree, rig.out_root / "python").returncode == 0


@pytest.mark.needs_root
def test_install_puts_a_verified_root_owned_copy_into_the_state_root(rig: Rig) -> None:
    rig.pin_everything()
    state = rig.tmp / "state"
    result = rig.with_rootfs_tar("--install", "--state-root", state)
    assert result.returncode == 0, result.stderr
    installed = state / "images" / "python"
    assert sorted(p.name for p in installed.iterdir()) == ["manifest.json", "rootfs.ext4", "vmlinux"]
    for p in (installed, *installed.iterdir()):
        assert (p.stat().st_uid, p.stat().st_gid) == (0, 0), p
    assert stat.S_IMODE(installed.stat().st_mode) == 0o755
    for p in installed.iterdir():
        assert stat.S_IMODE(p.stat().st_mode) == 0o644, p
    assert verify(rig.tree, installed).returncode == 0
    assert (installed / "manifest.json").read_bytes() == (rig.out_root / "python/manifest.json").read_bytes()
    assert sorted(p.name for p in (state / "images").iterdir()) == ["python"], "the staging directory must be gone"
    assert f"installed into {state / 'images'}" in result.stderr


@pytest.mark.needs_root
def test_installing_again_replaces_the_installed_image(rig: Rig) -> None:
    rig.pin_everything()
    state = rig.tmp / "state"
    assert rig.with_rootfs_tar("--install", "--state-root", state).returncode == 0
    old = (state / "images/python/manifest.json").read_bytes()
    rig.kernel.write_bytes(rig.kernel.read_bytes() + b"y")
    rig.pin_everything()
    assert rig.with_rootfs_tar("--install", "--state-root", state).returncode == 0
    assert (state / "images/python/manifest.json").read_bytes() != old
    assert sorted(p.name for p in (state / "images").iterdir()) == ["python"]


@pytest.mark.needs_root
def test_a_rootfs_that_would_not_boot_leaves_no_image_behind(rig: Rig) -> None:
    rig.pin_everything()
    rootfs_tarball(rig.tarball, omit=["usr/local/bin/acf-guest-agent"])
    result = rig.with_rootfs_tar()
    assert result.returncode == 1
    assert "does not meet the guest requirements" in result.stderr
    assert not (rig.out_root / "python").exists()
    assert list(rig.out_root.iterdir()) == [], "the staging directory must be cleaned up on failure"


@pytest.mark.needs_root
def test_not_enough_scratch_space_is_reported_before_the_build_starts(rig: Rig) -> None:
    rig.pin_everything()
    result = rig.with_rootfs_tar(env={"ACF_MIN_FREE_MIB": "999999999"})
    assert result.returncode == 1
    assert "needs about 999999999 MiB free" in result.stderr
    assert "TMPDIR" in result.stderr


@pytest.mark.needs_root
@pytest.mark.parametrize("image", ["base", "node", "browser"])
def test_every_recipe_name_builds_and_is_named_in_its_manifest(rig: Rig, image: str) -> None:
    rig.pin_everything(image)
    result = rig.with_rootfs_tar(image=image)
    assert result.returncode == 0, result.stderr
    assert manifest_of(rig.out_root / image)["name"] == image
    assert f"image={image};" in str(manifest_of(rig.out_root / image)["provenance"])


# ---------------------------------------------------------------- the container path, with a stub docker

STUB_DOCKER = r"""#!/bin/sh
# Records every call and its build context, then answers `buildx build` with the prepared tarball.
echo "docker $*" >>"$ACF_STUB_LOG"
if [ "$1" = buildx ] && [ "$2" = version ]; then
    [ -z "$ACF_STUB_NO_BUILDX" ] || exit 1
    exit 0
fi
if [ "$1" = buildx ] && [ "$2" = build ]; then
    [ -z "$ACF_STUB_BUILD_FAILS" ] || { echo "stub: build failed" >&2; exit 1; }
    for last; do :; done                  # the build context is the last argument
    (cd "$last" && find . -type f | sort) >"$ACF_STUB_LOG.context"
    cp "$last/Dockerfile" "$ACF_STUB_LOG.dockerfile"
    cp "$last/requirements.txt" "$ACF_STUB_LOG.requirements"
    for arg; do
        case "$arg" in type=tar,dest=*) dest=${arg#type=tar,dest=} ;; esac
    done
    cp "$ACF_STUB_TARBALL" "$dest"
    exit 0
fi
exit 99
"""


@pytest.fixture
def docker(rig: Rig, tmp_path: Path) -> Path:
    stub = tmp_path / "docker"
    stub.write_text(STUB_DOCKER)
    stub.chmod(0o755)
    return stub


def docker_env(rig: Rig, **extra: str) -> dict[str, str]:
    return {"ACF_STUB_LOG": str(rig.tmp / "docker.log"), "ACF_STUB_TARBALL": str(rig.tarball), **extra}


@pytest.mark.needs_root
def test_the_container_path_builds_from_the_digest_pinned_base_for_the_right_platform(rig: Rig, docker: Path) -> None:
    rig.pin_everything()
    requirements = rig.tmp / "requirements.txt"
    requirements.write_text("numpy==2.3.0 \\\n    --hash=sha256:" + "1" * 64 + "\n")
    result = rig.build(
        "--guest-agent", rig.agent, "--docker", docker, "--requirements", requirements, env=docker_env(rig)
    )
    assert result.returncode == 0, result.stderr

    calls = (rig.tmp / "docker.log").read_text().splitlines()
    assert calls[0] == "docker buildx version"
    (build_call,) = [c for c in calls if c.startswith("docker buildx build")]
    base = "public.ecr.aws/docker/library/python:3.14-slim-trixie"
    platform = "linux/amd64" if ARCH == "x86_64" else "linux/arm64"
    assert "--pull" in build_call
    assert f"--platform {platform}" in build_call
    assert f"--build-arg BASE_REF={base}@{DIGEST}" in build_call
    assert f"--build-arg SOURCE_DATE_EPOCH={EPOCH}" in build_call

    context = (rig.tmp / "docker.log.context").read_text().splitlines()
    assert "./Dockerfile" in context
    assert "./acf-guest-agent" in context
    assert "./requirements.txt" in context
    assert "./overlay/usr/local/sbin/acf-init" in context
    assert (rig.tmp / "docker.log.dockerfile").read_bytes() == (rig.tree / "images/python/Dockerfile").read_bytes()
    assert (rig.tmp / "docker.log.requirements").read_bytes() == requirements.read_bytes()

    provenance = str(manifest_of(rig.out_root / "python")["provenance"])
    assert f"base={base}@{DIGEST}" in provenance
    assert f"agent_sha256={sha256(rig.agent)}" in provenance
    assert provenance.endswith("pinned=yes")
    assert "NOT fully pinned" not in result.stderr
    assert "external tarball" not in result.stderr


@pytest.mark.needs_root
def test_without_requirements_the_context_still_has_an_empty_requirements_file(rig: Rig, docker: Path) -> None:
    rig.pin_everything("node")
    result = rig.build("--guest-agent", rig.agent, "--docker", docker, image="node", env=docker_env(rig))
    assert result.returncode == 0, result.stderr
    assert (rig.tmp / "docker.log.requirements").read_bytes() == b""


@pytest.mark.needs_root
def test_a_failing_container_build_is_an_error_and_leaves_no_image(rig: Rig, docker: Path) -> None:
    rig.pin_everything()
    result = rig.build("--guest-agent", rig.agent, "--docker", docker, env=docker_env(rig, ACF_STUB_BUILD_FAILS="1"))
    assert result.returncode == 1
    assert "the container build failed" in result.stderr
    assert not (rig.out_root / "python").exists()


@pytest.mark.needs_root
def test_a_docker_without_buildx_is_refused_with_the_reason(rig: Rig, docker: Path) -> None:
    rig.pin_everything()
    result = rig.build("--guest-agent", rig.agent, "--docker", docker, env=docker_env(rig, ACF_STUB_NO_BUILDX="1"))
    assert result.returncode == 1
    assert "'" + str(docker) + " buildx' is required" in result.stderr


@pytest.mark.needs_root
def test_a_missing_container_engine_says_how_to_avoid_needing_one(rig: Rig) -> None:
    rig.pin_everything()
    result = rig.build("--guest-agent", rig.agent, "--docker", "definitely-not-docker")
    assert result.returncode == 1
    assert "required command not found: definitely-not-docker" in result.stderr
    assert "--rootfs-tar" in result.stderr


@pytest.mark.needs_root
def test_an_unpinned_container_build_uses_the_tag_and_says_so(rig: Rig, docker: Path) -> None:
    result = rig.build("--guest-agent", rig.agent, "--docker", docker, "--allow-unpinned", env=docker_env(rig))
    assert result.returncode == 0, result.stderr
    (build_call,) = [
        c for c in (rig.tmp / "docker.log").read_text().splitlines() if c.startswith("docker buildx build")
    ]
    assert "BASE_REF=public.ecr.aws/docker/library/python:3.14-slim-trixie " in build_call + " ", (
        "no @digest when none is pinned"
    )
    assert "@sha256" not in build_call
    provenance = str(manifest_of(rig.out_root / "python")["provenance"])
    assert f"pinned=no; unpinned=BASE_DIGEST_python,KERNEL_SHA256_{ARCH}" in provenance


@pytest.mark.needs_root
def test_scripts_are_not_run_from_the_build_context_dir(rig: Rig, docker: Path) -> None:
    """The overlay's init must reach the Dockerfile unchanged: the context copy is byte-identical to the repository's."""
    rig.pin_everything()
    assert rig.build("--guest-agent", rig.agent, "--docker", docker, env=docker_env(rig)).returncode == 0
    assert (rig.tmp / "docker.log.context").read_text().count("./overlay/") >= 1
    assert os.access(rig.tree / "images/overlay/usr/local/sbin/acf-init", os.X_OK)
