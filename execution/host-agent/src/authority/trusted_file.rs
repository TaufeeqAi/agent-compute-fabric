//! The trusted-input rule (contract TI-1): integrity-checked loading of the host configuration, the
//! safety profile, the enrolment table, secrets and TLS material.
//!
//! The classic bug is *check the path, then open the path*: an attacker swaps the file between
//! the two. Here every check is performed on the **already-open file descriptor** (`fstat`), and
//! the bytes that are hashed and parsed are read from that same descriptor, so what was verified
//! is exactly what is used.
//!
//! Rejected: symlinks (`O_NOFOLLOW`), non-regular files, files not owned by an allowed uid,
//! group/world-writable files, oversize files, and files with a group/world-writable
//! ancestor directory (an unprivileged user who can write the directory can rename it away).
//!
//! A linked ancestor (`/var/run` → `/run`) is judged by the directory it points to **and** by every
//! directory that one is reached through: whoever can write any of them can swap what the link names.
//!
//! Executables the core runs obey the same rule ([`trusted_executable`]). A distribution may ship a
//! tool as a link (`/usr/sbin/ip` → `/bin/ip`), so for an executable the leaf may be a link; the file
//! it resolves to, and the directories on the way to it, are then held to the rule as well.

use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::error::{AcfError, FailureClass, Result};

pub const MAX_TRUSTED_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct TrustedBytes {
    pub bytes: Vec<u8>,
    /// Lowercase hex sha256 of `bytes`.
    pub sha256: String,
}

fn deny(msg: impl Into<String>) -> AcfError {
    AcfError::new(FailureClass::SecurityControlFailure, msg)
}

/// `allowed_owner_uids` is `[0]` in production; tests pass the current euid.
pub fn read_trusted(path: &Path, allowed_owner_uids: &[u32]) -> Result<TrustedBytes> {
    read_trusted_from(Path::new("/"), path, allowed_owner_uids)
}

/// [`read_trusted`] with the ancestor walk starting at `start` instead of `/`: `start` itself and every directory
/// below it are checked, the ones above it are not. Production always starts at `/`. The tests start at a directory
/// they built, so what they prove does not depend on where the machine keeps its temp directory (a test that can only
/// pass under a world-writable `/tmp` proves nothing about the walk). Private on purpose: a caller that could choose
/// `start` could choose to skip the directories that matter.
fn read_trusted_from(start: &Path, path: &Path, allowed_owner_uids: &[u32]) -> Result<TrustedBytes> {
    check_ancestors_from(start, path, allowed_owner_uids)?;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::CLOEXEC.bits() as i32)
        .open(path)
        .map_err(|e| deny(format!("cannot open {} safely: {e}", path.display())))?;
    let md = file.metadata()?;
    if !md.is_file() {
        return Err(deny(format!("{} is not a regular file", path.display())));
    }
    if !allowed_owner_uids.contains(&md.uid()) {
        return Err(deny(format!("{} is owned by uid {}, which is not trusted", path.display(), md.uid())));
    }
    if md.mode() & 0o022 != 0 {
        return Err(deny(format!("{} is group- or world-writable (mode {:o})", path.display(), md.mode() & 0o7777)));
    }
    if md.len() > MAX_TRUSTED_FILE_BYTES {
        return Err(deny(format!("{} is larger than {MAX_TRUSTED_FILE_BYTES} bytes", path.display())));
    }
    let mut bytes = Vec::with_capacity(md.len() as usize);
    // `take` guards against the file growing after fstat.
    File::take(file, MAX_TRUSTED_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TRUSTED_FILE_BYTES {
        return Err(deny(format!("{} grew beyond {MAX_TRUSTED_FILE_BYTES} bytes while reading", path.display())));
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(TrustedBytes { bytes, sha256 })
}

/// Every ancestor directory must be a real directory owned by a trusted uid and not writable by
/// group/other. (Sticky-bit directories like /tmp are *not* exempted: a trusted file must not
/// live somewhere unprivileged users can create siblings it could be confused with.)
pub fn check_ancestors(path: &Path, allowed_owner_uids: &[u32]) -> Result<()> {
    check_ancestors_from(Path::new("/"), path, allowed_owner_uids)
}

/// The walk behind [`check_ancestors`]; see [`read_trusted_from`] for what `start` means.
fn check_ancestors_from(start: &Path, path: &Path, allowed_owner_uids: &[u32]) -> Result<()> {
    let abs: PathBuf = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    walk(start, &abs, allowed_owner_uids)?;
    // A linked ancestor was judged above by the directory it points to. The directories *that* one is
    // reached through must hold the same property, so the resolved chain is walked as well.
    if let Some(parent) = abs.parent() {
        let real = std::fs::canonicalize(parent).map_err(|e| deny(format!("cannot resolve {}: {e}", parent.display())))?;
        if real != parent {
            walk(start, &real.join("leaf"), allowed_owner_uids)?;
        }
    }
    Ok(())
}

/// Check every directory component of `abs` except the leaf.
fn walk(start: &Path, abs: &Path, allowed_owner_uids: &[u32]) -> Result<()> {
    let mut cur = PathBuf::new();
    let comps: Vec<Component<'_>> = abs.components().collect();
    for (i, c) in comps.iter().enumerate() {
        cur.push(c.as_os_str());
        if i + 1 == comps.len() {
            break; // the leaf is checked on its fd
        }
        if !cur.starts_with(start) {
            continue; // above `start`; with `start == "/"` (production) this never skips anything
        }
        let md = std::fs::symlink_metadata(&cur).map_err(|e| deny(format!("cannot stat {}: {e}", cur.display())))?;
        if md.file_type().is_symlink() {
            // Symlinked ancestors (e.g. /var/run -> /run) are resolved by the kernel, then
            // checked as real directories below via `metadata` (follows links).
            let real = std::fs::metadata(&cur).map_err(|e| deny(format!("dangling ancestor {}: {e}", cur.display())))?;
            ancestor_ok(&cur, &real, allowed_owner_uids)?;
        } else {
            ancestor_ok(&cur, &md, allowed_owner_uids)?;
        }
    }
    Ok(())
}

/// TI-1 for an executable the core runs: reached through trusted directories, owned by a trusted
/// uid, not writable by group or other, and executable. The configured path may be a link placed by a
/// trusted owner; the file it resolves to is then held to the same rule.
///
/// An executable cannot be run from an open descriptor here, so this is a check of the path at the
/// time of the call. It is sound because every directory on both chains is writable by trusted owners
/// only: nobody else can change what the name resolves to between the check and the use.
pub fn trusted_executable(path: &Path, allowed_owner_uids: &[u32]) -> Result<()> {
    trusted_executable_from(Path::new("/"), path, allowed_owner_uids)
}

/// [`trusted_executable`] with the ancestor walk starting at `start`; see [`read_trusted_from`].
fn trusted_executable_from(start: &Path, path: &Path, allowed_owner_uids: &[u32]) -> Result<()> {
    let unavailable = |m: String| AcfError::new(FailureClass::DependencyUnavailable, m);
    check_ancestors_from(start, path, allowed_owner_uids)?;
    let real = std::fs::canonicalize(path).map_err(|e| unavailable(format!("{}: {e}", path.display())))?;
    if real != path {
        check_ancestors_from(start, &real, allowed_owner_uids)?;
    }
    let md = std::fs::symlink_metadata(&real).map_err(|e| unavailable(format!("{}: {e}", real.display())))?;
    if !md.is_file() {
        return Err(deny(format!("{} is not a regular file", real.display())));
    }
    if !allowed_owner_uids.contains(&md.uid()) {
        return Err(deny(format!("{} is owned by untrusted uid {}", real.display(), md.uid())));
    }
    if md.permissions().mode() & 0o022 != 0 {
        return Err(deny(format!("{} is group/world-writable", real.display())));
    }
    if md.permissions().mode() & 0o111 == 0 {
        return Err(unavailable(format!("{} is not executable", real.display())));
    }
    Ok(())
}

fn ancestor_ok(p: &Path, md: &std::fs::Metadata, allowed: &[u32]) -> Result<()> {
    if !md.is_dir() {
        return Err(deny(format!("ancestor {} is not a directory", p.display())));
    }
    if !allowed.contains(&md.uid()) {
        return Err(deny(format!("ancestor directory {} is owned by untrusted uid {}", p.display(), md.uid())));
    }
    if md.mode() & 0o022 != 0 {
        return Err(deny(format!("ancestor directory {} is group/world-writable (mode {:o})", p.display(), md.mode() & 0o7777)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn me() -> Vec<u32> {
        vec![rustix::process::geteuid().as_raw()]
    }

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mkdir(p: &Path) {
        std::fs::create_dir_all(p).unwrap();
        chmod(p, 0o755);
    }

    fn write_policy(p: &Path) {
        std::fs::write(p, b"hello: world\n").unwrap();
        chmod(p, 0o644);
    }

    /// A private directory with a policy file in it. Every test below starts the ancestor walk AT this directory
    /// (`read_trusted_from(d.path(), ..)`), so a verdict never depends on where the machine keeps `$TMPDIR` or on who
    /// owns `$HOME`: the walk is judged on directories the test built, with a mode the test chose.
    fn setup() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        chmod(d.path(), 0o755);
        let f = d.path().join("policy.yaml");
        write_policy(&f);
        (d, f)
    }

    /// The refusal's message, after checking that it is the security-control class (never a generic I/O error).
    fn denied<T: std::fmt::Debug>(r: Result<T>) -> String {
        let e = r.expect_err("must be refused");
        assert_eq!(e.class, FailureClass::SecurityControlFailure, "{}", e.message);
        e.message
    }

    #[test]
    fn reads_and_hashes_the_exact_bytes() {
        let (d, f) = setup();
        let t = read_trusted_from(d.path(), &f, &me()).expect("a private tree owned by a trusted uid is accepted");
        assert_eq!(t.bytes, b"hello: world\n");
        assert_eq!(t.sha256, hex::encode(Sha256::digest(b"hello: world\n")));
    }

    #[test]
    fn a_file_writable_by_group_or_other_is_rejected() {
        let (d, f) = setup();
        for mode in [0o664, 0o646, 0o666, 0o620, 0o602] {
            chmod(&f, mode);
            let m = denied(read_trusted_from(d.path(), &f, &me()));
            assert!(m.contains("is group- or world-writable"), "mode {mode:o}: {m}");
        }
    }

    #[test]
    fn a_symlink_leaf_is_rejected_without_following() {
        let (d, f) = setup();
        let link = d.path().join("link.yaml");
        symlink(&f, &link).unwrap();
        let m = denied(read_trusted_from(d.path(), &link, &me()));
        assert!(m.contains("cannot open") && m.contains("safely"), "{m}");
    }

    #[test]
    fn a_file_owned_by_an_untrusted_uid_is_rejected() {
        let (_d, f) = setup();
        let not_me = [rustix::process::geteuid().as_raw().wrapping_add(4242)];
        // Starting the walk at the file itself skips every ancestor, which isolates the file's own owner check.
        let m = denied(read_trusted_from(&f, &f, &not_me));
        assert!(m.contains("which is not trusted"), "{m}");
    }

    #[test]
    fn oversize_and_non_regular_files_are_rejected() {
        let (d, f) = setup();
        std::fs::write(&f, vec![b'a'; MAX_TRUSTED_FILE_BYTES as usize + 1]).unwrap();
        chmod(&f, 0o644);
        let m = denied(read_trusted_from(d.path(), &f, &me()));
        assert!(m.contains("is larger than"), "{m}");

        let sub = d.path().join("sub");
        mkdir(&sub);
        let m = denied(read_trusted_from(d.path(), &sub, &me()));
        assert!(m.contains("is not a regular file"), "a directory is not a trusted file: {m}");
    }

    #[test]
    fn a_group_or_world_writable_ancestor_is_rejected_even_when_sticky() {
        let (d, f) = setup();
        for mode in [0o775, 0o757, 0o777, 0o1777, 0o2775] {
            chmod(d.path(), mode);
            let m = denied(read_trusted_from(d.path(), &f, &me()));
            assert!(m.contains("is group/world-writable"), "mode {mode:o}: {m}");
            assert!(m.contains(&d.path().display().to_string()), "the message names the directory: {m}");
        }
    }

    #[test]
    fn every_directory_between_the_start_and_the_file_is_checked() {
        let (d, _f) = setup();
        let a = d.path().join("a");
        let b = a.join("b");
        mkdir(&b);
        let deep = b.join("policy.yaml");
        write_policy(&deep);
        read_trusted_from(d.path(), &deep, &me()).expect("a clean three-level tree is accepted");

        chmod(&a, 0o777);
        let m = denied(read_trusted_from(d.path(), &deep, &me()));
        assert!(m.contains(&format!("ancestor directory {} is group/world-writable", a.display())), "{m}");
    }

    #[test]
    fn a_symlinked_ancestor_is_judged_by_the_directory_it_points_to() {
        let (d, _f) = setup();
        let real = d.path().join("real");
        mkdir(&real);
        write_policy(&real.join("policy.yaml"));
        let link = d.path().join("link");
        symlink(&real, &link).unwrap();
        let through = link.join("policy.yaml");
        read_trusted_from(d.path(), &through, &me()).expect("a link to a clean directory is accepted");

        chmod(&real, 0o777);
        let m = denied(read_trusted_from(d.path(), &through, &me()));
        assert!(m.contains(&format!("ancestor directory {} is group/world-writable", link.display())), "{m}");
    }

    #[test]
    fn a_linked_ancestor_reached_through_a_writable_directory_is_rejected() {
        let (d, _f) = setup();
        // d/open is writable by others; d/open/target is clean. A link to the clean directory looks fine
        // by itself, but whoever can write d/open can replace `target` with a directory of their own.
        let open = d.path().join("open");
        let target = open.join("target");
        mkdir(&target);
        write_policy(&target.join("policy.yaml"));
        let link = d.path().join("link");
        symlink(&target, &link).unwrap();
        let through = link.join("policy.yaml");
        read_trusted_from(d.path(), &through, &me()).expect("clean while every directory on the way is clean");

        chmod(&open, 0o777);
        let m = denied(read_trusted_from(d.path(), &through, &me()));
        assert!(m.contains(&format!("ancestor directory {} is group/world-writable", open.display())), "{m}");
    }

    fn tool(p: &Path) {
        std::fs::write(p, b"#!/bin/sh\n").unwrap();
        chmod(p, 0o755);
    }

    #[test]
    fn an_executable_must_be_owned_closed_to_others_and_executable() {
        let (d, _f) = setup();
        let bin = d.path().join("tool");
        tool(&bin);
        trusted_executable_from(d.path(), &bin, &me()).expect("a private, executable file of a trusted owner");

        for mode in [0o775, 0o757, 0o777] {
            chmod(&bin, mode);
            let m = denied(trusted_executable_from(d.path(), &bin, &me()));
            assert!(m.contains("is group/world-writable"), "mode {mode:o}: {m}");
        }
        chmod(&bin, 0o644);
        let e = trusted_executable_from(d.path(), &bin, &me()).expect_err("not executable");
        assert_eq!(e.class, FailureClass::DependencyUnavailable, "{}", e.message);

        chmod(&bin, 0o755);
        let not_me = [rustix::process::geteuid().as_raw().wrapping_add(4242)];
        let m = denied(trusted_executable_from(&bin, &bin, &not_me));
        assert!(m.contains("is owned by untrusted uid"), "{m}");

        let e = trusted_executable_from(d.path(), &d.path().join("absent"), &me()).expect_err("missing");
        assert_eq!(e.class, FailureClass::DependencyUnavailable, "{}", e.message);
        let m = denied(trusted_executable_from(d.path(), d.path(), &me()));
        assert!(m.contains("is not a regular file"), "a directory is not an executable: {m}");
    }

    #[test]
    fn a_linked_executable_is_judged_by_the_file_it_resolves_to_and_the_way_there() {
        let (d, _f) = setup();
        let (sbin, bin) = (d.path().join("sbin"), d.path().join("bin"));
        mkdir(&sbin);
        mkdir(&bin);
        tool(&bin.join("ip"));
        // The way distributions ship some tools: sbin/ip -> ../bin/ip.
        let link = sbin.join("ip");
        symlink(bin.join("ip"), &link).unwrap();
        trusted_executable_from(d.path(), &link, &me()).expect("a link in a clean directory to a clean file");

        // The directory the file really lives in is open to others: the name is clean, the file is not safe.
        chmod(&bin, 0o777);
        let m = denied(trusted_executable_from(d.path(), &link, &me()));
        assert!(m.contains(&format!("ancestor directory {} is group/world-writable", bin.display())), "{m}");
        chmod(&bin, 0o755);

        // The file it resolves to is writable by others.
        chmod(&bin.join("ip"), 0o777);
        let m = denied(trusted_executable_from(d.path(), &link, &me()));
        assert!(m.contains(&format!("{} is group/world-writable", bin.join("ip").display())), "{m}");
        chmod(&bin.join("ip"), 0o755);

        // The directory holding the link is open to others: anyone could re-point the name.
        chmod(&sbin, 0o777);
        let m = denied(trusted_executable_from(d.path(), &link, &me()));
        assert!(m.contains(&format!("ancestor directory {} is group/world-writable", sbin.display())), "{m}");
    }

    #[test]
    fn dangling_missing_and_non_directory_ancestors_are_rejected() {
        let (d, f) = setup();
        symlink(d.path().join("nowhere"), d.path().join("dangling")).unwrap();
        let m = denied(read_trusted_from(d.path(), &d.path().join("dangling/policy.yaml"), &me()));
        assert!(m.contains("dangling ancestor"), "{m}");

        let m = denied(read_trusted_from(d.path(), &d.path().join("missing/policy.yaml"), &me()));
        assert!(m.contains("cannot stat"), "{m}");

        let m = denied(read_trusted_from(d.path(), &f.join("inside.yaml"), &me()));
        assert!(m.contains("is not a directory"), "{m}");
    }

    #[test]
    fn the_production_walk_starts_at_the_filesystem_root() {
        let (_d, f) = setup();
        // No real directory is owned by this uid, so the first ancestor examined is the one that is rejected: `/`.
        let nobody = [u32::MAX - 1];
        let m = denied(check_ancestors(&f, &nobody));
        assert!(m.starts_with("ancestor directory / is owned by untrusted uid"), "{m}");
        let m = denied(read_trusted(&f, &nobody));
        assert!(m.starts_with("ancestor directory / is owned by untrusted uid"), "{m}");
    }
}
