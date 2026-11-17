//! The narrow durable operation journal (spec §10.2, §21).
//!
//! # Model
//! An append-only file of checksummed *batches*. Each batch is one line:
//!
//! ```text
//! <crc32 hex, 8 chars> <space> <json {"seq":N,"entries":[...]}> \n
//! ```
//!
//! Entries are **full-record upserts** (the latest record for a key wins), not domain events: the
//! file is a write-ahead log for a tiny key-value state, deliberately *not* an event-sourced
//! store (spec §31). A batch is the unit of atomicity — either every entry in it is visible
//! after a crash, or none is.
//!
//! # Durability and ordering
//! `commit_with` holds one mutex across *check → append → fsync → apply*. That single critical
//! section is what makes idempotent `begin`, atomic capacity admission and generation
//! compare-and-swap correct without further locking. State is applied in memory **only after**
//! the fsync succeeds, so memory never runs ahead of disk.
//!
//! # Corruption (spec §21.4) — nothing corrupt is silently believed
//! * **Torn tail** (partial final line, or a bad final record): the signature of a crash during
//!   append. Safe to drop; truncated and reported as `TornTailRepaired`.
//! * **Mid-file corruption** (a bad record *followed by valid ones*) cannot be a crash artefact.
//!   The journal opens `Corrupt`: reads work, **every mutation is refused** with
//!   `RECOVERY_QUARANTINED` until an operator intervenes.

use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use super::records::{
    Entry, GenerationRecord, OperationRecord, QuarantineRecord, RecoveryRecord, RuntimeManifestRecord, SandboxRecord, SnapshotRecord,
};
use crate::{
    error::{AcfError, FailureClass, Result},
    ids::{Generation, OperationId, RecoveryId, SandboxId, SnapshotId},
};

/// A single committed batch may not exceed this (keeps recovery's per-record cost bounded and
/// stops a bug from stuffing output bytes into the journal).
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// Refuse to open (and ask for compaction) beyond this size.
pub const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const KEEP_RUNTIME_MANIFESTS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integrity {
    Clean,
    TornTailRepaired { dropped_bytes: u64 },
    Corrupt { line: u64, reason: String },
}

#[derive(Debug, Clone)]
pub struct OpenReport {
    pub integrity: Integrity,
    pub batches: u64,
    pub bytes: u64,
}

/// Materialised current state: the latest record per key.
#[derive(Debug, Default, Clone)]
pub struct JournalState {
    pub operations: HashMap<OperationId, OperationRecord>,
    pub sandboxes: HashMap<SandboxId, SandboxRecord>,
    pub generations: BTreeMap<(SandboxId, Generation), GenerationRecord>,
    pub snapshots: BTreeMap<(SnapshotId, Generation), SnapshotRecord>,
    pub recoveries: HashMap<RecoveryId, RecoveryRecord>,
    pub quarantines: Vec<QuarantineRecord>,
    pub runtime_manifests: Vec<RuntimeManifestRecord>,
}

impl JournalState {
    fn apply(&mut self, e: &Entry) {
        match e {
            Entry::Operation(r) => {
                self.operations.insert(r.operation_id.clone(), (**r).clone());
            }
            Entry::Sandbox(r) => {
                self.sandboxes.insert(r.sandbox_id.clone(), r.clone());
            }
            Entry::Generation(r) => {
                self.generations.insert((r.sandbox_id.clone(), r.generation), (**r).clone());
            }
            Entry::Snapshot(r) => {
                self.snapshots.insert((r.snapshot_id.clone(), r.generation), (**r).clone());
            }
            Entry::Recovery(r) => {
                self.recoveries.insert(r.recovery_id.clone(), r.clone());
            }
            Entry::Quarantine(r) => {
                if !self.quarantines.contains(r) {
                    self.quarantines.push(r.clone());
                }
            }
            Entry::RuntimeManifest(r) => {
                self.runtime_manifests.push(r.clone());
                let excess = self.runtime_manifests.len().saturating_sub(KEEP_RUNTIME_MANIFESTS);
                self.runtime_manifests.drain(..excess);
            }
        }
    }

    /// Latest generation record of a sandbox, if any.
    pub fn current_generation(&self, id: &SandboxId) -> Option<&GenerationRecord> {
        let cur = self.sandboxes.get(id)?.current;
        self.generations.get(&(id.clone(), cur))
    }

    /// Names resolve only to a sandbox whose *current* generation is not destroyed: destroying a
    /// sandbox frees its name, and a freed name must never resolve to the dead one.
    pub fn sandbox_by_name(&self, name: &str) -> Option<&SandboxRecord> {
        self.sandboxes.values().find(|s| {
            s.name.as_deref() == Some(name)
                && self.current_generation(&s.sandbox_id).is_some_and(|g| g.state != crate::domain::LifecycleState::Destroyed)
        })
    }

    pub fn snapshot_by_name(&self, name: &str) -> Option<&SnapshotRecord> {
        self.snapshots.values().filter(|s| s.name.as_deref() == Some(name) && s.holds_storage()).max_by_key(|s| s.generation)
    }

    pub fn live_generations(&self) -> impl Iterator<Item = &GenerationRecord> {
        self.generations.values().filter(|g| g.holds_reservation())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Batch {
    seq: u64,
    entries: Vec<Entry>,
}

#[derive(Debug)]
struct Inner {
    file: File,
    state: JournalState,
    next_seq: u64,
    len: u64,
    /// Set after a mid-file corruption or an unrecoverable append failure.
    poisoned: Option<String>,
    #[cfg(feature = "testing")]
    fail_next_append: bool,
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    inner: Mutex<Inner>,
}

fn encode(batch: &Batch) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(batch)?;
    if json.len() > MAX_BATCH_BYTES {
        return Err(AcfError::internal(format!(
            "journal batch of {} bytes exceeds the {MAX_BATCH_BYTES}-byte limit; large payloads belong in artifacts",
            json.len()
        )));
    }
    let crc = crc32fast::hash(&json);
    let mut line = Vec::with_capacity(json.len() + 10);
    line.extend_from_slice(format!("{crc:08x} ").as_bytes());
    line.extend_from_slice(&json);
    line.push(b'\n');
    Ok(line)
}

fn decode_line(line: &[u8]) -> std::result::Result<Batch, String> {
    if line.len() < 10 || line[8] != b' ' {
        return Err("malformed record framing".into());
    }
    let crc_hex = std::str::from_utf8(&line[..8]).map_err(|_| "non-utf8 checksum")?;
    let want = u32::from_str_radix(crc_hex, 16).map_err(|_| "non-hex checksum")?;
    let json = &line[9..];
    let got = crc32fast::hash(json);
    if got != want {
        return Err(format!("checksum mismatch (stored {want:08x}, computed {got:08x})"));
    }
    serde_json::from_slice::<Batch>(json).map_err(|e| format!("valid checksum but undecodable batch: {e}"))
}

fn fsync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

impl Journal {
    pub fn open(path: &Path) -> Result<(Self, OpenReport)> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let existed = path.exists();
        let mut file = OpenOptions::new().read(true).append(true).create(true).mode(0o600).open(path)?;
        if !existed && let Some(dir) = path.parent() {
            fsync_dir(dir)?;
        }
        let size = file.metadata()?.len();
        if size > MAX_JOURNAL_BYTES {
            return Err(AcfError::new(
                FailureClass::ResourceExhaustion,
                format!("journal is {size} bytes (> {MAX_JOURNAL_BYTES}); run compaction before starting"),
            ));
        }
        let mut bytes = Vec::with_capacity(size as usize);
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut bytes)?;

        let mut state = JournalState::default();
        let mut next_seq = 1u64;
        let mut good_end = 0usize;
        let mut batches = 0u64;
        let mut integrity = Integrity::Clean;
        let mut poisoned = None;

        let mut pos = 0usize;
        let mut line_no = 0u64;
        while pos < bytes.len() {
            line_no += 1;
            let rest = &bytes[pos..];
            let Some(nl) = rest.iter().position(|b| *b == b'\n') else {
                // Final segment without a newline: a torn append.
                integrity = Integrity::TornTailRepaired { dropped_bytes: rest.len() as u64 };
                break;
            };
            let line = &rest[..nl];
            let line_end = pos + nl + 1;
            match decode_line(line) {
                Ok(b) if b.seq == next_seq => {
                    for e in &b.entries {
                        state.apply(e);
                    }
                    next_seq = b.seq + 1;
                    batches += 1;
                    good_end = line_end;
                    pos = line_end;
                }
                bad => {
                    let reason = match bad {
                        Ok(b) => format!("sequence break: expected {next_seq}, found {}", b.seq),
                        Err(r) => r,
                    };
                    if line_end == bytes.len() {
                        // Bad *last* record: indistinguishable from a torn append. Drop it.
                        integrity = Integrity::TornTailRepaired { dropped_bytes: (bytes.len() - good_end) as u64 };
                    } else {
                        // Valid-looking data follows: this is real corruption, not a crash.
                        integrity = Integrity::Corrupt { line: line_no, reason: reason.clone() };
                        poisoned = Some(format!("journal corrupt at line {line_no}: {reason}"));
                    }
                    break;
                }
            }
        }

        if let Integrity::TornTailRepaired { .. } = integrity {
            file.set_len(good_end as u64)?;
            file.sync_all()?;
        }
        let len = if poisoned.is_some() { bytes.len() as u64 } else { good_end as u64 };
        let report = OpenReport { integrity, batches, bytes: len };
        let inner = Inner {
            file,
            state,
            next_seq,
            len,
            poisoned,
            #[cfg(feature = "testing")]
            fail_next_append: false,
        };
        Ok((Self { path: path.to_owned(), inner: Mutex::new(inner) }, report))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| AcfError::internal("journal mutex poisoned by a panic"))
    }

    /// Read-only view of committed state.
    pub fn read<R>(&self, f: impl FnOnce(&JournalState) -> R) -> Result<R> {
        Ok(f(&self.lock()?.state))
    }

    pub fn is_quarantined(&self) -> Option<String> {
        self.lock().ok().and_then(|g| g.poisoned.clone())
    }

    /// Atomic **check → append → fsync → apply**.
    ///
    /// `f` sees the committed state and returns the entries to append plus a value for the
    /// caller. Returning `Err` (or an empty entry list) writes nothing. The closure runs while
    /// the journal mutex is held, so it must be quick and must not call back into the journal.
    pub fn commit_with<T>(&self, f: impl FnOnce(&JournalState) -> Result<(Vec<Entry>, T)>) -> Result<T> {
        let mut g = self.lock()?;
        if let Some(why) = &g.poisoned {
            return Err(AcfError::new(FailureClass::RecoveryQuarantined, why.clone()));
        }
        let (entries, out) = f(&g.state)?;
        if entries.is_empty() {
            return Ok(out);
        }
        let batch = Batch { seq: g.next_seq, entries };
        let line = encode(&batch)?;

        #[cfg(feature = "testing")]
        if std::mem::take(&mut g.fail_next_append) {
            return Err(AcfError::new(FailureClass::Internal, "injected journal append failure"));
        }

        let prev_len = g.len;
        let write = g.file.write_all(&line).and_then(|()| g.file.sync_data());
        if let Err(e) = write {
            // Best effort: remove a partial line so the tail stays well-formed. If even that
            // fails the on-disk tail is unknowable, so refuse all further writes.
            if g.file.set_len(prev_len).and_then(|()| g.file.sync_data()).is_err() {
                g.poisoned = Some(format!("append failed and could not be rolled back: {e}"));
            }
            return Err(AcfError::new(FailureClass::Internal, format!("journal append failed: {e}")));
        }
        g.len += line.len() as u64;
        g.next_seq += 1;
        for e in &batch.entries {
            g.state.apply(e);
        }
        Ok(out)
    }

    /// Unconditional commit of already-decided entries.
    pub fn commit(&self, entries: Vec<Entry>) -> Result<()> {
        self.commit_with(|_| Ok((entries, ())))
    }

    pub fn len_bytes(&self) -> u64 {
        self.lock().map(|g| g.len).unwrap_or(0)
    }

    /// Rewrite the journal as a single batch of live state, dropping all but the newest
    /// `keep_terminal_ops` terminal operations. Crash-safe: write tmp, fsync, rename, fsync dir.
    pub fn compact(&self, keep_terminal_ops: usize) -> Result<u64> {
        let mut g = self.lock()?;
        if let Some(why) = &g.poisoned {
            return Err(AcfError::new(FailureClass::RecoveryQuarantined, why.clone()));
        }
        let mut terminal: Vec<&OperationRecord> = g.state.operations.values().filter(|o| o.is_terminal()).collect();
        terminal.sort_by(|a, b| b.updated_wall.cmp(&a.updated_wall).then_with(|| b.operation_id.cmp(&a.operation_id)));
        let drop_ids: Vec<OperationId> = terminal.iter().skip(keep_terminal_ops).map(|o| o.operation_id.clone()).collect();

        let mut state = g.state.clone();
        for id in &drop_ids {
            state.operations.remove(id);
        }
        let mut entries: Vec<Entry> = Vec::new();
        entries.extend(state.operations.values().cloned().map(|r| Entry::Operation(Box::new(r))));
        entries.extend(state.sandboxes.values().cloned().map(Entry::Sandbox));
        entries.extend(state.generations.values().cloned().map(|r| Entry::Generation(Box::new(r))));
        entries.extend(state.snapshots.values().cloned().map(|r| Entry::Snapshot(Box::new(r))));
        entries.extend(state.recoveries.values().cloned().map(Entry::Recovery));
        entries.extend(state.quarantines.iter().cloned().map(Entry::Quarantine));
        entries.extend(state.runtime_manifests.iter().cloned().map(Entry::RuntimeManifest));

        // A compacted file is a *sequence* of bounded batches, so the size cap still applies.
        let tmp = self.path.with_extension("wal.compacting");
        let mut out = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        let mut seq = 1u64;
        let mut written = 0u64;
        for chunk in entries.chunks(64) {
            let line = encode(&Batch { seq, entries: chunk.to_vec() })?;
            out.write_all(&line)?;
            written += line.len() as u64;
            seq += 1;
        }
        out.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            fsync_dir(dir)?;
        }
        g.file = OpenOptions::new().read(true).append(true).open(&self.path)?;
        g.state = state;
        g.next_seq = seq;
        g.len = written;
        Ok(drop_ids.len() as u64)
    }

    #[cfg(feature = "testing")]
    pub fn inject_append_failure_once(&self) {
        if let Ok(mut g) = self.lock() {
            g.fail_next_append = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clock::MonotonicRef,
        domain::{CallerIdentity, OperationPhase, OperationStatus, OperationType, PolicyId, RequestFingerprint},
    };

    pub(crate) fn op(id: &str, terminal: bool) -> OperationRecord {
        OperationRecord {
            operation_id: OperationId::parse(id).unwrap(),
            operation_type: OperationType::SandboxCreate,
            fingerprint: RequestFingerprint { schema_version: 1, algorithm: "sha256".into(), digest: "d".into() },
            request_schema_version: "1".into(),
            resource_id: "host".into(),
            expected_generation: None,
            created_wall: "2026-10-05T00:00:00.000Z".into(),
            created_mono: MonotonicRef { boot_id: "b".into(), ns: 1 },
            deadline: MonotonicRef { boot_id: "b".into(), ns: 2 },
            caller: CallerIdentity { uid: 0, gid: 0, pid: None },
            policy_id: PolicyId { name: "p".into(), version: "1".into(), digest: "0".repeat(64) },
            phase: if terminal { OperationPhase::Terminal } else { OperationPhase::Accepted },
            status: if terminal { OperationStatus::Succeeded } else { OperationStatus::Accepted },
            failure: None,
            result: None,
            run_id: None,
            sandbox: None,
            snapshot: None,
            recovery_id: None,
            updated_wall: format!("2026-10-05T00:00:{id}"),
        }
    }

    fn put(j: &Journal, id: &str) {
        j.commit(vec![Entry::Operation(Box::new(op(id, false)))]).unwrap();
    }

    #[test]
    fn committed_state_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        {
            let (j, rep) = Journal::open(&p).unwrap();
            assert_eq!(rep.integrity, Integrity::Clean);
            put(&j, "op-aaaaaaaa");
            put(&j, "op-bbbbbbbb");
        }
        let (j, rep) = Journal::open(&p).unwrap();
        assert_eq!((rep.integrity, rep.batches), (Integrity::Clean, 2));
        assert_eq!(j.read(|s| s.operations.len()).unwrap(), 2);
    }

    #[test]
    fn a_torn_final_line_is_repaired_and_earlier_state_is_intact() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        {
            let (j, _) = Journal::open(&p).unwrap();
            put(&j, "op-aaaaaaaa");
        }
        // Simulate a crash halfway through the next append: partial line, no newline.
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"deadbeef {\"seq\":2,\"entr").unwrap();
        drop(f);

        let (j, rep) = Journal::open(&p).unwrap();
        assert!(matches!(rep.integrity, Integrity::TornTailRepaired { dropped_bytes } if dropped_bytes > 0), "{:?}", rep.integrity);
        assert_eq!(j.read(|s| s.operations.len()).unwrap(), 1);
        put(&j, "op-cccccccc"); // and it accepts new writes cleanly afterwards
        let (j2, rep2) = Journal::open(&p).unwrap();
        assert_eq!(rep2.integrity, Integrity::Clean);
        assert_eq!(j2.read(|s| s.operations.len()).unwrap(), 2);
    }

    #[test]
    fn a_bad_final_record_with_newline_is_also_a_torn_tail() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        {
            let (j, _) = Journal::open(&p).unwrap();
            put(&j, "op-aaaaaaaa");
        }
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"00000000 {\"seq\":2,\"entries\":[]}\n").unwrap(); // wrong CRC, last line
        drop(f);
        let (_, rep) = Journal::open(&p).unwrap();
        assert!(matches!(rep.integrity, Integrity::TornTailRepaired { .. }), "{:?}", rep.integrity);
    }

    #[test]
    fn mid_file_corruption_is_quarantined_and_blocks_all_mutation() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        {
            let (j, _) = Journal::open(&p).unwrap();
            put(&j, "op-aaaaaaaa");
            put(&j, "op-bbbbbbbb");
            put(&j, "op-cccccccc");
        }
        let mut bytes = fs::read(&p).unwrap();
        let first_nl = bytes.iter().position(|b| *b == b'\n').unwrap();
        bytes[first_nl + 20] ^= 0x55; // flip bits inside the *second* record's JSON
        fs::write(&p, &bytes).unwrap();

        let (j, rep) = Journal::open(&p).unwrap();
        assert!(matches!(rep.integrity, Integrity::Corrupt { line: 2, .. }), "{:?}", rep.integrity);
        assert!(j.is_quarantined().is_some());
        let err = j.commit(vec![Entry::Operation(Box::new(op("op-dddddddd", false)))]).unwrap_err();
        assert_eq!(err.class, FailureClass::RecoveryQuarantined);
        // reads still work, and only the prefix before the corruption is believed
        assert_eq!(j.read(|s| s.operations.len()).unwrap(), 1);
    }

    #[test]
    fn commit_with_is_an_atomic_check_and_append() {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = Journal::open(&d.path().join("j.wal")).unwrap();
        let id = OperationId::parse("op-aaaaaaaa").unwrap();
        let try_begin = || {
            j.commit_with(|s| {
                if s.operations.contains_key(&id) {
                    Ok((vec![], false))
                } else {
                    Ok((vec![Entry::Operation(Box::new(op("op-aaaaaaaa", false)))], true))
                }
            })
            .unwrap()
        };
        assert!(try_begin(), "first caller wins");
        assert!(!try_begin(), "second caller observes the first's commit");
    }

    #[test]
    fn failed_append_changes_nothing_in_memory_or_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (j, _) = Journal::open(&p).unwrap();
        put(&j, "op-aaaaaaaa");
        let before = fs::read(&p).unwrap();
        j.inject_append_failure_once();
        assert!(j.commit(vec![Entry::Operation(Box::new(op("op-bbbbbbbb", false)))]).is_err());
        assert_eq!(j.read(|s| s.operations.len()).unwrap(), 1, "memory must not run ahead of disk");
        assert_eq!(fs::read(&p).unwrap(), before);
        put(&j, "op-bbbbbbbb"); // and the journal keeps working
        assert_eq!(j.read(|s| s.operations.len()).unwrap(), 2);
    }

    #[test]
    fn oversized_batch_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = Journal::open(&d.path().join("j.wal")).unwrap();
        let mut o = op("op-aaaaaaaa", true);
        o.result = Some(serde_json::json!({"blob": "x".repeat(MAX_BATCH_BYTES)}));
        let e = j.commit(vec![Entry::Operation(Box::new(o))]).unwrap_err();
        assert!(e.message.contains("exceeds"), "{}", e.message);
    }

    #[test]
    fn compaction_keeps_live_state_and_newest_terminal_ops_and_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (j, _) = Journal::open(&p).unwrap();
        for i in 0..5 {
            j.commit(vec![Entry::Operation(Box::new(op(&format!("op-0000000{i}"), true)))]).unwrap();
        }
        put(&j, "op-live0000"); // non-terminal: must never be dropped
        let dropped = j.compact(2).unwrap();
        assert_eq!(dropped, 3);
        assert_eq!(j.read(|s| s.operations.len()).unwrap(), 3);
        put(&j, "op-after000");
        drop(j);
        let (j2, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.integrity, Integrity::Clean);
        assert_eq!(j2.read(|s| s.operations.len()).unwrap(), 4);
        assert!(j2.read(|s| s.operations.contains_key(&OperationId::parse("op-live0000").unwrap())).unwrap());
    }
}
