//! The host-local durable store (contract §23): a narrow, append-only journal.
//!
//! # Model
//! A file of checksummed *batches*, one per line:
//!
//! ```text
//! <crc32 hex, 8 chars> <space> <json {"seq":N,"epoch":E,"entries":[...]}> \n
//! ```
//!
//! Entries are **full-record upserts** (the latest record for a key wins), not domain events: the
//! file is a write-ahead log for a small key-value state, deliberately *not* an event-sourced store.
//! A batch is the unit of atomicity (PS-3): either every entry in it is visible after a crash, or
//! none is.
//!
//! # Identity (PS-5, PS-6)
//! * **Lineage** — a random id written as the first record when the store is created. Every
//!   sequence, revision and cursor is meaningful only together with it (ID-4).
//! * **Commit sequence** — `seq`, strictly increasing within the lineage. It is stamped on every
//!   record as its `revision`, so a compaction never changes a revision.
//! * **Activation epoch** — one more than the highest epoch in the file, taken each time the store
//!   is opened for writing and recorded in every batch. A batch from a lower epoch after a higher
//!   one is a stale writer and is never believed.
//!
//! # Durability and ordering (PS-4, PS-7)
//! `commit_with` holds one mutex across *check → append → fsync → apply*. That single critical
//! section is what makes idempotent BEGIN, atomic admission and fencing correct without further
//! locking. State is applied in memory **only after** the fsync succeeds, so memory never runs
//! ahead of disk. Before every append the file must still have the length this writer left it at:
//! if it does not, another writer exists and this activation fences itself.
//!
//! # Corruption (PS-8) — nothing corrupt is silently believed
//! * **Torn tail** (partial final line, or a bad final record): the signature of a crash during
//!   append. Safe to drop; truncated and reported.
//! * **Any other corruption** cannot be a crash artefact. The store opens write-blocked: reads work,
//!   **every mutation is refused**, and the host serves in `READ_ONLY`.
//! * A store whose schema this version does not support is neither written nor interpreted (PS-11).
//!
//! # Bounded growth (PS-10)
//! The file only grows by appending, so what retention forgets and what a later record replaces stay
//! in it until it is rewritten as current state (*compaction*: a new file, fsync, rename). That
//! happens when the store is opened and, while the host serves, whenever the file has grown past
//! `compact_at_bytes` and at least half of it is no longer current ([`Journal::compact_if_grown`]).
//! A compaction changes no revision and continues the commit sequence.
//!
//! # Reserved capacity (PS-9)
//! A ballast file of `reserve_bytes` sits beside the journal. If an append fails for lack of space
//! the ballast is released and the append retried, so recording a containment operation does not
//! compete with workload data. While the ballast is released the host refuses new privilege.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use super::{
    migrate::{self, MigrationDefaults},
    records::{
        ActivationRecord, Entry, ForgetRecord, GenerationRecord, OpKey, OperationRecord, ProfileRecord, QuarantineRecord, RecoveryRecord,
        STORE_SCHEMA_VERSION, SandboxRecord, SnapshotRecord, StoreMeta,
    },
};
use crate::{
    domain::{LifecycleState, SnapshotRef, Tags},
    error::{AcfError, FailureClass, Result},
    ids::{Generation, RecoveryId, SandboxId, SnapshotId},
};

/// A single committed batch may not exceed this (keeps recovery's per-record cost bounded and stops
/// a bug from stuffing output bytes into the journal).
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// The core does not open a larger file: it would read all of it into memory. Compaction while
/// serving keeps a store far below this; one that is above it is compacted with
/// `acf-host journal compact`, which opens a store of any size.
pub const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
/// Default of `store.compact_at_bytes`: the file is rewritten once it has grown past this.
pub const COMPACT_AT_BYTES: u64 = 64 * 1024 * 1024;
const KEEP_ACTIVATIONS: usize = 16;
const KEEP_PROFILES: usize = 16;
const KEEP_QUARANTINE_REPORTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integrity {
    Clean,
    TornTailRepaired {
        dropped_bytes: u64,
    },
    Corrupt {
        line: u64,
        reason: String,
    },
    /// Written under a schema this version does not support. Not interpreted.
    UnsupportedSchema {
        found: u32,
    },
}

/// Why the store refuses writes. Each maps to host mode `READ_ONLY`; the last two also end the
/// activation (fail-stop, FS-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteBlock {
    Corrupt(String),
    UnsupportedSchema(u32),
    /// The outcome of a commit is not certain.
    Uncertain(String),
    /// Another writer changed the file: this activation is stale.
    Fenced(String),
}

impl WriteBlock {
    pub fn message(&self) -> String {
        match self {
            WriteBlock::Corrupt(m) => format!("the store is corrupt: {m}"),
            WriteBlock::UnsupportedSchema(v) => {
                format!("the store was written with schema {v}; this version supports {STORE_SCHEMA_VERSION}")
            }
            WriteBlock::Uncertain(m) => format!("the outcome of a commit is uncertain: {m}"),
            WriteBlock::Fenced(m) => format!("this activation was fenced: {m}"),
        }
    }

    /// The core must stop and re-establish its state from the store (FS-9).
    pub fn is_fail_stop(&self) -> bool {
        matches!(self, WriteBlock::Uncertain(_) | WriteBlock::Fenced(_))
    }
}

#[derive(Debug, Clone)]
pub struct OpenReport {
    pub integrity: Integrity,
    pub batches: u64,
    pub bytes: u64,
    pub lineage: String,
    pub epoch: u64,
    pub last_seq: u64,
    /// Schema the store was migrated from at this open, if it was.
    pub migrated_from: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct StoreOptions {
    /// Capacity kept from workload data (`control_store_reserve`). `0` disables the ballast.
    pub reserve_bytes: u64,
    /// How to tag records written before tags existed. `None`: an older schema is not migrated.
    pub migration: Option<MigrationDefaults>,
    /// The largest file the store is opened from. `None`: any size (the maintenance tools, which
    /// exist to deal with a store that outgrew the limit).
    pub max_bytes: Option<u64>,
    /// `store.compact_at_bytes`: the file is rewritten as current state once it has grown past this
    /// and at least half of it is no longer current (PS-10).
    pub compact_at_bytes: u64,
    /// Whether opening may rewrite the file. The maintenance tools say no: looking at a store must
    /// not change it.
    pub compact_at_open: bool,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            reserve_bytes: 0,
            migration: None,
            max_bytes: Some(MAX_JOURNAL_BYTES),
            compact_at_bytes: COMPACT_AT_BYTES,
            compact_at_open: true,
        }
    }
}

impl StoreOptions {
    /// For `acf-host journal verify` and `journal compact`: a store of any size, opened as it is.
    pub fn maintenance() -> Self {
        Self { max_bytes: None, compact_at_open: false, ..Self::default() }
    }
}

/// Materialised current state: the latest record per key.
#[derive(Debug, Default, Clone)]
pub struct JournalState {
    pub meta: Option<StoreMeta>,
    pub operations: HashMap<OpKey, OperationRecord>,
    /// Keys of the operations that are not terminal. Exclusivity is decided from this (J-3).
    pub open_operations: BTreeSet<OpKey>,
    pub sandboxes: HashMap<SandboxId, SandboxRecord>,
    pub generations: BTreeMap<(SandboxId, Generation), GenerationRecord>,
    pub snapshots: BTreeMap<(SnapshotId, Generation), SnapshotRecord>,
    pub recoveries: HashMap<RecoveryId, RecoveryRecord>,
    pub quarantines: Vec<QuarantineRecord>,
    pub activations: Vec<ActivationRecord>,
    pub profiles: Vec<ProfileRecord>,
    /// Cursors below this may have missed a tombstone that retention removed (API-11).
    pub change_floor: u64,
    /// Sequence of the last committed batch.
    pub last_seq: u64,
}

fn trim_front<T>(v: &mut Vec<T>, keep: usize) {
    let excess = v.len().saturating_sub(keep);
    v.drain(..excess);
}

impl JournalState {
    fn apply(&mut self, e: &Entry) {
        match e {
            Entry::Meta(m) => self.meta = Some(m.clone()),
            Entry::Activation(a) => {
                self.activations.push(a.clone());
                trim_front(&mut self.activations, KEEP_ACTIVATIONS);
            }
            Entry::Operation(r) => {
                let key = r.key();
                if r.is_terminal() {
                    self.open_operations.remove(&key);
                } else {
                    self.open_operations.insert(key.clone());
                }
                self.operations.insert(key, (**r).clone());
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
                    trim_front(&mut self.quarantines, KEEP_QUARANTINE_REPORTS);
                }
            }
            Entry::Profile(p) => {
                self.profiles.push(p.clone());
                trim_front(&mut self.profiles, KEEP_PROFILES);
            }
            Entry::Forget(f) => self.forget(f),
        }
    }

    fn forget(&mut self, f: &ForgetRecord) {
        for k in &f.operations {
            // A non-terminal operation is never removed (OP-13), whatever a record says.
            if !self.operations.get(k).is_some_and(OperationRecord::is_terminal) {
                continue;
            }
            if let Some(id) = self.operations.remove(k).and_then(|op| op.recovery_id) {
                self.recoveries.remove(&id);
            }
        }
        for id in &f.sandboxes {
            self.sandboxes.remove(id);
            self.generations.retain(|(s, _), _| s != id);
        }
        for key in &f.snapshots {
            self.snapshots.remove(key);
        }
        self.change_floor = self.change_floor.max(f.change_floor);
    }

    /// The current generation record of a sandbox, if any.
    pub fn current_generation(&self, id: &SandboxId) -> Option<&GenerationRecord> {
        let cur = self.sandboxes.get(id)?.current;
        self.generations.get(&(id.clone(), cur))
    }

    /// Aliases are scoped to their tags: two scopes may use one name without learning of each other
    /// (AU-9). A name resolves only to a sandbox whose current generation is not destroyed.
    pub fn sandbox_by_name(&self, tags: &Tags, name: &str) -> Option<&SandboxRecord> {
        self.sandboxes.values().find(|s| {
            s.tags == *tags
                && s.name.as_deref() == Some(name)
                && self.current_generation(&s.sandbox_id).is_some_and(|g| g.state != LifecycleState::Destroyed)
        })
    }

    /// Every live sandbox called `name`, whatever its tags: what an operator's lookup by name sees.
    pub fn sandboxes_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a SandboxRecord> {
        self.sandboxes.values().filter(move |s| {
            s.name.as_deref() == Some(name) && self.current_generation(&s.sandbox_id).is_some_and(|g| g.state != LifecycleState::Destroyed)
        })
    }

    pub fn snapshot_by_name(&self, tags: &Tags, name: &str) -> Option<&SnapshotRecord> {
        self.snapshots
            .values()
            .filter(|s| s.tags == *tags && s.name.as_deref() == Some(name) && s.holds_storage())
            .max_by_key(|s| s.generation)
    }

    /// Generations that hold a lease (J-5).
    pub fn live_generations(&self) -> impl Iterator<Item = &GenerationRecord> {
        self.generations.values().filter(|g| g.holds_reservation())
    }

    /// Operations that are not terminal.
    pub fn open(&self) -> impl Iterator<Item = &OperationRecord> {
        self.open_operations.iter().filter_map(|k| self.operations.get(k))
    }

    /// Non-terminal operations that hold `sandbox`.
    pub fn open_on_sandbox<'a>(&'a self, sandbox: &'a SandboxId) -> impl Iterator<Item = &'a OperationRecord> {
        self.open().filter(move |o| o.sandbox.as_ref().is_some_and(|(s, _)| s == sandbox))
    }

    /// Non-terminal operations that reference `snapshot` (RF-1).
    pub fn open_on_snapshot<'a>(&'a self, snapshot: &'a SnapshotRef) -> impl Iterator<Item = &'a OperationRecord> {
        self.open().filter(move |o| o.snapshot.as_ref() == Some(snapshot))
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Batch {
    pub(crate) seq: u64,
    #[serde(default)]
    pub(crate) epoch: u64,
    /// The sequence was deliberately advanced past a gap (see [`Journal::jump_sequence`]).
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) jump: bool,
    pub(crate) entries: Vec<Entry>,
}

/// The ballast that keeps `reserve_bytes` of the state filesystem for the store (PS-9).
#[derive(Debug)]
struct Reserve {
    path: PathBuf,
    bytes: u64,
}

impl Reserve {
    fn hold(&self) -> std::io::Result<()> {
        if fs::metadata(&self.path).is_ok_and(|m| m.len() == self.bytes) {
            return Ok(());
        }
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&self.path)?;
        // Real blocks, not a sparse file: write the zeros.
        let chunk = vec![0u8; 64 * 1024];
        let mut left = self.bytes;
        while left > 0 {
            let n = left.min(chunk.len() as u64) as usize;
            f.write_all(&chunk[..n])?;
            left -= n as u64;
        }
        crate::durability::sync_all(&f)
    }

    fn release(&self) -> std::io::Result<()> {
        OpenOptions::new().write(true).open(&self.path)?.set_len(0)
    }
}

#[derive(Debug)]
struct Inner {
    file: File,
    state: JournalState,
    next_seq: u64,
    len: u64,
    epoch: u64,
    blocked: Option<WriteBlock>,
    reserve_released: bool,
    /// Length of the file when it was last current state only (at open, or after a compaction).
    compacted_len: u64,
    #[cfg(any(test, feature = "testing"))]
    fail_next_append: Option<std::io::ErrorKind>,
    /// Test-only: called with the committed state after every commit.
    #[cfg(any(test, feature = "testing"))]
    after_commit: Option<CommitObserver>,
    /// Test-only: the next failed append also cannot be rolled back (the commit is uncertain).
    #[cfg(any(test, feature = "testing"))]
    lose_next_rollback: bool,
}

/// Test-only observer of committed state (the joint-state invariants hold "after every commit").
#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
struct CommitObserver(std::sync::Arc<dyn Fn(&JournalState) + Send + Sync>);

#[cfg(any(test, feature = "testing"))]
impl std::fmt::Debug for CommitObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommitObserver")
    }
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    lineage: String,
    /// Constant for the life of this value, so reading it never takes the lock (and can therefore
    /// be done inside a `read` or `commit_with` closure).
    epoch: u64,
    reserve: Option<Reserve>,
    /// `store.compact_at_bytes`.
    compact_at: u64,
    inner: Mutex<Inner>,
}

pub(crate) fn encode(batch: &Batch) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(batch)?;
    if json.len() > MAX_BATCH_BYTES {
        return Err(AcfError::internal(format!(
            "store batch of {} bytes exceeds the {MAX_BATCH_BYTES}-byte limit; large payloads belong in the output store",
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

/// Check framing and checksum; return the JSON payload.
pub(crate) fn checked_payload(line: &[u8]) -> std::result::Result<&[u8], String> {
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
    Ok(json)
}

fn decode_line(line: &[u8]) -> std::result::Result<Batch, String> {
    let json = checked_payload(line)?;
    serde_json::from_slice::<Batch>(json).map_err(|e| format!("valid checksum but undecodable batch: {e}"))
}

pub(crate) fn fsync_dir(dir: &Path) -> Result<()> {
    crate::durability::sync_all(&File::open(dir)?)?;
    Ok(())
}

/// The schema of the file at `bytes`, read from its first record without interpreting the rest.
/// `None`: the file is empty. Schema 1 files have no meta record.
fn sniff_schema(bytes: &[u8]) -> std::result::Result<Option<u32>, String> {
    let Some(nl) = bytes.iter().position(|b| *b == b'\n') else {
        return Ok(None); // empty, or a single torn line: nothing was ever committed
    };
    let v: serde_json::Value = serde_json::from_slice(checked_payload(&bytes[..nl])?).map_err(|e| e.to_string())?;
    let first = &v["entries"][0];
    if first["kind"] == "meta" {
        return first["schema_version"].as_u64().map(|n| Some(n as u32)).ok_or_else(|| "meta record has no schema_version".to_owned());
    }
    Ok(Some(1))
}

struct Replay {
    state: JournalState,
    next_seq: u64,
    good_end: usize,
    batches: u64,
    integrity: Integrity,
    max_epoch: u64,
}

fn replay(bytes: &[u8]) -> Replay {
    let mut r = Replay { state: JournalState::default(), next_seq: 0, good_end: 0, batches: 0, integrity: Integrity::Clean, max_epoch: 0 };
    let (mut pos, mut line_no) = (0usize, 0u64);
    while pos < bytes.len() {
        line_no += 1;
        let rest = &bytes[pos..];
        let Some(nl) = rest.iter().position(|b| *b == b'\n') else {
            // Final segment without a newline: a torn append.
            r.integrity = Integrity::TornTailRepaired { dropped_bytes: rest.len() as u64 };
            break;
        };
        let line_end = pos + nl + 1;
        let verdict = decode_line(&rest[..nl]).and_then(|b| {
            // The first batch of a file names where the sequence starts (a compacted file does not
            // start at 1); afterwards it is contiguous unless a batch says it jumped.
            let in_order = r.batches == 0 || b.seq == r.next_seq || (b.jump && b.seq > r.next_seq);
            if !in_order {
                Err(format!("sequence break: expected {}, found {}", r.next_seq, b.seq))
            } else if b.epoch < r.max_epoch {
                Err(format!("batch {} was written by activation {} after activation {} had written", b.seq, b.epoch, r.max_epoch))
            } else {
                Ok(b)
            }
        });
        match verdict {
            Ok(b) => {
                for e in &b.entries {
                    r.state.apply(e);
                }
                r.state.last_seq = b.seq;
                r.next_seq = b.seq + 1;
                r.max_epoch = b.epoch;
                r.batches += 1;
                r.good_end = line_end;
                pos = line_end;
            }
            Err(reason) => {
                r.integrity = if line_end == bytes.len() {
                    // Bad *last* record: indistinguishable from a torn append. Drop it.
                    Integrity::TornTailRepaired { dropped_bytes: (bytes.len() - r.good_end) as u64 }
                } else {
                    // Valid-looking data follows: this is real corruption, not a crash.
                    Integrity::Corrupt { line: line_no, reason }
                };
                break;
            }
        }
    }
    r
}

impl Journal {
    /// Open with no reserve and no migration (tools and tests).
    pub fn open(path: &Path) -> Result<(Self, OpenReport)> {
        Self::open_with(path, &StoreOptions::default())
    }

    /// Open the store for writing. The caller holds the single-instance lock (PS-5).
    pub fn open_with(path: &Path, opts: &StoreOptions) -> Result<(Self, OpenReport)> {
        let dir = path.parent().map(Path::to_owned).unwrap_or_default();
        fs::create_dir_all(&dir)?;
        migrate::finish_interrupted(path)?;
        let existed = path.exists();
        let mut file = OpenOptions::new().read(true).append(true).create(true).mode(0o600).open(path)?;
        if !existed {
            fsync_dir(&dir)?;
        }
        let size = file.metadata()?.len();
        if let Some(max) = opts.max_bytes
            && size > max
        {
            return Err(AcfError::exhausted(format!(
                "the store is {size} bytes (> {max}); compact it with `acf-host journal compact` before starting"
            )));
        }
        let mut bytes = Vec::with_capacity(size as usize);
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut bytes)?;

        let mut migrated_from = None;
        match sniff_schema(&bytes) {
            Ok(None) | Ok(Some(STORE_SCHEMA_VERSION)) => {}
            Ok(Some(found)) if found < STORE_SCHEMA_VERSION && opts.migration.is_some() => {
                let defaults = opts.migration.as_ref().ok_or_else(|| AcfError::internal("migration defaults vanished"))?;
                // A store that cannot be migrated is not interpreted either: the host serves READ_ONLY.
                if let Err(e) = migrate::migrate(path, &bytes, found, defaults) {
                    return Ok(Self::blocked(path, file, bytes.len() as u64, Integrity::Corrupt { line: 0, reason: e.message }));
                }
                migrated_from = Some(found);
                file = OpenOptions::new().read(true).append(true).mode(0o600).open(path)?;
                bytes.clear();
                file.seek(SeekFrom::Start(0))?;
                file.read_to_end(&mut bytes)?;
            }
            Ok(Some(found)) => return Ok(Self::blocked(path, file, bytes.len() as u64, Integrity::UnsupportedSchema { found })),
            Err(reason) => return Ok(Self::blocked(path, file, bytes.len() as u64, Integrity::Corrupt { line: 1, reason })),
        }

        let mut r = replay(&bytes);
        if let Integrity::TornTailRepaired { .. } = r.integrity {
            file.set_len(r.good_end as u64)?;
            crate::durability::sync_all(&file)?;
        }
        let blocked = match &r.integrity {
            Integrity::Corrupt { line, reason } => Some(WriteBlock::Corrupt(format!("line {line}: {reason}"))),
            _ => None,
        };
        let len = if blocked.is_some() { bytes.len() as u64 } else { r.good_end as u64 };
        if r.batches == 0 {
            r.next_seq = 1;
        }
        let epoch = r.max_epoch + 1;
        let lineage = match &r.state.meta {
            Some(m) => m.lineage.clone(),
            None => crate::ids::random_token()?,
        };
        let reserve = (opts.reserve_bytes > 0).then(|| Reserve { path: path.with_extension("reserve"), bytes: opts.reserve_bytes });
        let created = r.state.meta.is_none() && blocked.is_none();
        let report = OpenReport {
            integrity: r.integrity,
            batches: r.batches,
            bytes: len,
            lineage: lineage.clone(),
            epoch,
            last_seq: r.state.last_seq,
            migrated_from,
        };
        let inner = Inner {
            file,
            state: r.state,
            next_seq: r.next_seq,
            len,
            epoch,
            blocked,
            reserve_released: false,
            compacted_len: len,
            #[cfg(any(test, feature = "testing"))]
            fail_next_append: None,
            #[cfg(any(test, feature = "testing"))]
            after_commit: None,
            #[cfg(any(test, feature = "testing"))]
            lose_next_rollback: false,
        };
        let j = Self {
            path: path.to_owned(),
            lineage: lineage.clone(),
            epoch,
            reserve,
            compact_at: opts.compact_at_bytes.max(1),
            inner: Mutex::new(inner),
        };
        if created {
            // A new store: its first record says what it is.
            j.commit(vec![Entry::Meta(StoreMeta {
                schema_version: STORE_SCHEMA_VERSION,
                lineage,
                created_wall: crate::clock::rfc3339_now(),
            })])?;
        }
        if let Some(res) = &j.reserve
            && j.write_block().is_none()
            && let Err(e) = res.hold()
        {
            return Err(AcfError::exhausted(format!("cannot reserve {} bytes for the store at {}: {e}", res.bytes, res.path.display())));
        }
        // What an earlier activation left behind is not known to be current: rewrite a file that has
        // grown past the threshold once, here, and count growth from the result.
        if opts.compact_at_open && j.len_bytes() > j.compact_at && j.write_block().is_none() {
            j.compact(usize::MAX)?;
        }
        Ok((j, report))
    }

    /// A store this version must not write or interpret: empty state, every mutation refused.
    fn blocked(path: &Path, file: File, len: u64, integrity: Integrity) -> (Self, OpenReport) {
        let blocked = match &integrity {
            Integrity::UnsupportedSchema { found } => WriteBlock::UnsupportedSchema(*found),
            Integrity::Corrupt { line, reason } => WriteBlock::Corrupt(format!("line {line}: {reason}")),
            _ => WriteBlock::Corrupt("unreadable".into()),
        };
        let report =
            OpenReport { integrity, batches: 0, bytes: len, lineage: "unknown".into(), epoch: 0, last_seq: 0, migrated_from: None };
        let inner = Inner {
            file,
            state: JournalState::default(),
            next_seq: 1,
            len,
            epoch: 0,
            blocked: Some(blocked),
            reserve_released: false,
            compacted_len: len,
            #[cfg(any(test, feature = "testing"))]
            fail_next_append: None,
            #[cfg(any(test, feature = "testing"))]
            after_commit: None,
            #[cfg(any(test, feature = "testing"))]
            lose_next_rollback: false,
        };
        // A blocked store is never written, so it is never compacted either.
        let j = Self {
            path: path.to_owned(),
            lineage: "unknown".into(),
            epoch: 0,
            reserve: None,
            compact_at: u64::MAX,
            inner: Mutex::new(inner),
        };
        (j, report)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| AcfError::internal("store mutex poisoned by a panic"))
    }

    /// Read-only view of committed state.
    pub fn read<R>(&self, f: impl FnOnce(&JournalState) -> R) -> Result<R> {
        Ok(f(&self.lock()?.state))
    }

    pub fn lineage(&self) -> &str {
        &self.lineage
    }

    /// The epoch of this activation. Recorded in every batch it writes.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Sequence of the last committed batch.
    pub fn last_seq(&self) -> u64 {
        self.lock().map(|g| g.state.last_seq).unwrap_or(0)
    }

    /// Why the store refuses writes, if it does.
    pub fn write_block(&self) -> Option<WriteBlock> {
        self.lock().ok().and_then(|g| g.blocked.clone())
    }

    /// The ballast was released to make room for a commit (PS-9). New privilege is refused meanwhile.
    pub fn reserve_released(&self) -> bool {
        self.lock().map(|g| g.reserve_released).unwrap_or(false)
    }

    /// Try to take the ballast back (called periodically once space may have returned).
    pub fn restore_reserve(&self) -> bool {
        let Some(res) = &self.reserve else { return true };
        let Ok(mut g) = self.lock() else { return false };
        if !g.reserve_released {
            return true;
        }
        if res.hold().is_ok() {
            g.reserve_released = false;
            true
        } else {
            let _ = res.release();
            false
        }
    }

    fn append(g: &mut Inner, line: &[u8]) -> std::io::Result<()> {
        #[cfg(any(test, feature = "testing"))]
        if let Some(kind) = g.fail_next_append.take() {
            return Err(std::io::Error::new(kind, "injected store append failure"));
        }
        g.file.write_all(line).and_then(|()| crate::durability::sync_data(&g.file))
    }

    /// Atomic **check → append → fsync → apply**.
    ///
    /// `f` sees the committed state and returns the entries to append plus a value for the caller.
    /// Returning `Err` (or an empty entry list) writes nothing. The closure runs while the store
    /// mutex is held, so it must be quick and must not call back into the store.
    pub fn commit_with<T>(&self, f: impl FnOnce(&JournalState) -> Result<(Vec<Entry>, T)>) -> Result<T> {
        let mut g = self.lock()?;
        if let Some(why) = &g.blocked {
            return Err(AcfError::new(FailureClass::HostNotServing, why.message()));
        }
        let (mut entries, out) = f(&g.state)?;
        if entries.is_empty() {
            return Ok(out);
        }
        let seq = g.next_seq;
        for e in &mut entries {
            e.stamp(seq);
        }
        let batch = Batch { seq, epoch: g.epoch, jump: false, entries };
        Self::write_batch(&mut g, &batch, self.reserve.as_ref())?;
        Ok(out)
    }

    fn write_batch(g: &mut Inner, batch: &Batch, reserve: Option<&Reserve>) -> Result<()> {
        let line = encode(batch)?;
        // Fencing (PS-5): the file must be exactly as this writer left it.
        let on_disk = g.file.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
        if on_disk != g.len {
            let why = format!("the store file is {on_disk} bytes, this activation left it at {}; another writer exists", g.len);
            g.blocked = Some(WriteBlock::Fenced(why.clone()));
            return Err(AcfError::new(FailureClass::HostNotServing, why));
        }
        let prev_len = g.len;
        let mut written = Self::append(g, &line);
        if let Err(e) = &written
            && matches!(e.kind(), std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded)
            && let Some(res) = reserve
            && !g.reserve_released
        {
            // Remove any partial line, release the ballast, and try once more (PS-9).
            if g.file.set_len(prev_len).and_then(|()| crate::durability::sync_data(&g.file)).is_ok() && res.release().is_ok() {
                g.reserve_released = true;
                written = Self::append(g, &line);
            }
        }
        if let Err(e) = written {
            // Best effort: remove a partial line so the tail stays well-formed. If even that fails
            // the on-disk tail is unknowable: the commit is uncertain and this activation stops.
            #[cfg(any(test, feature = "testing"))]
            let rollback_lost = std::mem::take(&mut g.lose_next_rollback);
            #[cfg(not(any(test, feature = "testing")))]
            let rollback_lost = false;
            if rollback_lost || g.file.set_len(prev_len).and_then(|()| crate::durability::sync_data(&g.file)).is_err() {
                g.blocked = Some(WriteBlock::Uncertain(format!("append failed and could not be rolled back: {e}")));
            }
            let class = if matches!(e.kind(), std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded) {
                FailureClass::ResourceExhausted
            } else {
                FailureClass::InternalError
            };
            return Err(AcfError::new(class, format!("store append failed: {e}")));
        }
        g.len += line.len() as u64;
        g.next_seq = batch.seq + 1;
        for e in &batch.entries {
            g.state.apply(e);
        }
        g.state.last_seq = batch.seq;
        #[cfg(any(test, feature = "testing"))]
        if let Some(observer) = &g.after_commit {
            (observer.0)(&g.state);
        }
        Ok(())
    }

    /// Test-only: call `f` with the committed state after every commit of this activation. `f` runs
    /// while the store lock is held, so it must not call back into the store.
    #[cfg(any(test, feature = "testing"))]
    pub fn observe_commits(&self, f: impl Fn(&JournalState) + Send + Sync + 'static) {
        if let Ok(mut g) = self.lock() {
            g.after_commit = Some(CommitObserver(std::sync::Arc::new(f)));
        }
    }

    /// Unconditional commit of already-decided entries.
    pub fn commit(&self, entries: Vec<Entry>) -> Result<()> {
        self.commit_with(|_| Ok((entries, ())))
    }

    /// Advance the commit sequence past `to` (LN-2): after an operator acknowledges a store that is
    /// older than the system it describes, every new record must sort after every marker on disk.
    pub fn jump_sequence(&self, to: u64, entries: Vec<Entry>) -> Result<u64> {
        let mut g = self.lock()?;
        if let Some(why) = &g.blocked {
            return Err(AcfError::new(FailureClass::HostNotServing, why.message()));
        }
        let seq = g.next_seq.max(to.saturating_add(1));
        let mut entries = entries;
        for e in &mut entries {
            e.stamp(seq);
        }
        let batch = Batch { seq, epoch: g.epoch, jump: seq != g.next_seq, entries };
        Self::write_batch(&mut g, &batch, self.reserve.as_ref())?;
        Ok(seq)
    }

    pub fn len_bytes(&self) -> u64 {
        self.lock().map(|g| g.len).unwrap_or(0)
    }

    /// Rewrite the file as live state only, dropping all but the newest `keep_terminal_ops` terminal
    /// operations. Revisions and the commit sequence are preserved. Crash-safe: write a temporary
    /// file, fsync, rename, fsync the directory.
    pub fn compact(&self, keep_terminal_ops: usize) -> Result<u64> {
        let mut g = self.lock()?;
        if let Some(why) = &g.blocked {
            return Err(AcfError::new(FailureClass::HostNotServing, why.message()));
        }
        let mut terminal: Vec<&OperationRecord> = g.state.operations.values().filter(|o| o.is_terminal()).collect();
        terminal.sort_by(|a, b| b.revision.cmp(&a.revision).then_with(|| b.operation_id.cmp(&a.operation_id)));
        let drop_keys: Vec<OpKey> = terminal.iter().skip(keep_terminal_ops).map(|o| o.key()).collect();

        let mut state = g.state.clone();
        let mut floor = state.change_floor;
        for k in &drop_keys {
            if let Some(op) = state.operations.remove(k) {
                floor = floor.max(op.revision);
                if let Some(id) = op.recovery_id {
                    state.recoveries.remove(&id);
                }
            }
        }
        state.change_floor = floor;
        let mut entries: Vec<Entry> = Vec::new();
        entries.extend(state.meta.iter().cloned().map(Entry::Meta));
        entries.extend(state.activations.iter().cloned().map(Entry::Activation));
        entries.extend(state.profiles.iter().cloned().map(Entry::Profile));
        entries.extend(state.sandboxes.values().cloned().map(Entry::Sandbox));
        entries.extend(state.generations.values().cloned().map(|r| Entry::Generation(Box::new(r))));
        entries.extend(state.snapshots.values().cloned().map(|r| Entry::Snapshot(Box::new(r))));
        entries.extend(state.operations.values().cloned().map(|r| Entry::Operation(Box::new(r))));
        entries.extend(state.recoveries.values().cloned().map(Entry::Recovery));
        entries.extend(state.quarantines.iter().cloned().map(Entry::Quarantine));
        if floor > 0 {
            entries.push(Entry::Forget(ForgetRecord { change_floor: floor, ..ForgetRecord::default() }));
        }

        // The compacted file continues the sequence: its batches are numbered after the last commit,
        // and the records inside keep the revisions they already carry.
        let tmp = self.path.with_extension("wal.compacting");
        let mut out = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        let mut seq = g.next_seq;
        let mut written = 0u64;
        for chunk in entries.chunks(64) {
            let line = encode(&Batch { seq, epoch: g.epoch, jump: false, entries: chunk.to_vec() })?;
            out.write_all(&line)?;
            written += line.len() as u64;
            seq += 1;
        }
        crate::durability::sync_all(&out)?;
        drop(out);
        // The handle the journal will append through is opened BEFORE the switch, on the very file
        // that is about to take the store's name. After the rename nothing is left that could fail
        // and leave the journal appending to a file that no longer has a name.
        let switched = OpenOptions::new().read(true).append(true).open(&tmp)?;
        fs::rename(&tmp, &self.path)?;
        g.file = switched;
        state.last_seq = seq.saturating_sub(1).max(state.last_seq);
        g.state = state;
        g.next_seq = seq;
        g.len = written;
        g.compacted_len = written;
        // The switch must survive a power cut, or a later commit could be appended to a file the
        // directory no longer names. If that cannot be confirmed the commit history is uncertain,
        // which is a fail-stop (FS-9): the next activation reads whichever file the directory has.
        if let Some(dir) = self.path.parent()
            && let Err(e) = fsync_dir(dir)
        {
            let why = format!("the compacted store could not be made durable: {}", e.message);
            g.blocked = Some(WriteBlock::Uncertain(why.clone()));
            return Err(AcfError::internal(why).with_possible_side_effect());
        }
        Ok(drop_keys.len() as u64)
    }

    /// PS-10: rewrite the file as current state if it has grown past `compact_at_bytes` **and** has at
    /// least doubled since it was last current state only. The second condition makes the cost
    /// proportional to what is reclaimed: a store whose current state alone is large is not rewritten
    /// at every call. Every terminal operation is kept; forgetting them is retention's job (OP-12).
    /// Returns whether the file was rewritten.
    pub fn compact_if_grown(&self) -> Result<bool> {
        let due = {
            let g = self.lock()?;
            g.blocked.is_none() && g.len > self.compact_at && g.len >= g.compacted_len.saturating_mul(2)
        };
        if due {
            self.compact(usize::MAX)?;
        }
        Ok(due)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn inject_append_failure_once(&self) {
        self.inject_append_error_once(std::io::ErrorKind::Other);
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn inject_append_error_once(&self, kind: std::io::ErrorKind) {
        if let Ok(mut g) = self.lock() {
            g.fail_next_append = Some(kind);
        }
    }

    /// Test-only: the next append fails **and** what reached the disk cannot be established.
    #[cfg(any(test, feature = "testing"))]
    pub fn inject_uncertain_append_once(&self) {
        if let Ok(mut g) = self.lock() {
            g.fail_next_append = Some(std::io::ErrorKind::Other);
            g.lose_next_rollback = true;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        clock::MonotonicRef,
        domain::{Issuer, OperationState, OperationType, OwnerScope, PeerId, ProfileId, RequestFingerprint},
        ids::OperationId,
    };

    pub(crate) fn tags(scope: &str) -> Tags {
        Tags { peer_id: PeerId::parse("peer-1").unwrap(), owner_scope: OwnerScope::parse(scope).unwrap() }
    }

    pub(crate) fn op(id: &str, terminal: bool) -> OperationRecord {
        OperationRecord {
            operation_id: OperationId::parse(id).unwrap(),
            tags: tags("scope-a"),
            on_behalf_of: None,
            issuer: Issuer::Peer,
            operation_type: OperationType::SandboxCreate,
            fingerprint: RequestFingerprint { schema_version: 2, algorithm: "sha256".into(), digest: "d".into() },
            protocol: "acf.host/2".into(),
            target: "host".into(),
            expected_generation: None,
            issued_at: "2026-11-18T00:00:00.000Z".into(),
            created_wall: "2026-11-18T00:00:00.000Z".into(),
            created_ms: 0,
            created_mono: MonotonicRef { boot_id: "b".into(), ns: 1 },
            deadline: MonotonicRef { boot_id: "b".into(), ns: 2 },
            profile_id: ProfileId { name: "p".into(), version: "1".into(), digest: "0".repeat(64) },
            epoch: 1,
            state: if terminal { OperationState::Succeeded } else { OperationState::Accepted },
            step: None,
            cancelled_by: None,
            failure: None,
            cleanup: None,
            residue: None,
            execution_started: false,
            result: None,
            run_id: None,
            sandbox: None,
            snapshot: None,
            recovery_id: None,
            finished_ms: terminal.then_some(1),
            updated_wall: "2026-11-18T00:00:00.000Z".into(),
            revision: 0,
        }
    }

    fn put(j: &Journal, id: &str) {
        j.commit(vec![Entry::Operation(Box::new(op(id, false)))]).unwrap();
    }

    fn ops(j: &Journal) -> usize {
        j.read(|s| s.operations.len()).unwrap()
    }

    #[test]
    fn a_new_store_records_what_it_is_and_keeps_its_lineage_across_reopen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (j, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.integrity, Integrity::Clean);
        let meta = j.read(|s| s.meta.clone()).unwrap().unwrap();
        assert_eq!((meta.schema_version, meta.lineage.as_str()), (STORE_SCHEMA_VERSION, j.lineage()));
        assert_eq!(meta.lineage.len(), 32, "128 bits of lineage");
        let lineage = j.lineage().to_owned();
        drop(j);
        let (j2, rep2) = Journal::open(&p).unwrap();
        assert_eq!((j2.lineage(), rep2.lineage.as_str()), (lineage.as_str(), lineage.as_str()));
        let (other, _) = Journal::open(&d.path().join("other.wal")).unwrap();
        assert_ne!(other.lineage(), lineage, "two stores never share a lineage");
    }

    #[test]
    fn committed_state_survives_reopen_and_each_activation_takes_a_higher_epoch() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        {
            let (j, rep) = Journal::open(&p).unwrap();
            assert_eq!((rep.epoch, j.epoch()), (1, 1));
            put(&j, "op-aaaaaaaa");
            put(&j, "op-bbbbbbbb");
        }
        let (j, rep) = Journal::open(&p).unwrap();
        assert_eq!((rep.integrity, rep.batches, rep.epoch), (Integrity::Clean, 3, 2));
        assert_eq!(ops(&j), 2);
        drop(j);
        assert_eq!(Journal::open(&p).unwrap().1.epoch, 2, "an activation that wrote nothing does not consume an epoch");
    }

    #[test]
    fn the_commit_sequence_is_stamped_as_the_revision_and_only_increases() {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = Journal::open(&d.path().join("j.wal")).unwrap();
        let mut last = j.last_seq();
        for id in ["op-aaaaaaaa", "op-bbbbbbbb", "op-aaaaaaaa"] {
            put(&j, id);
            let rev = j.read(|s| s.operations.values().find(|o| o.operation_id.as_str() == id).map(|o| o.revision)).unwrap().unwrap();
            assert!(rev > last, "{id}: revision {rev} must exceed {last}");
            assert_eq!(rev, j.last_seq());
            last = rev;
        }
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
        f.write_all(b"deadbeef {\"seq\":3,\"entr").unwrap();
        drop(f);

        let (j, rep) = Journal::open(&p).unwrap();
        assert!(matches!(rep.integrity, Integrity::TornTailRepaired { dropped_bytes } if dropped_bytes > 0), "{:?}", rep.integrity);
        assert_eq!(ops(&j), 1);
        put(&j, "op-cccccccc"); // and it accepts new writes cleanly afterwards
        drop(j);
        let (j2, rep2) = Journal::open(&p).unwrap();
        assert_eq!(rep2.integrity, Integrity::Clean);
        assert_eq!(ops(&j2), 2);
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
        f.write_all(b"00000000 {\"seq\":3,\"entries\":[]}\n").unwrap(); // wrong CRC, last line
        drop(f);
        let (_, rep) = Journal::open(&p).unwrap();
        assert!(matches!(rep.integrity, Integrity::TornTailRepaired { .. }), "{:?}", rep.integrity);
    }

    #[test]
    fn mid_file_corruption_blocks_every_mutation_and_keeps_only_the_trusted_prefix() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        {
            let (j, _) = Journal::open(&p).unwrap();
            put(&j, "op-aaaaaaaa");
            put(&j, "op-bbbbbbbb");
            put(&j, "op-cccccccc");
        }
        let mut bytes = fs::read(&p).unwrap();
        let nls: Vec<usize> = bytes.iter().enumerate().filter(|(_, b)| **b == b'\n').map(|(i, _)| i).collect();
        bytes[nls[1] + 20] ^= 0x55; // flip bits inside the *third* record's JSON
        fs::write(&p, &bytes).unwrap();

        let (j, rep) = Journal::open(&p).unwrap();
        assert!(matches!(rep.integrity, Integrity::Corrupt { line: 3, .. }), "{:?}", rep.integrity);
        assert!(matches!(j.write_block(), Some(WriteBlock::Corrupt(_))));
        let err = j.commit(vec![Entry::Operation(Box::new(op("op-dddddddd", false)))]).unwrap_err();
        assert_eq!(err.class, FailureClass::HostNotServing);
        // reads still work, and only the prefix before the corruption is believed
        assert_eq!(ops(&j), 1);
    }

    #[test]
    fn a_store_from_a_newer_schema_is_neither_written_nor_interpreted() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let future = Batch {
            seq: 1,
            epoch: 1,
            jump: false,
            entries: vec![Entry::Meta(StoreMeta {
                schema_version: STORE_SCHEMA_VERSION + 1,
                lineage: "f".repeat(32),
                created_wall: "t".into(),
            })],
        };
        let mut bytes = encode(&future).unwrap();
        bytes.extend(
            encode(&Batch { seq: 2, epoch: 1, jump: false, entries: vec![Entry::Operation(Box::new(op("op-aaaaaaaa", false)))] }).unwrap(),
        );
        fs::write(&p, &bytes).unwrap();

        let (j, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.integrity, Integrity::UnsupportedSchema { found: STORE_SCHEMA_VERSION + 1 });
        assert_eq!(ops(&j), 0, "nothing from an unsupported schema is interpreted");
        assert!(j.commit(vec![Entry::Operation(Box::new(op("op-bbbbbbbb", false)))]).is_err());
        assert_eq!(fs::read(&p).unwrap(), bytes, "and the file is untouched");
    }

    #[test]
    fn commit_with_is_an_atomic_check_and_append() {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = Journal::open(&d.path().join("j.wal")).unwrap();
        let key = op("op-aaaaaaaa", false).key();
        let try_begin = || {
            j.commit_with(|s| {
                if s.operations.contains_key(&key) {
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
    fn operation_ids_are_namespaced_by_peer_and_scope() {
        let d = tempfile::tempdir().unwrap();
        let (j, _) = Journal::open(&d.path().join("j.wal")).unwrap();
        let mut a = op("op-aaaaaaaa", false);
        let mut b = op("op-aaaaaaaa", false);
        a.tags = tags("scope-a");
        b.tags = tags("scope-b");
        j.commit(vec![Entry::Operation(Box::new(a)), Entry::Operation(Box::new(b))]).unwrap();
        assert_eq!(ops(&j), 2, "the same id in two scopes is two operations (OP-10)");
        assert_eq!(j.read(|s| s.open_operations.len()).unwrap(), 2);
    }

    #[test]
    fn a_failed_append_changes_nothing_in_memory_or_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (j, _) = Journal::open(&p).unwrap();
        put(&j, "op-aaaaaaaa");
        let before = fs::read(&p).unwrap();
        let seq = j.last_seq();
        j.inject_append_failure_once();
        assert!(j.commit(vec![Entry::Operation(Box::new(op("op-bbbbbbbb", false)))]).is_err());
        assert_eq!(ops(&j), 1, "memory must not run ahead of disk");
        assert_eq!(j.last_seq(), seq, "a commit that did not happen consumes no sequence");
        assert_eq!(fs::read(&p).unwrap(), before);
        assert!(j.write_block().is_none(), "a clean rollback is a definite non-commit, not uncertainty");
        put(&j, "op-bbbbbbbb"); // and the store keeps working
        assert_eq!(ops(&j), 2);
    }

    #[test]
    fn a_second_writer_fences_the_stale_activation() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (old, _) = Journal::open(&p).unwrap();
        put(&old, "op-aaaaaaaa");
        // A later activation takes the store (in production the instance lock prevents this; the
        // fence is what holds if the lock is ever bypassed).
        let (new, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.epoch, 2);
        put(&new, "op-bbbbbbbb");
        let e = old.commit(vec![Entry::Operation(Box::new(op("op-cccccccc", false)))]).unwrap_err();
        assert_eq!(e.class, FailureClass::HostNotServing);
        assert!(matches!(old.write_block(), Some(WriteBlock::Fenced(_))), "{:?}", old.write_block());
        assert!(old.write_block().unwrap().is_fail_stop());
        drop((old, new));
        let (j, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.integrity, Integrity::Clean, "the stale writer wrote nothing");
        assert_eq!(ops(&j), 2);
    }

    #[test]
    fn a_batch_from_a_stale_epoch_is_never_believed() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        {
            let (j, _) = Journal::open(&p).unwrap();
            put(&j, "op-aaaaaaaa");
        }
        {
            let (j, _) = Journal::open(&p).unwrap(); // epoch 2
            put(&j, "op-bbbbbbbb");
        }
        // Forge two more batches: one from epoch 1 (stale), then a valid-looking one.
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(
            &encode(&Batch { seq: 4, epoch: 1, jump: false, entries: vec![Entry::Operation(Box::new(op("op-stale000", false)))] }).unwrap(),
        )
        .unwrap();
        f.write_all(
            &encode(&Batch { seq: 5, epoch: 2, jump: false, entries: vec![Entry::Operation(Box::new(op("op-after000", false)))] }).unwrap(),
        )
        .unwrap();
        drop(f);
        let (j, rep) = Journal::open(&p).unwrap();
        assert!(matches!(rep.integrity, Integrity::Corrupt { line: 4, .. }), "{:?}", rep.integrity);
        assert_eq!(ops(&j), 2, "neither the stale batch nor anything after it is believed");
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
    fn compaction_keeps_live_state_revisions_and_the_sequence() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (j, _) = Journal::open(&p).unwrap();
        for i in 0..5 {
            j.commit(vec![Entry::Operation(Box::new(op(&format!("op-0000000{i}"), true)))]).unwrap();
        }
        put(&j, "op-live0000"); // non-terminal: must never be dropped
        let live_rev = j.read(|s| s.operations.values().find(|o| !o.is_terminal()).map(|o| o.revision)).unwrap().unwrap();
        let seq_before = j.last_seq();
        let dropped = j.compact(2).unwrap();
        assert_eq!(dropped, 3);
        assert_eq!(ops(&j), 3);
        assert!(j.last_seq() >= seq_before, "the sequence never goes backwards");
        assert!(j.read(|s| s.change_floor).unwrap() > 0, "dropping records moves the change floor");
        put(&j, "op-after000");
        let lineage = j.lineage().to_owned();
        drop(j);
        let (j2, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.integrity, Integrity::Clean);
        assert_eq!(j2.lineage(), lineage);
        assert_eq!(ops(&j2), 4);
        let again = j2.read(|s| s.operations.values().find(|o| o.operation_id.as_str() == "op-live0000").map(|o| o.revision)).unwrap();
        assert_eq!(again, Some(live_rev), "a compaction never changes a revision");
        assert!(j2.last_seq() > seq_before);
    }

    /// PS-10: the file is rewritten while the store is open, and nothing is lost by it.
    #[test]
    fn a_store_that_grew_is_compacted_while_it_is_open_and_loses_nothing() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let small = StoreOptions { compact_at_bytes: 8 * 1024, ..StoreOptions::default() };
        let (j, _) = Journal::open_with(&p, &small).unwrap();
        assert!(!j.compact_if_grown().unwrap(), "an almost empty store is left alone");

        // One live record rewritten many times: almost all of the file is history.
        put(&j, "op-live0000");
        let mut rewritten = 0;
        while j.len_bytes() <= 16 * 1024 {
            j.commit(vec![Entry::Operation(Box::new(op("op-churn000", true)))]).unwrap();
            rewritten += 1;
        }
        assert!(rewritten > 10);
        let (before, seq_before) = (j.len_bytes(), j.last_seq());
        let live_rev = j.read(|s| s.operations.values().find(|o| !o.is_terminal()).map(|o| o.revision)).unwrap().unwrap();

        assert!(j.compact_if_grown().unwrap());
        let after = j.len_bytes();
        assert!(after < before / 4, "{before} -> {after}: the history is gone from the file");
        assert_eq!(ops(&j), 2, "both records are still there");
        assert_eq!(std::fs::metadata(&p).unwrap().len(), after, "the file on disk is the compacted one");
        assert!(!j.compact_if_grown().unwrap(), "current state only: nothing to reclaim");

        // The journal goes on appending to the new file, in the same sequence.
        put(&j, "op-after000");
        assert!(j.last_seq() > seq_before);
        assert!(std::fs::metadata(&p).unwrap().len() > after, "the commit after the switch reached the file");
        drop(j);
        let (j2, rep) = Journal::open_with(&p, &small).unwrap();
        assert_eq!(rep.integrity, Integrity::Clean);
        assert_eq!(ops(&j2), 3);
        let again = j2.read(|s| s.operations.values().find(|o| o.operation_id.as_str() == "op-live0000").map(|o| o.revision)).unwrap();
        assert_eq!(again, Some(live_rev), "a compaction never changes a revision");
        assert!(!d.path().join("j.wal.compacting").exists(), "no temporary file is left");
    }

    /// A store whose current state is itself large is not rewritten over and over: only growth
    /// since the last rewrite counts.
    #[test]
    fn a_large_store_is_rewritten_only_when_it_has_doubled() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let small = StoreOptions { compact_at_bytes: 4 * 1024, ..StoreOptions::default() };
        let (j, _) = Journal::open_with(&p, &small).unwrap();
        for i in 0..40 {
            put(&j, &format!("op-live{i:04}")); // forty live records: all of it is current state
        }
        assert!(j.len_bytes() > 4 * 1024);
        assert!(j.compact_if_grown().unwrap(), "the first rewrite establishes what current state costs");
        let current = j.len_bytes();
        put(&j, "op-one-more");
        assert!(!j.compact_if_grown().unwrap(), "above the threshold, but nothing worth reclaiming");
        while j.len_bytes() < 2 * current {
            j.commit(vec![Entry::Operation(Box::new(op("op-churn000", true)))]).unwrap();
        }
        assert!(j.compact_if_grown().unwrap());
        assert_eq!(ops(&j), 42);
    }

    /// The core does not open a store above its limit, and the tool that shrinks a store must be
    /// able to: otherwise a host that outgrew the limit could neither start nor be repaired.
    #[test]
    fn the_maintenance_tools_open_a_store_the_core_refuses_for_its_size() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let never = StoreOptions { compact_at_bytes: u64::MAX, ..StoreOptions::default() };
        let (j, _) = Journal::open_with(&p, &never).unwrap();
        put(&j, "op-live0000");
        while j.len_bytes() <= 32 * 1024 {
            j.commit(vec![Entry::Operation(Box::new(op("op-churn000", true)))]).unwrap();
        }
        let grown = j.len_bytes();
        drop(j);

        let core = StoreOptions { max_bytes: Some(16 * 1024), ..StoreOptions::default() };
        let refused = Journal::open_with(&p, &core).expect_err("larger than the core opens");
        assert_eq!(refused.class, FailureClass::ResourceExhausted);
        assert!(refused.message.contains("journal compact"), "the refusal names the way out: {}", refused.message);

        // `journal verify`: any size, and looking changes nothing.
        let (looked, rep) = Journal::open_with(&p, &StoreOptions::maintenance()).unwrap();
        assert_eq!((rep.integrity, looked.len_bytes()), (Integrity::Clean, grown));
        assert_eq!(std::fs::metadata(&p).unwrap().len(), grown, "opening for maintenance does not rewrite the store");
        // `journal compact`.
        looked.compact(usize::MAX).unwrap();
        assert!(looked.len_bytes() < 16 * 1024);
        drop(looked);
        let (j, _) = Journal::open_with(&p, &core).expect("the core opens the compacted store");
        assert_eq!(ops(&j), 2);
    }

    #[test]
    fn retention_forgets_only_terminal_operations_and_moves_the_change_floor() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (j, _) = Journal::open(&p).unwrap();
        j.commit(vec![Entry::Operation(Box::new(op("op-done0000", true)))]).unwrap();
        put(&j, "op-live0000");
        let done = op("op-done0000", true).key();
        let live = op("op-live0000", false).key();
        j.commit(vec![Entry::Forget(ForgetRecord {
            operations: vec![done.clone(), live.clone()],
            change_floor: 7,
            ..ForgetRecord::default()
        })])
        .unwrap();
        assert!(!j.read(|s| s.operations.contains_key(&done)).unwrap());
        assert!(j.read(|s| s.operations.contains_key(&live)).unwrap(), "a non-terminal operation is never removed (OP-13)");
        drop(j);
        let (j2, _) = Journal::open(&p).unwrap();
        assert_eq!((ops(&j2), j2.read(|s| s.change_floor).unwrap()), (1, 7), "a replay forgets the same records");
    }

    #[test]
    fn the_sequence_can_be_jumped_forward_and_never_backward() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (j, _) = Journal::open(&p).unwrap();
        put(&j, "op-aaaaaaaa");
        let seq = j.jump_sequence(500, vec![Entry::Operation(Box::new(op("op-ack00000", true)))]).unwrap();
        assert_eq!(seq, 501);
        assert_eq!(j.jump_sequence(10, vec![Entry::Operation(Box::new(op("op-ack00001", true)))]).unwrap(), 502);
        put(&j, "op-bbbbbbbb");
        drop(j);
        let (j2, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.integrity, Integrity::Clean, "a recorded jump is not a sequence break");
        assert_eq!(j2.last_seq(), 503);
    }

    #[test]
    fn the_reserve_is_released_to_record_a_commit_when_the_disk_is_full_and_taken_back_later() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let (j, _) = Journal::open_with(&p, &StoreOptions { reserve_bytes: 128 * 1024, ..StoreOptions::default() }).unwrap();
        let ballast = p.with_extension("reserve");
        assert_eq!(fs::metadata(&ballast).unwrap().len(), 128 * 1024);
        j.inject_append_error_once(std::io::ErrorKind::StorageFull);
        put(&j, "op-aaaaaaaa"); // succeeds on the retry, after the ballast was released
        assert!(j.reserve_released());
        assert_eq!(fs::metadata(&ballast).unwrap().len(), 0);
        assert_eq!(ops(&j), 1);
        assert!(j.restore_reserve());
        assert!(!j.reserve_released());
        assert_eq!(fs::metadata(&ballast).unwrap().len(), 128 * 1024);
    }
}
