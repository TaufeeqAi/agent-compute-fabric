//! Store schema migration (contract PS-11, PS-12).
//!
//! A migration is **atomic**: the new-schema file is written and fsynced beside the old one, and only
//! then do two renames switch them. An interruption before the first rename leaves the previous
//! schema intact and usable by the previous version; an interruption between the two is finished at
//! the next open. The old file is kept as `<store>.schema<N>` and is never deleted by the host.
//!
//! Migration works on the *latest record per key* and never interprets an operation's intent: a
//! non-terminal operation is carried over as it is and is then resolved like any other inherited
//! operation (§11.6), which needs only its type, target and declared resources (PS-12).
//!
//! Schema 1 → 2 (this file): records gain scope tags, an expiry, the dotted operation names, the
//! closed failure-class set and the tagged network intent. Results of operations that completed
//! under schema 1 are not carried over (their shape changed); their terminal state is.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};

use super::{
    journal::{Batch, checked_payload, encode, fsync_dir},
    records::{Entry, STORE_SCHEMA_VERSION, StoreMeta},
};
use crate::{
    clock::MonotonicRef,
    domain::{OwnerScope, PeerId},
    error::{AcfError, Result},
};

/// How to complete records written before tags and expiry existed.
#[derive(Debug, Clone)]
pub struct MigrationDefaults {
    /// Peer and scope that own every migrated record.
    pub peer_id: PeerId,
    pub owner_scope: OwnerScope,
    /// Lifetime granted to every migrated sandbox, counted from the migration.
    pub lifetime_ms: u64,
    pub now_wall: String,
    pub now_wall_ms: i64,
    pub now_mono: MonotonicRef,
}

fn staged(path: &Path) -> PathBuf {
    path.with_extension("wal.migrating")
}

fn backup(path: &Path, from: u32) -> PathBuf {
    path.with_extension(format!("wal.schema{from}"))
}

/// Finish or discard a migration that was interrupted (called before the store is opened).
pub(crate) fn finish_interrupted(path: &Path) -> Result<()> {
    let staged = staged(path);
    if !staged.exists() {
        return Ok(());
    }
    if path.exists() {
        // The switch never started: the previous schema is intact. Drop the staging file.
        fs::remove_file(&staged)?;
    } else {
        // The old file was already moved aside, and the staging file was complete before that.
        fs::rename(&staged, path)?;
    }
    if let Some(dir) = path.parent() {
        fsync_dir(dir)?;
    }
    Ok(())
}

fn class_v2(v1: &str) -> &'static str {
    match v1 {
        "VALIDATION" => "INVALID_REQUEST",
        "AUTHORIZATION" => "AUTHORIZATION_DENIED",
        "STATE_CONFLICT" => "STATE_CONFLICT",
        "ADMISSION_REJECTED" | "RESOURCE_EXHAUSTION" | "OUTPUT_LIMIT" => "RESOURCE_EXHAUSTED",
        "TIMEOUT_UNKNOWN" => "TIMEOUT",
        "BACKEND_UNAVAILABLE" | "BACKEND_CRASH" => "DEPENDENCY_UNAVAILABLE",
        "CORRUPT_INPUT" => "INTEGRITY_FAILURE",
        "SCHEMA_MISMATCH" => "PROTOCOL_ERROR",
        "COMPATIBILITY_FAILURE" => "INCOMPATIBLE_RUNTIME",
        "PARTIAL_COMPLETION" => "PARTIAL_COMPLETION",
        "LOST_RESPONSE" => "UNKNOWN_OUTCOME",
        "SECURITY_CONTROL_FAILURE" => "SECURITY_CONTROL_FAILURE",
        "RECOVERY_QUARANTINED" => "QUARANTINED",
        "UNSUPPORTED" => "UNSUPPORTED",
        "NOT_FOUND" => "NOT_FOUND",
        _ => "INTERNAL_ERROR",
    }
}

fn failure_v2(f: &Value) -> Value {
    if f.is_null() {
        return Value::Null;
    }
    json!({
        "class": class_v2(f["class"].as_str().unwrap_or_default()),
        "message": f["message"].as_str().unwrap_or_default(),
        "side_effect": if f["side_effect"] == "none" { "NONE" } else { "POSSIBLE" },
    })
}

fn type_v2(v1: &str) -> Option<&'static str> {
    Some(match v1 {
        "sandbox_create" => "sandbox.create",
        "sandbox_start" => "sandbox.start",
        "sandbox_stop" => "sandbox.stop",
        "sandbox_destroy" => "sandbox.destroy",
        "exec" => "exec.run",
        "snapshot_create" => "snapshot.create",
        "snapshot_restore" => "snapshot.restore",
        "snapshot_delete" => "snapshot.delete",
        "policy_reload" => "profile.reload",
        _ => return None,
    })
}

fn resources_v2(r: &Value) -> Value {
    let mut r = r.clone();
    if r["network"].is_string() {
        r["network"] = json!({"mode": "none"});
    }
    r
}

fn tags(d: &MigrationDefaults) -> Value {
    json!({"peer_id": d.peer_id, "owner_scope": d.owner_scope})
}

fn operation_v2(o: &Value, d: &MigrationDefaults) -> Result<Value> {
    let ty = type_v2(o["operation_type"].as_str().unwrap_or_default())
        .ok_or_else(|| AcfError::corrupt(format!("schema 1 operation of unknown type {}", o["operation_type"])))?;
    let step = if o["phase"]["phase"] == "in_progress" { o["phase"]["step"].clone() } else { Value::Null };
    let failure = failure_v2(&o["failure"]);
    // Under schema 1 any operation could end UNKNOWN. Only an execution can now (FS-4): for the
    // others, "the host could not prove it clean" is a failure whose cleanup is still pending.
    let (state, cleanup) = match (o["status"].as_str().unwrap_or_default(), ty) {
        ("ACCEPTED", _) => ("ACCEPTED", Value::Null),
        ("IN_PROGRESS", _) => ("IN_PROGRESS", Value::Null),
        ("SUCCEEDED", _) => ("SUCCEEDED", Value::Null),
        ("CANCELLED", _) => ("CANCELLED", json!("COMPLETE")),
        ("UNKNOWN", "exec.run") => ("UNKNOWN", Value::Null),
        ("UNKNOWN", _) => ("FAILED", json!("PENDING")),
        (_, _) => ("FAILED", if failure["side_effect"] == "POSSIBLE" { json!("PENDING") } else { json!("COMPLETE") }),
    };
    let terminal = !matches!(state, "ACCEPTED" | "IN_PROGRESS");
    let residue = match (&o["sandbox"], cleanup == json!("PENDING")) {
        (Value::Array(s), true) if s.len() == 2 => json!({"kind": "generation", "sandbox_id": s[0], "generation": s[1]}),
        _ => Value::Null,
    };
    Ok(json!({
        "kind": "operation",
        "operation_id": o["operation_id"],
        "tags": tags(d),
        "on_behalf_of": o["caller"]["uid"].as_u64().map(|u| format!("local-uid:{u}")),
        "issuer": "PEER",
        "operation_type": ty,
        "fingerprint": o["fingerprint"],
        "protocol": o["request_schema_version"],
        "target": o["resource_id"],
        "expected_generation": o["expected_generation"],
        "issued_at": o["created_wall"],
        "created_wall": o["created_wall"],
        "created_ms": 0,
        "created_mono": o["created_mono"],
        "deadline": o["deadline"],
        "profile_id": o["policy_id"],
        "epoch": 0,
        "state": state,
        "step": step,
        "cancelled_by": if state == "CANCELLED" { json!("CALLER") } else { Value::Null },
        "failure": failure,
        "cleanup": cleanup,
        "residue": residue,
        "execution_started": ty == "exec.run" && o["phase"]["phase"] != "accepted",
        "result": null,
        "run_id": o["run_id"],
        "sandbox": o["sandbox"],
        "snapshot": o["snapshot"],
        "recovery_id": o["recovery_id"],
        "finished_ms": if terminal { json!(d.now_wall_ms) } else { Value::Null },
        "updated_wall": o["updated_wall"],
    }))
}

fn generation_v2(g: &Value, d: &MigrationDefaults) -> Value {
    let mut out = g.clone();
    out["kind"] = json!("generation");
    out["tags"] = tags(d);
    out["resources"] = resources_v2(&g["resources"]);
    if out["handle"].is_object() {
        out["handle"]["resources"] = resources_v2(&g["handle"]["resources"]);
    }
    out["profile_id"] = g["policy_id"].clone();
    out["failure"] = failure_v2(&g["failure"]);
    out["expected_agent_version"] = Value::Null;
    out["guest_agent_version"] = Value::Null;
    out["quarantined_ms"] = if g["quarantined"].is_null() { Value::Null } else { json!(d.now_wall_ms) };
    if let Some(m) = out.as_object_mut() {
        m.remove("policy_id");
    }
    out
}

fn snapshot_v2(s: &Value, d: &MigrationDefaults) -> Value {
    let mut out = s.clone();
    out["kind"] = json!("snapshot");
    out["tags"] = tags(d);
    out["failure"] = failure_v2(&s["failure"]);
    out["deleted_ms"] = if s["state"] == "DELETED" { json!(d.now_wall_ms) } else { Value::Null };
    out
}

fn sandbox_v2(s: &Value, destroyed: bool, d: &MigrationDefaults) -> Value {
    json!({
        "kind": "sandbox",
        "sandbox_id": s["sandbox_id"],
        "tags": tags(d),
        "name": s["name"],
        "created_wall": s["created_wall"],
        "created_ms": 0,
        "last_generation": s["last_generation"],
        "current": s["current"],
        "expiry": {
            "boot_id": d.now_mono.boot_id,
            "mono_ns": d.now_mono.ns.saturating_add(d.lifetime_ms.saturating_mul(1_000_000)),
            "wall_ms": d.now_wall_ms.saturating_add(i64::try_from(d.lifetime_ms).unwrap_or(i64::MAX)),
            "lifetime_ms": d.lifetime_ms,
        },
        "destroyed_ms": if destroyed { json!(d.now_wall_ms) } else { Value::Null },
    })
}

fn recovery_v2(r: &Value, d: &MigrationDefaults) -> Value {
    json!({
        "kind": "recovery",
        "recovery_id": r["recovery_id"],
        "operation": {"peer_id": d.peer_id, "owner_scope": d.owner_scope, "operation_id": r["operation_id"]},
        "target": r["resource_id"],
        "generation": r["generation"],
        "plan": r["initial_classification"],
        "observations": r["observations"],
        "actions": r["actions"],
        "attempt_count": r["attempt_count"],
        "outcome": r["final_classification"],
        "quarantine_reason": r["quarantine_reason"],
        "updated_wall": r["updated_wall"],
    })
}

/// The latest schema 1 record per key, in a stable order.
fn fold_v1(bytes: &[u8]) -> Result<BTreeMap<String, Value>> {
    let mut latest: BTreeMap<String, Value> = BTreeMap::new();
    let mut next_seq = 1u64;
    let mut pos = 0usize;
    while pos < bytes.len() {
        let rest = &bytes[pos..];
        let Some(nl) = rest.iter().position(|b| *b == b'\n') else { break }; // a torn tail is not a commit
        let last = pos + nl + 1 == bytes.len();
        let parsed = checked_payload(&rest[..nl]).and_then(|p| serde_json::from_slice::<Value>(p).map_err(|e| e.to_string()));
        let batch = match parsed {
            Ok(b) if b["seq"].as_u64() == Some(next_seq) => b,
            _ if last => break, // a bad final record is a torn append
            Ok(b) => return Err(AcfError::corrupt(format!("schema 1 store: sequence break at {} (expected {next_seq})", b["seq"]))),
            Err(e) => return Err(AcfError::corrupt(format!("schema 1 store: {e}"))),
        };
        for e in batch["entries"].as_array().into_iter().flatten() {
            let key = match e["kind"].as_str().unwrap_or_default() {
                "operation" => format!("1-operation/{}", e["operation_id"]),
                "sandbox" => format!("2-sandbox/{}", e["sandbox_id"]),
                "generation" => format!("3-generation/{}/{:020}", e["sandbox_id"], e["generation"].as_u64().unwrap_or(0)),
                "snapshot" => format!("4-snapshot/{}/{:020}", e["snapshot_id"], e["generation"].as_u64().unwrap_or(0)),
                "recovery" => format!("5-recovery/{}", e["recovery_id"]),
                "quarantine" => format!("6-quarantine/{}/{}/{}", e["resource_id"], e["generation"], e["reason"]),
                _ => continue, // runtime manifests describe a past activation of a past version
            };
            latest.insert(key, e.clone());
        }
        next_seq += 1;
        pos += nl + 1;
    }
    Ok(latest)
}

/// Rewrite the store at `path` (whose content is `bytes`, schema `from`) under the current schema.
pub(crate) fn migrate(path: &Path, bytes: &[u8], from: u32, d: &MigrationDefaults) -> Result<()> {
    if from != 1 {
        return Err(AcfError::incompatible(format!("no migration from store schema {from} to {STORE_SCHEMA_VERSION}")));
    }
    let v1 = fold_v1(bytes)?;
    let destroyed = |sandbox: &Value| {
        let key = format!("3-generation/{}/{:020}", sandbox["sandbox_id"], sandbox["current"].as_u64().unwrap_or(0));
        v1.get(&key).is_some_and(|g| g["state"] == "DESTROYED")
    };
    let mut entries: Vec<Entry> = vec![Entry::Meta(StoreMeta {
        schema_version: STORE_SCHEMA_VERSION,
        lineage: crate::ids::random_token()?,
        created_wall: d.now_wall.clone(),
    })];
    for old in v1.values() {
        let new = match old["kind"].as_str().unwrap_or_default() {
            "operation" => operation_v2(old, d)?,
            "sandbox" => sandbox_v2(old, destroyed(old), d),
            "generation" => generation_v2(old, d),
            "snapshot" => snapshot_v2(old, d),
            "recovery" => recovery_v2(old, d),
            _ => old.clone(),
        };
        let entry: Entry = serde_json::from_value(new)
            .map_err(|e| AcfError::corrupt(format!("schema 1 record does not convert ({}): {e}", old["kind"])))?;
        entries.push(entry);
    }

    let staged = staged(path);
    let mut out = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&staged)?;
    for (i, chunk) in entries.chunks(64).enumerate() {
        let seq = i as u64 + 1;
        let mut chunk = chunk.to_vec();
        for e in &mut chunk {
            e.stamp(seq);
        }
        out.write_all(&encode(&Batch { seq, epoch: 0, jump: false, entries: chunk })?)?;
    }
    crate::durability::sync_all(&out)?;
    drop(out);
    // The switch. Before the first rename the old store is untouched; between the two renames
    // `finish_interrupted` completes it.
    fs::rename(path, backup(path, from))?;
    fs::rename(&staged, path)?;
    if let Some(dir) = path.parent() {
        fsync_dir(dir)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        domain::{LifecycleState, NetworkIntent, OperationState, OperationType},
        store::{Integrity, Journal, StoreOptions},
    };

    fn defaults() -> MigrationDefaults {
        MigrationDefaults {
            peer_id: PeerId::parse("local-admin").unwrap(),
            owner_scope: OwnerScope::parse("default").unwrap(),
            lifetime_ms: 3_600_000,
            now_wall: "2026-11-18T00:00:00.000Z".into(),
            now_wall_ms: 1_795_000_000_000,
            now_mono: MonotonicRef { boot_id: "boot".into(), ns: 5 },
        }
    }

    fn v1_line(seq: u64, entries: Value) -> Vec<u8> {
        let json = serde_json::to_vec(&json!({"seq": seq, "entries": entries})).unwrap();
        let mut line = format!("{:08x} ", crc32fast::hash(&json)).into_bytes();
        line.extend(json);
        line.push(b'\n');
        line
    }

    const SBX: &str = "sbx-00000000000000000000000000000001";

    pub(crate) fn v1_store() -> Vec<u8> {
        let fp = json!({"schema_version": 1, "algorithm": "sha256", "digest": "d"});
        let mono = json!({"boot_id": "old-boot", "ns": 1});
        let policy = json!({"name": "p", "version": "1", "digest": "0".repeat(64)});
        let op = |id: &str, ty: &str, phase: Value, status: &str, failure: Value| {
            json!({"kind": "operation", "operation_id": id, "operation_type": ty, "fingerprint": fp, "request_schema_version": "acf.host/1",
                "resource_id": SBX, "expected_generation": 1, "created_wall": "2026-10-01T00:00:00.000Z", "created_mono": mono, "deadline": mono,
                "caller": {"uid": 1000, "gid": 1000, "pid": 7}, "policy_id": policy, "phase": phase, "status": status, "failure": failure,
                "result": {"type": "sandbox", "data": {}}, "run_id": null, "sandbox": [SBX, 1], "snapshot": null, "recovery_id": null,
                "updated_wall": "2026-10-01T00:00:01.000Z"})
        };
        let resources = json!({"vcpus": 2, "memory_mib": 256, "disk_mib": 128, "network": "none"});
        let image = json!({"image_id": "sha256:i", "alias": "python", "architecture": "x86_64", "kernel_identity": "sha256:k",
            "rootfs_identity": "sha256:r", "manifest_version": 1, "provenance_reference": null});
        let generation = json!({"kind": "generation", "sandbox_id": SBX, "generation": 1, "state": "RUNNING", "paused_from": null,
            "resources": resources, "image": image, "reservation": {"vcpus": 2, "memory_mib": 320, "disk_mib": 128, "uid_slot": 0},
            "owner_nonce": "n", "handle": {"sandbox": {"sandbox_id": SBX, "generation": 1}, "uid": 100000, "gid": 100000, "resources": resources,
            "boot_args": "", "process": null}, "process": null, "created_by": "op-create00", "source_snapshot": null, "last_run": null,
            "policy_id": policy, "security_profile_id": "sp", "failure": null, "quarantined": null, "updated_wall": "t"});
        let mut b =
            v1_line(1, json!([{"kind": "runtime_manifest", "instance_id": "i", "profile_id": "sp", "recorded_wall": "t", "manifest": {}}]));
        b.extend(v1_line(
            2,
            json!([op("op-create00", "sandbox_create", json!({"phase": "terminal"}), "SUCCEEDED", Value::Null),
                {"kind": "sandbox", "sandbox_id": SBX, "name": "base", "created_wall": "t", "last_generation": 1, "current": 1}, generation]),
        ));
        b.extend(v1_line(
            3,
            json!([op("op-exec0000", "exec", json!({"phase": "in_progress", "step": "exec"}), "IN_PROGRESS", Value::Null)]),
        ));
        b.extend(v1_line(
            4,
            json!([op(
                "op-stop0000",
                "sandbox_stop",
                json!({"phase": "terminal"}),
                "UNKNOWN",
                json!({"class": "BACKEND_CRASH", "message": "VMM survived", "side_effect": "possible"})
            )]),
        ));
        b
    }

    #[test]
    fn a_schema_1_store_is_migrated_with_its_non_terminal_operations_and_the_old_file_is_kept() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        fs::write(&p, v1_store()).unwrap();
        let (j, rep) = Journal::open_with(&p, &StoreOptions { migration: Some(defaults()), ..StoreOptions::default() }).unwrap();
        assert_eq!((rep.integrity.clone(), rep.migrated_from), (Integrity::Clean, Some(1)));
        assert_eq!(fs::read(d.path().join("j.wal.schema1")).unwrap(), v1_store(), "the previous store is kept, byte for byte");
        let epoch = j.epoch();
        j.read(|s| {
            assert_eq!(s.meta.as_ref().unwrap().schema_version, STORE_SCHEMA_VERSION);
            assert_eq!(s.operations.len(), 3);
            let by = |id: &str| s.operations.values().find(|o| o.operation_id.as_str() == id).unwrap();
            let exec = by("op-exec0000");
            assert_eq!(
                (exec.operation_type, exec.state, exec.step.as_deref()),
                (OperationType::ExecRun, OperationState::InProgress, Some("exec"))
            );
            assert!(exec.is_inherited(epoch), "a migrated non-terminal operation is inherited, so it is never continued");
            assert!(exec.execution_started);
            let stop = by("op-stop0000");
            assert_eq!(stop.state, OperationState::Failed, "only an execution may end UNKNOWN under the current schema");
            assert_eq!(stop.failure.as_ref().unwrap().class, crate::error::FailureClass::DependencyUnavailable);
            assert_eq!(stop.cleanup, Some(crate::domain::Cleanup::Pending));
            assert_eq!(by("op-create00").on_behalf_of.as_deref(), Some("local-uid:1000"));
            assert_eq!(s.open_operations.len(), 1);
            let sb = s.sandboxes.values().next().unwrap();
            assert_eq!(
                (sb.tags.peer_id.as_str(), sb.tags.owner_scope.as_str(), sb.expiry.lifetime_ms),
                ("local-admin", "default", 3_600_000)
            );
            let g = s.generations.values().next().unwrap();
            assert_eq!((g.state, &g.resources.network), (LifecycleState::Running, &NetworkIntent::None));
            assert!(g.created_seq > 0 && g.revision > 0);
        })
        .unwrap();
        drop(j);
        let (_, again) = Journal::open(&p).unwrap();
        assert_eq!((again.integrity, again.migrated_from), (Integrity::Clean, None), "a migrated store opens as an ordinary one");
    }

    #[test]
    fn a_migration_interrupted_before_the_switch_leaves_the_previous_schema_usable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        fs::write(&p, v1_store()).unwrap();
        fs::write(staged(&p), b"half-written new store").unwrap(); // crash while staging
        finish_interrupted(&p).unwrap();
        assert!(!staged(&p).exists());
        assert_eq!(fs::read(&p).unwrap(), v1_store(), "the schema 1 store is byte-for-byte what the previous version left");
    }

    #[test]
    fn a_migration_interrupted_between_the_renames_is_finished_at_the_next_open() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        fs::write(&p, v1_store()).unwrap();
        migrate(&p, &v1_store(), 1, &defaults()).unwrap();
        // Recreate the window: new store still staged, old store already moved aside.
        fs::rename(&p, staged(&p)).unwrap();
        let (j, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.integrity, Integrity::Clean);
        assert_eq!(j.read(|s| s.operations.len()).unwrap(), 3);
        assert!(backup(&p, 1).exists());
    }

    #[test]
    fn without_migration_defaults_an_older_schema_is_not_interpreted() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        fs::write(&p, v1_store()).unwrap();
        let (j, rep) = Journal::open(&p).unwrap();
        assert_eq!(rep.integrity, Integrity::UnsupportedSchema { found: 1 });
        assert_eq!(j.read(|s| s.operations.len()).unwrap(), 0);
        assert_eq!(fs::read(&p).unwrap(), v1_store());
    }

    #[test]
    fn a_corrupt_schema_1_store_is_not_migrated() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("j.wal");
        let mut bytes = v1_store();
        let first_nl = bytes.iter().position(|b| *b == b'\n').unwrap();
        bytes[first_nl + 30] ^= 0x55;
        fs::write(&p, &bytes).unwrap();
        assert!(migrate(&p, &bytes, 1, &defaults()).is_err());
        assert_eq!(fs::read(&p).unwrap(), bytes, "nothing was switched");
        assert!(!staged(&p).exists());
    }
}
