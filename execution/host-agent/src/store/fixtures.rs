//! Record builders for unit tests (compiled only under `cfg(test)`).

use std::collections::BTreeSet;

use super::records::{GenerationRecord, SnapshotRecord};
use crate::{
    domain::{ImageRef, LifecycleState, NetworkIntent, OwnerScope, PeerId, ProfileId, Reservation, SandboxResources, SnapshotState, Tags},
    ids::{Generation, OperationId, SandboxId, SnapshotId},
};

pub(crate) fn tags(scope: &str) -> Tags {
    Tags { peer_id: PeerId::parse("peer-1").unwrap(), owner_scope: OwnerScope::parse(scope).unwrap() }
}

pub(crate) fn profile_id() -> ProfileId {
    ProfileId { name: "p".into(), version: "1".into(), digest: "0".repeat(64) }
}

pub(crate) fn image() -> ImageRef {
    ImageRef {
        image_id: "sha256:i".into(),
        alias: None,
        architecture: "x".into(),
        kernel_identity: "k".into(),
        rootfs_identity: "r".into(),
        manifest_version: 1,
        provenance_reference: None,
    }
}

pub(crate) fn resources(vcpus: u8, memory_mib: u32, disk_mib: u32) -> SandboxResources {
    SandboxResources { vcpus, memory_mib, disk_mib, network: NetworkIntent::None }
}

pub(crate) fn generation(reservation: Reservation, state: LifecycleState) -> GenerationRecord {
    GenerationRecord {
        sandbox_id: SandboxId::generate(),
        generation: Generation::FIRST,
        tags: tags("scope-a"),
        state,
        paused_from: None,
        resources: resources(1, 128, 64),
        image: image(),
        reservation,
        owner_nonce: "n".into(),
        handle: None,
        process: None,
        created_by: OperationId::parse("op-12345678").unwrap(),
        created_seq: 0,
        source_snapshot: None,
        last_run: None,
        profile_id: profile_id(),
        security_profile_id: "sp".into(),
        expected_agent_version: None,
        guest_agent_version: None,
        secret_refs: BTreeSet::new(),
        failure: None,
        quarantined: None,
        quarantined_ms: None,
        observe_attempts: 0,
        updated_wall: String::new(),
        revision: 0,
    }
}

pub(crate) fn snapshot(reserved_bytes: u64, state: SnapshotState) -> SnapshotRecord {
    SnapshotRecord {
        snapshot_id: SnapshotId::generate(),
        generation: Generation::FIRST,
        tags: tags("scope-a"),
        name: None,
        state,
        manifest_digest: None,
        reserved_bytes,
        actual_bytes: 0,
        source: None,
        source_run: None,
        created_by: OperationId::parse("op-12345678").unwrap(),
        created_wall: String::new(),
        restore_count: 0,
        secret_refs: BTreeSet::new(),
        failure: None,
        deleted_ms: None,
        revision: 0,
    }
}
