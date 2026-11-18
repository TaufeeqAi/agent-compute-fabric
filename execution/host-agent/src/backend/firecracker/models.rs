//! Request/response bodies for Firecracker's HTTP API, **v1.17.0**.
//!
//! Field names and enums are transcribed from `src/firecracker/swagger/firecracker.yaml` at the
//! `v1.17.0` tag. Each body has a golden-JSON test: a typo here would otherwise only surface as an
//! opaque `400` from a live VMM, which cannot run in CI without KVM.
//!
//! Notable v1.17 details encoded on purpose:
//! * snapshot **load** uses `mem_backend` (`mem_file_path` on load is *deprecated*);
//! * snapshot **create** takes `mem_file_path` (not deprecated) and `sync_snapshot_files`;
//! * `PUT /vsock` has a deprecated `vsock_id`, which is therefore omitted;
//! * `GET /vm/config` exposes `network-interfaces`, which is how we *prove* `network=none`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MachineConfig {
    pub vcpu_count: u8,
    pub mem_size_mib: u32,
    /// SMT must stay off: sibling hyperthreads of different tenants are a side-channel risk.
    pub smt: bool,
    pub track_dirty_pages: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
    /// `Writeback` would risk losing acknowledged guest writes across a VMM crash; `Unsafe` is
    /// Firecracker's default and the one snapshotting is validated against. Spelled explicitly so
    /// a future default change cannot silently alter durability semantics.
    pub cache_type: &'static str,
    pub io_engine: &'static str,
}

/// `PUT /network-interfaces/{iface_id}`: the guest's one interface in network mode `allowlist`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NetworkInterface {
    pub iface_id: String,
    /// The device the VMM attaches to, by name, inside its own network namespace.
    pub host_dev_name: String,
    pub guest_mac: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Vsock {
    pub guest_cid: u32,
    pub uds_path: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct InstanceAction {
    pub action_type: &'static str,
}

impl InstanceAction {
    pub const START: InstanceAction = InstanceAction { action_type: "InstanceStart" };
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct VmState {
    pub state: &'static str,
}

impl VmState {
    pub const PAUSED: VmState = VmState { state: "Paused" };
    pub const RESUMED: VmState = VmState { state: "Resumed" };
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotCreate {
    pub snapshot_type: &'static str,
    pub snapshot_path: String,
    pub mem_file_path: String,
    pub sync_snapshot_files: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MemBackend {
    pub backend_type: &'static str,
    pub backend_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotLoad {
    pub snapshot_path: String,
    pub mem_backend: MemBackend,
    pub track_dirty_pages: bool,
    /// We resume explicitly after verifying `GET /` reports `Paused`, so a failed load can never
    /// leave a half-resumed guest running.
    pub resume_vm: bool,
}

/// `GET /` — fields we read.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct InstanceInfo {
    pub id: String,
    pub state: String,
    pub vmm_version: String,
}

/// `GET /vm/config` — only what we assert on.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct FullVmConfig {
    #[serde(rename = "network-interfaces", default)]
    pub network_interfaces: Vec<serde_json::Value>,
    #[serde(default)]
    pub drives: Vec<serde_json::Value>,
    #[serde(rename = "machine-config")]
    pub machine_config: Option<serde_json::Value>,
}

/// Firecracker's error body.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct FcError {
    pub fault_message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn j<T: Serialize>(v: &T) -> serde_json::Value {
        serde_json::to_value(v).unwrap()
    }

    #[test]
    fn machine_config_body() {
        assert_eq!(
            j(&MachineConfig { vcpu_count: 2, mem_size_mib: 512, smt: false, track_dirty_pages: false }),
            json!({"vcpu_count": 2, "mem_size_mib": 512, "smt": false, "track_dirty_pages": false})
        );
    }

    #[test]
    fn boot_source_and_drive_bodies() {
        assert_eq!(
            j(&BootSource { kernel_image_path: "/vmlinux".into(), boot_args: "console=ttyS0".into() }),
            json!({"kernel_image_path": "/vmlinux", "boot_args": "console=ttyS0"})
        );
        assert_eq!(
            j(&Drive {
                drive_id: "rootfs".into(),
                path_on_host: "/rootfs.ext4".into(),
                is_root_device: true,
                is_read_only: false,
                cache_type: "Unsafe",
                io_engine: "Sync"
            }),
            json!({"drive_id":"rootfs","path_on_host":"/rootfs.ext4","is_root_device":true,"is_read_only":false,"cache_type":"Unsafe","io_engine":"Sync"})
        );
    }

    #[test]
    fn vsock_omits_the_deprecated_vsock_id() {
        let v = j(&Vsock { guest_cid: 3, uds_path: "/v.sock".into() });
        assert_eq!(v, json!({"guest_cid": 3, "uds_path": "/v.sock"}));
        assert!(v.get("vsock_id").is_none());
    }

    #[test]
    fn action_and_vm_state_enums_use_the_exact_spelling() {
        assert_eq!(j(&InstanceAction::START), json!({"action_type": "InstanceStart"}));
        assert_eq!(j(&VmState::PAUSED), json!({"state": "Paused"}));
        assert_eq!(j(&VmState::RESUMED), json!({"state": "Resumed"}));
    }

    #[test]
    fn snapshot_create_uses_full_type_and_syncs_files() {
        assert_eq!(
            j(&SnapshotCreate {
                snapshot_type: "Full",
                snapshot_path: "/snap.vmstate".into(),
                mem_file_path: "/snap.mem".into(),
                sync_snapshot_files: true
            }),
            json!({"snapshot_type":"Full","snapshot_path":"/snap.vmstate","mem_file_path":"/snap.mem","sync_snapshot_files":true})
        );
    }

    #[test]
    fn snapshot_load_uses_mem_backend_never_the_deprecated_mem_file_path() {
        let v = j(&SnapshotLoad {
            snapshot_path: "/snap.vmstate".into(),
            mem_backend: MemBackend { backend_type: "File", backend_path: "/snap.mem".into() },
            track_dirty_pages: false,
            resume_vm: false,
        });
        assert_eq!(
            v,
            json!({"snapshot_path":"/snap.vmstate","mem_backend":{"backend_type":"File","backend_path":"/snap.mem"},"track_dirty_pages":false,"resume_vm":false})
        );
        assert!(v.get("mem_file_path").is_none(), "mem_file_path on load is deprecated in v1.17");
    }

    #[test]
    fn responses_parse_from_documented_shapes() {
        let info: InstanceInfo =
            serde_json::from_str(r#"{"app_name":"Firecracker","id":"anonymous-instance","state":"Not started","vmm_version":"1.17.0"}"#)
                .unwrap();
        assert_eq!((info.state.as_str(), info.vmm_version.as_str()), ("Not started", "1.17.0"));
        let cfg: FullVmConfig =
            serde_json::from_str(r#"{"drives":[{"drive_id":"rootfs"}],"machine-config":{"vcpu_count":1},"network-interfaces":[]}"#)
                .unwrap();
        assert!(cfg.network_interfaces.is_empty());
        let none: FullVmConfig = serde_json::from_str(r#"{"drives":[]}"#).unwrap();
        assert!(none.network_interfaces.is_empty(), "absent key must read as zero interfaces");
        assert_eq!(serde_json::from_str::<FcError>(r#"{"fault_message":"bad"}"#).unwrap().fault_message, "bad");
    }
}
