//! Operation vocabulary (contract §11). `UNKNOWN` is a first-class terminal state and is never
//! collapsed into `FAILED` or `SUCCEEDED` (OP-9).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    method::{Method, OperationClass},
    refs::SnapshotRef,
};
use crate::{
    error::{AcfError, FailureClass, SideEffect},
    ids::{Generation, SandboxId},
};

macro_rules! operation_types {
    ($( $variant:ident => $name:literal, $class:ident; )+) => {
        /// The type of a durable operation. Every method that is not a read has one; `sandbox.fail`
        /// exists only as an operation the host issues itself (OP-24) and is not a wire method.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        pub enum OperationType {
            $( #[serde(rename = $name)] $variant, )+
        }

        impl OperationType {
            pub const ALL: &'static [OperationType] = &[ $( OperationType::$variant, )+ ];

            pub const fn name(self) -> &'static str {
                match self { $( OperationType::$variant => $name, )+ }
            }

            pub const fn class(self) -> OperationClass {
                match self { $( OperationType::$variant => OperationClass::$class, )+ }
            }
        }
    };
}

operation_types! {
    SandboxCreate     => "sandbox.create",     Granting;
    SandboxStart      => "sandbox.start",      Granting;
    ExecRun           => "exec.run",           Granting;
    SnapshotCreate    => "snapshot.create",    Granting;
    SnapshotRestore   => "snapshot.restore",   Granting;
    SandboxStop       => "sandbox.stop",       Containment;
    SandboxDestroy    => "sandbox.destroy",    Containment;
    SandboxFail       => "sandbox.fail",       Containment;
    SnapshotDelete    => "snapshot.delete",    Containment;
    OperationCancel   => "operation.cancel",   Containment;
    ProfileReload     => "profile.reload",     Operator;
    QuarantineRelease => "quarantine.release", Operator;
    HostSetMode       => "host.set_mode",      Operator;
    HostAcknowledge   => "host.acknowledge",   Operator;
}

impl OperationType {
    /// The operation type a wire method creates. `None` for reads, which leave no record.
    pub const fn of(method: Method) -> Option<OperationType> {
        Some(match method {
            Method::SandboxCreate => Self::SandboxCreate,
            Method::SandboxStart => Self::SandboxStart,
            Method::ExecRun => Self::ExecRun,
            Method::SnapshotCreate => Self::SnapshotCreate,
            Method::SnapshotRestore => Self::SnapshotRestore,
            Method::SandboxStop => Self::SandboxStop,
            Method::SandboxDestroy => Self::SandboxDestroy,
            Method::SnapshotDelete => Self::SnapshotDelete,
            Method::OperationCancel => Self::OperationCancel,
            Method::ProfileReload => Self::ProfileReload,
            Method::QuarantineRelease => Self::QuarantineRelease,
            Method::HostSetMode => Self::HostSetMode,
            Method::HostAcknowledge => Self::HostAcknowledge,
            _ => return None,
        })
    }

    /// Only inside a guest can an effect be neither proven nor undone by the host (FS-4).
    pub const fn is_execution(self) -> bool {
        matches!(self, Self::ExecRun)
    }

    /// How strongly a containment operation contains a sandbox: `destroy` > `stop` > `fail` (§11.2).
    /// A containment request is refused only when one of equal or greater strength is in flight (CC-4).
    pub const fn containment_strength(self) -> u8 {
        match self {
            Self::SandboxDestroy | Self::QuarantineRelease => 3,
            Self::SandboxStop => 2,
            Self::SandboxFail => 1,
            _ => 0,
        }
    }
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Contract §11.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationState {
    /// BEGIN is durable; no step has run.
    Accepted,
    /// A step is declared or running.
    InProgress,
    /// Inherited from an earlier activation, or a step's outcome is uncertain: the host is
    /// establishing the outcome.
    Recovering,
    /// The operation's effect is in place.
    Succeeded,
    /// The effect is not in place.
    Failed,
    /// Ended by `operation.cancel` or by a containment operation.
    Cancelled,
    /// The effect may have happened and the host cannot establish it. Executions only.
    Unknown,
}

impl OperationState {
    pub const ALL: [OperationState; 7] =
        [Self::Accepted, Self::InProgress, Self::Recovering, Self::Succeeded, Self::Failed, Self::Cancelled, Self::Unknown];

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled | Self::Unknown)
    }
}

/// What a terminal operation did (API-9). A caller may issue a *new* operation for the same intent
/// safely only after `NOT_APPLIED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Effect {
    Applied,
    NotApplied,
    MayBeApplied,
}

/// Whether what a `FAILED` or `CANCELLED` operation created is gone (OP-7, FS-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Cleanup {
    /// Everything the operation created is proven removed.
    Complete,
    /// A `FAILED` generation or an `INVALID` snapshot remains and holds its lease.
    Pending,
    Quarantined,
}

/// Who ended a `CANCELLED` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancelledBy {
    /// `operation.cancel`.
    Caller,
    /// A containment operation on the same sandbox (CC-3).
    Superseded,
}

/// The table of §11.3: the `effect` of a terminal operation. `None` while it is not terminal.
///
/// `execution_started` is true for an execution whose command was handed to the guest: such a
/// command may have had effects whatever the host did afterwards.
pub const fn terminal_effect(state: OperationState, cleanup: Option<Cleanup>, execution_started: bool) -> Option<Effect> {
    match state {
        OperationState::Accepted | OperationState::InProgress | OperationState::Recovering => None,
        OperationState::Succeeded => Some(Effect::Applied),
        OperationState::Unknown => Some(Effect::MayBeApplied),
        OperationState::Failed | OperationState::Cancelled => {
            if execution_started {
                Some(Effect::MayBeApplied)
            } else {
                match cleanup {
                    Some(Cleanup::Complete) => Some(Effect::NotApplied),
                    _ => Some(Effect::MayBeApplied),
                }
            }
        }
    }
}

/// What a failed or cancelled operation may have left behind. `cleanup` is derived from the
/// committed state of this record at the time an operation is read, so it moves from `PENDING` to
/// `COMPLETE` when the residue is later proven removed, without rewriting a terminal operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Residue {
    Generation { sandbox_id: SandboxId, generation: Generation },
    Snapshot { snapshot: SnapshotRef },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FailureInfo {
    pub class: FailureClass,
    pub message: String,
    pub side_effect: SideEffect,
}

impl FailureInfo {
    pub fn new(class: FailureClass, message: impl Into<String>, side_effect: SideEffect) -> Self {
        Self { class, message: message.into(), side_effect }
    }
}

impl From<&AcfError> for FailureInfo {
    fn from(e: &AcfError) -> Self {
        Self { class: e.class, message: e.message.clone(), side_effect: e.side_effect }
    }
}

/// Canonical request fingerprint (OP-11). See [`super::fingerprint`] for the rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestFingerprint {
    pub schema_version: u32,
    pub algorithm: String,
    pub digest: String,
}

/// Identity of the safety profile in force when an operation was admitted (SP-1, SP-2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ProfileId {
    pub name: String,
    pub version: String,
    /// sha256 of the exact bytes that were verified and parsed. This is the identity.
    pub digest: String,
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}#{}", self.name, self.version, &self.digest[..self.digest.len().min(12)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_types_are_the_non_read_methods_plus_the_host_issued_one() {
        let from_methods: Vec<OperationType> = Method::ALL.iter().filter_map(|m| OperationType::of(*m)).collect();
        assert_eq!(from_methods.len(), Method::ALL.iter().filter(|m| m.requires_operation()).count());
        for m in Method::ALL {
            match OperationType::of(*m) {
                Some(t) => {
                    assert_eq!(t.name(), m.name(), "an operation is recorded under its method's name");
                    assert_eq!(t.class(), m.class());
                }
                None => assert_eq!(m.class(), OperationClass::Read, "{m}: only reads leave no record"),
            }
        }
        let host_only: Vec<_> = OperationType::ALL.iter().filter(|t| !from_methods.contains(t)).collect();
        assert_eq!(host_only, vec![&OperationType::SandboxFail]);
        assert_eq!(OperationType::SandboxFail.class(), OperationClass::Containment, "the host issues only containment (OP-25)");
        assert!(Method::parse("sandbox.fail").is_none(), "no caller can name the host's own operation");
    }

    #[test]
    fn operation_states_match_the_contract_table() {
        // §11.3: (state, terminal).
        let table = [
            ("ACCEPTED", false),
            ("IN_PROGRESS", false),
            ("RECOVERING", false),
            ("SUCCEEDED", true),
            ("FAILED", true),
            ("CANCELLED", true),
            ("UNKNOWN", true),
        ];
        for (s, (name, terminal)) in OperationState::ALL.into_iter().zip(table) {
            assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{name}\""));
            assert_eq!(s.is_terminal(), terminal, "{name}");
        }
    }

    #[test]
    fn effect_table() {
        use Cleanup::*;
        use OperationState::*;
        for s in [Accepted, InProgress, Recovering] {
            assert_eq!(terminal_effect(s, None, false), None, "{s:?}: no effect is stated before the operation ends");
        }
        assert_eq!(terminal_effect(Succeeded, None, false), Some(Effect::Applied));
        assert_eq!(terminal_effect(Unknown, None, true), Some(Effect::MayBeApplied));
        for s in [Failed, Cancelled] {
            assert_eq!(terminal_effect(s, Some(Complete), false), Some(Effect::NotApplied), "{s:?}");
            assert_eq!(terminal_effect(s, Some(Pending), false), Some(Effect::MayBeApplied), "{s:?}");
            assert_eq!(terminal_effect(s, Some(Quarantined), false), Some(Effect::MayBeApplied), "{s:?}");
            assert_eq!(terminal_effect(s, None, false), Some(Effect::MayBeApplied), "{s:?}: no proof of cleanup is not cleanup");
            assert_eq!(
                terminal_effect(s, Some(Complete), true),
                Some(Effect::MayBeApplied),
                "{s:?}: a command handed to a guest may have run whatever happened to the host side"
            );
        }
    }

    #[test]
    fn unknown_is_never_reported_as_applied_or_not_applied() {
        for cleanup in [None, Some(Cleanup::Complete), Some(Cleanup::Pending), Some(Cleanup::Quarantined)] {
            for started in [false, true] {
                assert_eq!(terminal_effect(OperationState::Unknown, cleanup, started), Some(Effect::MayBeApplied));
            }
        }
    }

    #[test]
    fn destroy_is_stronger_than_stop_and_stop_than_fail() {
        use OperationType::*;
        assert!(SandboxDestroy.containment_strength() > SandboxStop.containment_strength());
        assert!(SandboxStop.containment_strength() > SandboxFail.containment_strength());
        assert!(SandboxFail.containment_strength() > SandboxStart.containment_strength());
    }
}
