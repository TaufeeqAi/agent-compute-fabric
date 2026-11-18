//! The command set (contract §10.3), its classes (§11.2) and the role table (§9.2).
//!
//! This is the closed vocabulary a caller can name. Everything else about a request is data. The
//! table is pure, so "every method × every role" (T-AUTH-02) and "every host mode × every class"
//! (T-STATE-04) are exhaustive unit tests, not samples.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::authority::Role;

/// What an operation does to privilege (§11.2). The class, not the method, decides how the host
/// treats capacity, exclusivity, deadlines and inheritance by a later activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    /// Creates privilege: runs once, bounded by a deadline, never continued by a later activation.
    Granting,
    /// Removes privilege: never refused for capacity or load, re-driven until proven.
    Containment,
    /// Served from committed state. Leaves no record.
    Read,
    /// Administers the host. Role `operator` only; one at a time.
    Operator,
}

macro_rules! methods {
    ($( $variant:ident => $name:literal, $class:ident; )+) => {
        /// Every method of the host API, by its wire name.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
        pub enum Method {
            $( #[serde(rename = $name)] $variant, )+
        }

        impl Method {
            pub const ALL: &'static [Method] = &[ $( Method::$variant, )+ ];

            pub const fn name(self) -> &'static str {
                match self { $( Method::$variant => $name, )+ }
            }

            pub fn parse(name: &str) -> Option<Method> {
                match name { $( $name => Some(Method::$variant), )+ _ => None }
            }

            pub const fn class(self) -> OperationClass {
                match self { $( Method::$variant => OperationClass::$class, )+ }
            }
        }
    };
}

methods! {
    SandboxCreate      => "sandbox.create",     Granting;
    SandboxStart       => "sandbox.start",      Granting;
    ExecRun            => "exec.run",           Granting;
    SnapshotCreate     => "snapshot.create",    Granting;
    SnapshotRestore    => "snapshot.restore",   Granting;
    SandboxStop        => "sandbox.stop",       Containment;
    SandboxDestroy     => "sandbox.destroy",    Containment;
    SnapshotDelete     => "snapshot.delete",    Containment;
    OperationCancel    => "operation.cancel",   Containment;
    SandboxInspect     => "sandbox.inspect",    Read;
    SandboxList        => "sandbox.list",       Read;
    SnapshotList       => "snapshot.list",      Read;
    OperationGet       => "operation.get",      Read;
    OperationList      => "operation.list",     Read;
    RunInspect         => "run.inspect",        Read;
    RunOutput          => "run.output",         Read;
    HostInfo           => "host.info",          Read;
    HostMetrics        => "host.metrics",       Read;
    ProfileReload      => "profile.reload",     Operator;
    QuarantineRelease  => "quarantine.release", Operator;
    HostSetMode        => "host.set_mode",      Operator;
    HostAcknowledge    => "host.acknowledge",   Operator;
}

impl Method {
    /// Granting, containment and operator methods create a durable operation and therefore require a
    /// caller-supplied `operation_id` and `issued_at` (§10.2, INV-005).
    pub const fn requires_operation(self) -> bool {
        !matches!(self.class(), OperationClass::Read)
    }

    /// The role table of §9.2. A method outside the peer's role is refused with `AUTHORIZATION_DENIED`.
    pub const fn allowed_for(self, role: Role) -> bool {
        match role {
            Role::Observer => matches!(self, Method::HostInfo | Method::HostMetrics),
            Role::Caller => !matches!(self.class(), OperationClass::Operator),
            Role::Operator => true,
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_set_is_exactly_the_contract_table() {
        // §10.3, transcribed. A method added or removed in code without a contract change fails here.
        let table: &[(&str, OperationClass)] = &[
            ("sandbox.create", OperationClass::Granting),
            ("sandbox.start", OperationClass::Granting),
            ("exec.run", OperationClass::Granting),
            ("snapshot.create", OperationClass::Granting),
            ("snapshot.restore", OperationClass::Granting),
            ("sandbox.stop", OperationClass::Containment),
            ("sandbox.destroy", OperationClass::Containment),
            ("snapshot.delete", OperationClass::Containment),
            ("operation.cancel", OperationClass::Containment),
            ("sandbox.inspect", OperationClass::Read),
            ("sandbox.list", OperationClass::Read),
            ("snapshot.list", OperationClass::Read),
            ("operation.get", OperationClass::Read),
            ("operation.list", OperationClass::Read),
            ("run.inspect", OperationClass::Read),
            ("run.output", OperationClass::Read),
            ("host.info", OperationClass::Read),
            ("host.metrics", OperationClass::Read),
            ("profile.reload", OperationClass::Operator),
            ("quarantine.release", OperationClass::Operator),
            ("host.set_mode", OperationClass::Operator),
            ("host.acknowledge", OperationClass::Operator),
        ];
        assert_eq!(Method::ALL.len(), table.len());
        for (name, class) in table {
            let m = Method::parse(name).unwrap_or_else(|| panic!("{name} is in the contract but not in the code"));
            assert_eq!(m.class(), *class, "{name}");
            assert_eq!(m.name(), *name);
            assert_eq!(serde_json::to_string(&m).unwrap(), format!("\"{name}\""), "the wire name is the contract name");
        }
        assert!(Method::parse("sandbox.pause").is_none(), "pause/resume are not caller-visible (§10.3)");
        assert!(Method::parse("rm.rf").is_none());
    }

    #[test]
    fn every_method_for_every_role_matches_the_role_table() {
        for &m in Method::ALL {
            let observer = matches!(m, Method::HostInfo | Method::HostMetrics);
            assert_eq!(m.allowed_for(Role::Observer), observer, "observer × {m}");
            assert_eq!(m.allowed_for(Role::Caller), m.class() != OperationClass::Operator, "caller × {m}");
            assert!(m.allowed_for(Role::Operator), "operator × {m}");
        }
    }

    #[test]
    fn only_reads_are_exempt_from_an_operation_identity() {
        for &m in Method::ALL {
            assert_eq!(m.requires_operation(), m.class() != OperationClass::Read, "{m}");
        }
    }
}
