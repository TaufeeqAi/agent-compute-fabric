//! Crash-point injection (contract T-OP-05, T-REC-02; never in a release build, TI-3). A "crash" is modelled by the operation task returning
//! [`Crashed`] at a named point *without running any cleanup or commit code that would have
//! followed* — exactly what process death does. Tests then build a fresh coordinator over the
//! same on-disk journal and backend world and run recovery.

use std::{collections::HashSet, sync::Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// Request accepted, nothing durable yet.
    BeforeJournalWrite,
    /// Journal says "accepted", no mutation performed.
    AfterJournalBeforeMutation,
    /// A privileged step is declared in the journal but has not run.
    BeforeBackendStep,
    /// The backend mutated host state; nothing recorded the result.
    AfterBackendMutationBeforeCommit,
    /// Result committed to the journal; the client never got the response.
    AfterTerminalCommitBeforeResponse,
}

#[derive(Debug)]
pub struct Crashed(pub FaultPoint);

#[derive(Debug, Default)]
pub struct FaultInjector {
    armed: Mutex<HashSet<(FaultPoint, String)>>,
}

impl FaultInjector {
    /// Arm `point` for the given operation step name (`"*"` matches any step).
    pub fn arm(&self, point: FaultPoint, step: &str) {
        if let Ok(mut a) = self.armed.lock() {
            a.insert((point, step.to_owned()));
        }
    }

    pub fn disarm_all(&self) {
        if let Ok(mut a) = self.armed.lock() {
            a.clear();
        }
    }

    /// Returns `Err(Crashed)` (once) if this point+step is armed.
    pub fn hit(&self, point: FaultPoint, step: &str) -> Result<(), Crashed> {
        let Ok(mut a) = self.armed.lock() else { return Ok(()) };
        if a.remove(&(point, step.to_owned())) || a.remove(&(point, "*".to_owned())) {
            return Err(Crashed(point));
        }
        Ok(())
    }
}
