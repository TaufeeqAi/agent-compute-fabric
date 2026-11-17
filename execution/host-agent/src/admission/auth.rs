//! Caller identity and endpoint authorization (spec §16.1–16.2).
//!
//! Identity comes from the kernel (`SO_PEERCRED`), never from the request body. If it cannot be
//! established the request is **denied** — there is no anonymous mode and no fallback.

use crate::{
    domain::CallerIdentity,
    error::{AcfError, Result},
};

/// Credentials as reported by the kernel for a connected peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Authorizer {
    allowed_uids: Vec<u32>,
    allowed_gids: Vec<u32>,
}

impl Authorizer {
    pub fn new(allowed_uids: Vec<u32>, allowed_gids: Vec<u32>) -> Self {
        Self { allowed_uids, allowed_gids }
    }

    /// `peer == None` means credentials could not be obtained: fail closed.
    pub fn authorize(&self, peer: Option<PeerCred>) -> Result<CallerIdentity> {
        let p = peer.ok_or_else(|| AcfError::authorization("peer credentials unavailable; refusing anonymous caller"))?;
        if self.allowed_uids.contains(&p.uid) || self.allowed_gids.contains(&p.gid) {
            Ok(CallerIdentity { uid: p.uid, gid: p.gid, pid: p.pid })
        } else {
            Err(AcfError::authorization(format!("uid {} gid {} is not permitted to use this host agent", p.uid, p.gid)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FailureClass;

    fn a() -> Authorizer {
        Authorizer::new(vec![0], vec![990])
    }

    #[test]
    fn allowed_by_uid_or_gid() {
        assert!(a().authorize(Some(PeerCred { uid: 0, gid: 7, pid: Some(1) })).is_ok());
        assert!(a().authorize(Some(PeerCred { uid: 1000, gid: 990, pid: None })).is_ok());
    }

    #[test]
    fn unknown_caller_and_missing_credentials_are_denied() {
        let e = a().authorize(Some(PeerCred { uid: 1000, gid: 1000, pid: None })).unwrap_err();
        assert_eq!(e.class, FailureClass::Authorization);
        let e = a().authorize(None).unwrap_err();
        assert_eq!(e.class, FailureClass::Authorization);
        assert!(
            Authorizer::new(vec![], vec![]).authorize(Some(PeerCred { uid: 0, gid: 0, pid: None })).is_err(),
            "empty allowlist denies everyone, even root"
        );
    }
}
