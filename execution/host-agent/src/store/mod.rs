//! The durable store (contract §23, boundary B14): durability, atomicity, ordering and lineage.
//! It owns no domain meaning. Exactly one core writes it (PS-5); nothing else does.

#[cfg(test)]
pub(crate) mod fixtures;
pub mod journal;
pub mod lock;
pub mod migrate;
pub mod records;

pub use journal::{Integrity, Journal, JournalState, OpenReport, StoreOptions, WriteBlock};
pub use lock::HostLock;
pub use migrate::MigrationDefaults;
pub use records::*;
