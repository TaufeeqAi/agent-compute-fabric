//! The suites named after the contract's test catalog (§31.2). One module per catalog section; each
//! test is named after the catalog entry it implements (`t_auth_02_…`).
//!
//! Evidence level: everything here is L2 — the real coordinator, store, recovery and admission
//! pipeline over the in-memory backend (§31.1). L0 and L1 entries live beside the code they test
//! (the decision table, the lifecycle relation, the fingerprint, the schema, admission arithmetic)
//! and are listed in `docs/VERIFICATION_STATUS.md`. L4 entries need a real VMM and are not here.

mod api;
mod auth;
mod conc;
mod edge;
mod exec;
mod obs;
mod op;
mod pers;
mod rec;
mod res;
mod snap;
mod state;
