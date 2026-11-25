//! Reads (contract §10.6). Served from committed state, subject to roles and tags (API-12), and
//! never recorded. A list can be followed with a cursor instead of being re-read (API-11).

use base64::{Engine, engine::general_purpose::STANDARD};

use super::Host;
use crate::{
    api::{
        ALLOWLIST_NETWORK, CallerParameters, Cursor, FEATURES, HostInfo, ListParams, MAX_OUTPUT_CHUNK_BYTES, OperationView, OutputChunk,
        OutputStream, PROTOCOL, Page, ReadResult, RunOutputParams, SandboxView, SnapshotView,
    },
    domain::{AuthorityContext, HostMode, LifecycleState, NetworkMode, OperationType, RunResult, SnapshotState},
    error::{AcfError, FailureClass, Result},
    ids::{OperationId, RunId, SandboxId},
    store::{JournalState, OpKey, OperationRecord},
};

/// Cut `items` (already filtered) into one page in ascending revision order. A page never ends
/// between two items that share a revision, so continuing from `next` can skip nothing.
///
/// Nor does it end below `floor`, the oldest cursor this kind of listing still accepts, so `next`
/// is always a cursor the host accepts and a full listing can be followed to its end (API-11: "the
/// caller lists again in full" must be possible). Without that rule, a sandbox that has not changed
/// since before a newer tombstone was forgotten makes every full listing longer than one page end
/// with a cursor that is already expired. Below the floor lie only records of a kind that has
/// tombstones and that have not changed for longer than `change_retention`: they are bounded by the
/// host's capacity (`envelope.max_sandboxes`, `envelope.max_snapshots`), so such a page stays small.
fn paginate<T>(mut items: Vec<(u64, T)>, limit: usize, floor: u64, lineage: &str, current_seq: u64) -> Page<T> {
    items.sort_by_key(|(rev, _)| *rev);
    let mut cut = items.len().min(limit);
    while cut > 0 && cut < items.len() && (items[cut].0 == items[cut - 1].0 || items[cut - 1].0 < floor) {
        cut += 1;
    }
    let more = cut < items.len();
    let next = if more { items[cut - 1].0 } else { current_seq };
    items.truncate(cut);
    Page { items: items.into_iter().map(|(_, v)| v).collect(), more, next: Cursor { lineage: lineage.to_owned(), sequence: next } }
}

impl Host {
    /// API-11: the revision a list must report changes after. `None` means "a full listing".
    /// A cursor from another lineage, from before `floor`, or from a future this store has not
    /// seen is refused with `CURSOR_EXPIRED`: the caller lists again in full.
    fn changed_since(&self, state: &JournalState, p: &ListParams, floor: u64) -> Result<Option<u64>> {
        let Some(c) = &p.changed_since else { return Ok(None) };
        let expired = |why: &str| AcfError::new(FailureClass::CursorExpired, format!("{why}; list again without a cursor"));
        if c.lineage != self.journal.lineage() {
            return Err(expired("the cursor belongs to a different store lineage"));
        }
        if c.sequence < floor {
            return Err(expired("the cursor is older than the change retention window"));
        }
        if c.sequence > state.last_seq {
            return Err(expired("the cursor is ahead of this store"));
        }
        Ok(Some(c.sequence))
    }

    /// The oldest cursor a listing of sandboxes or snapshots accepts: a follower from before it may
    /// have missed a tombstone that retention has since forgotten (PS-10).
    fn tombstone_floor(state: &JournalState) -> u64 {
        state.change_floor
    }

    /// Operations have no tombstones: an operation record ends by being forgotten after
    /// `operation_retention`, which no listing reports (PS-10). Forgetting a *sandbox's* tombstone
    /// takes nothing from a follower of operations, so it does not expire an operation cursor.
    const OPERATION_FLOOR: u64 = 0;

    pub fn host_info(&self) -> Result<HostInfo> {
        let (live, snaps, quarantined) = self.journal.read(|s| {
            (
                s.live_generations().count(),
                s.snapshots.values().filter(|x| x.holds_storage()).count(),
                s.live_generations().filter(|g| g.quarantined.is_some()).count(),
            )
        })?;
        let profile = self.profile();
        let ops = &self.cfg.operations;
        let mode = self.mode();
        // VR-3 with §20.1: a feature is advertised only while this host offers it. Mode `allowlist`
        // needs the backend's support and the profile's listing, and a profile can be reloaded. What
        // the backend alone can do stays visible in `capabilities`.
        let allowlist = self.backend.capabilities().network_modes.contains(&NetworkMode::Allowlist)
            && profile.lists_network_mode(NetworkMode::Allowlist);
        Ok(HostInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            host_id: self.cfg.host_id.clone(),
            protocols: vec![PROTOCOL.to_owned()],
            features: FEATURES.iter().filter(|f| **f != ALLOWLIST_NETWORK || allowlist).map(|f| (*f).to_owned()).collect(),
            mode,
            containment_reasons: self.containment_reasons(),
            read_only_reason: self.journal.write_block().map(|b| b.message()),
            lineage: self.journal.lineage().to_owned(),
            activation_epoch: self.journal.epoch(),
            instance_id: self.instance_id.clone(),
            backend: self.backend.identity().clone(),
            capabilities: self.backend.capabilities().clone(),
            profile: profile.id().clone(),
            parameters: CallerParameters {
                acceptance_horizon_ms: ops.acceptance_horizon_ms,
                clock_skew_tolerance_ms: ops.clock_skew_tolerance_ms,
                operation_retention_ms: ops.operation_retention_ms,
                change_retention_ms: ops.change_retention_ms,
                output_retention_ms: ops.output_retention_ms,
                wait_max_ms: ops.wait_max_ms,
                max_request_bytes: self.cfg.edge.max_request_bytes as u64,
                ceilings: profile.limits().clone(),
                sandbox_lifetime_default_secs: profile.defaults().lifetime_secs,
                sandbox_lifetime_max_secs: profile.limits().max_lifetime_secs,
                allowlist_max_entries: profile.limits().max_allowlist_entries,
            },
            store_integrity: self.store_integrity.clone(),
            live_sandboxes: live,
            snapshots: snaps,
            quarantined,
            operations_in_flight: self.operations_in_flight(),
        })
    }

    /// `host.metrics`: activity counters, plus the measurements that show *standing risk* (§24.3) —
    /// what is wrong right now, not what happened.
    pub fn metrics(&self) -> serde_json::Value {
        let m = &self.telemetry.metrics;
        let now_ms = self.clock.wall_ms();
        let gauge = |name: &str, v: usize| m.set_gauge(name, i64::try_from(v).unwrap_or(i64::MAX));
        if let Ok(s) = self.journal.read(Clone::clone) {
            gauge("live_sandboxes", s.live_generations().count());
            gauge("snapshots", s.snapshots.values().filter(|x| x.holds_storage()).count());
            gauge("operations_open", s.open_operations.len());
            let oldest_open = s.open().map(|o| now_ms.saturating_sub(o.created_ms)).max().unwrap_or(0);
            m.set_gauge("oldest_open_operation_age_ms", oldest_open);
            let quarantined: Vec<_> = s.live_generations().filter(|g| g.quarantined.is_some()).collect();
            gauge("quarantined_generations", quarantined.len());
            let oldest_q = quarantined.iter().filter_map(|g| g.quarantined_ms).map(|t| now_ms.saturating_sub(t)).max().unwrap_or(0);
            m.set_gauge("oldest_quarantine_age_ms", oldest_q);
            gauge("failed_generations_holding_leases", s.live_generations().filter(|g| g.state == LifecycleState::Failed).count());
            gauge("unmanaged_resources", s.quarantines.iter().filter(|q| q.unmanaged).count());
        }
        let since_sweep = self.sweep.lock().ok().and_then(|s| s.last_complete_ms).map(|t| now_ms.saturating_sub(t)).unwrap_or(-1);
        m.set_gauge("ms_since_last_complete_sweep", since_sweep);
        m.set_gauge("store_bytes", i64::try_from(self.journal.len_bytes()).unwrap_or(i64::MAX));
        m.set_gauge("store_reserve_bytes", i64::try_from(self.cfg.store.reserve_bytes).unwrap_or(i64::MAX));
        m.set_gauge("store_reserve_released", i64::from(self.journal.reserve_released()));
        m.set_gauge("operations_in_flight", i64::try_from(self.operations_in_flight()).unwrap_or(i64::MAX));
        m.set_gauge(
            "host_mode",
            match self.mode() {
                HostMode::Starting => 0,
                HostMode::Serving => 1,
                HostMode::Draining => 2,
                HostMode::Containment => 3,
                HostMode::ReadOnly => 4,
            },
        );
        m.snapshot()
    }

    /// By id or by alias. Aliases resolve only here, for reads (ID-5). A name is unique within its
    /// tags, so it is looked up in the requester's own tags first. An operator reads any record
    /// (§9.2) and may therefore also name a sandbox of other tags, as long as the name is unambiguous
    /// among the records it may read; otherwise it uses the id. This is the rule for operation ids too.
    pub fn sandbox_inspect(&self, authority: &AuthorityContext, selector: &str) -> Result<SandboxView> {
        let absent = || AcfError::not_found("no such sandbox");
        self.journal.read(|s| {
            let sb = match (SandboxId::parse(selector), s.sandbox_by_name(&authority.tags(), selector)) {
                (Ok(id), _) => s.sandboxes.get(&id),
                (Err(_), Some(own)) => Some(own),
                (Err(_), None) => {
                    let mut others = s.sandboxes_named(selector).filter(|sb| authority.may_access(&sb.tags));
                    match (others.next(), others.next()) {
                        (Some(_), Some(_)) => return Err(AcfError::validation("that name exists in several scopes; use the sandbox id")),
                        (one, _) => one,
                    }
                }
            }
            .filter(|sb| authority.may_access(&sb.tags))
            .ok_or_else(absent)?;
            let g =
                s.generations.get(&(sb.sandbox_id.clone(), sb.current)).ok_or_else(|| AcfError::internal("generation record missing"))?;
            Ok(self.sandbox_view_in(sb, g))
        })?
    }

    pub fn sandbox_list(&self, authority: &AuthorityContext, p: &ListParams) -> Result<Page<SandboxView>> {
        self.journal.read(|s| {
            let floor = Self::tombstone_floor(s);
            let since = self.changed_since(s, p, floor)?;
            let items = s
                .sandboxes
                .values()
                .filter(|sb| authority.may_access(&sb.tags))
                .filter_map(|sb| s.generations.get(&(sb.sandbox_id.clone(), sb.current)).map(|g| self.sandbox_view_in(sb, g)))
                // A full listing shows what exists; a delta also shows what stopped existing.
                .filter(|v| match since {
                    Some(seq) => v.revision > seq,
                    None => v.state != LifecycleState::Destroyed,
                })
                .map(|v| (v.revision, v))
                .collect();
            Ok(paginate(items, p.page_size()?, floor, self.journal.lineage(), s.last_seq))
        })?
    }

    pub fn snapshot_list(&self, authority: &AuthorityContext, p: &ListParams) -> Result<Page<SnapshotView>> {
        let page = self.journal.read(|s| {
            let floor = Self::tombstone_floor(s);
            let since = self.changed_since(s, p, floor)?;
            let items = s
                .snapshots
                .values()
                .filter(|x| authority.may_access(&x.tags))
                .filter(|x| match since {
                    Some(seq) => x.revision > seq,
                    None => x.state != SnapshotState::Deleted,
                })
                .map(|x| (x.revision, x.clone()))
                .collect();
            Ok::<_, AcfError>(paginate(items, p.page_size()?, floor, self.journal.lineage(), s.last_seq))
        })??;
        // Compatibility is checked outside the store lock: it reads manifests from disk (§21.6, VR-7).
        Ok(Page {
            items: page.items.iter().map(|x| self.snapshot_view(x, self.snapshot_incompatibility(x))).collect(),
            more: page.more,
            next: page.next,
        })
    }

    /// The operation `id` names for this caller: its own namespace first; an operator may also name
    /// an operation of another scope when the id is unambiguous.
    pub(crate) fn resolve_operation(&self, authority: &AuthorityContext, id: &OperationId) -> Result<OperationRecord> {
        let own = OpKey::new(&authority.tags(), id);
        self.journal.read(|s| {
            if let Some(o) = s.operations.get(&own) {
                return Ok(o.clone());
            }
            let mut others = s.operations.values().filter(|o| o.operation_id == *id && authority.may_access(&o.tags));
            match (others.next(), others.next()) {
                (Some(o), None) => Ok(o.clone()),
                (Some(_), Some(_)) => Err(AcfError::validation("that operation id exists in several scopes; ask from the owning scope")),
                _ => Err(AcfError::not_found(format!("operation {id} does not exist"))),
            }
        })?
    }

    /// Resolve an operation by id — how a caller recovers from a lost response (API-8, FS-5).
    pub fn operation_get(&self, authority: &AuthorityContext, id: &OperationId) -> Result<OperationView> {
        let rec = self.resolve_operation(authority, id)?;
        self.journal.read(|s| self.operation_view(s, &rec))
    }

    pub fn operation_list(&self, authority: &AuthorityContext, p: &ListParams) -> Result<Page<OperationView>> {
        self.journal.read(|s| {
            let since = self.changed_since(s, p, Self::OPERATION_FLOOR)?.unwrap_or(0);
            let items = s
                .operations
                .values()
                .filter(|o| authority.may_access(&o.tags) && o.revision > since)
                .map(|o| (o.revision, self.operation_view(s, o)))
                .collect();
            Ok(paginate(items, p.page_size()?, Self::OPERATION_FLOOR, self.journal.lineage(), s.last_seq))
        })?
    }

    fn run_operation(&self, authority: &AuthorityContext, run_id: &RunId) -> Result<OperationRecord> {
        self.journal
            .read(|s| {
                s.operations
                    .values()
                    .find(|o| {
                        o.operation_type == OperationType::ExecRun && o.run_id.as_ref() == Some(run_id) && authority.may_access(&o.tags)
                    })
                    .cloned()
            })?
            .ok_or_else(|| AcfError::not_found(format!("run {run_id} does not exist")))
    }

    fn stored_run(rec: &OperationRecord) -> Option<RunResult> {
        rec.result.as_ref().and_then(|v| serde_json::from_value::<RunResult>(v.clone()).ok())
    }

    /// An execution's full result (output re-attached), or its operation while it is in flight.
    pub fn run_inspect(&self, authority: &AuthorityContext, run_id: &RunId) -> Result<ReadResult> {
        let rec = self.run_operation(authority, run_id)?;
        match Self::stored_run(&rec) {
            Some(mut r) if rec.is_terminal() => {
                self.hydrate_run(&mut r);
                Ok(ReadResult::Run(Box::new(r)))
            }
            _ => Ok(ReadResult::Operation(Box::new(self.journal.read(|s| self.operation_view(s, &rec))?))),
        }
    }

    /// One slice of one stream of an execution's stored output (OU-4). Without the
    /// `incremental_output` feature, output is available when the execution has ended (OU-5).
    pub fn run_output(&self, authority: &AuthorityContext, p: &RunOutputParams) -> Result<OutputChunk> {
        let rec = self.run_operation(authority, &p.run_id)?;
        if !rec.is_terminal() {
            return Err(AcfError::unsupported("the execution has not ended, and this host does not offer `incremental_output`"));
        }
        let run = Self::stored_run(&rec).ok_or_else(|| AcfError::not_found("the execution produced no result"))?;
        let cap = match p.stream {
            OutputStream::Stdout => &run.stdout,
            OutputStream::Stderr => &run.stderr,
        };
        let bytes = if cap.kept_bytes == 0 {
            Vec::new()
        } else if !cap.data_b64.is_empty() {
            STANDARD.decode(&cap.data_b64).map_err(|_| AcfError::internal("stored output is not valid base64"))?
        } else {
            let artifact =
                cap.artifact.as_ref().ok_or_else(|| AcfError::not_found("the output of this execution is no longer retained"))?;
            self.artifacts
                .get(&artifact.artifact_id, cap.kept_bytes + 16)
                .map(|(_, b)| b)
                .map_err(|_| AcfError::not_found("the output of this execution is no longer retained"))?
        };
        let len = bytes.len() as u64;
        if p.offset > len {
            return Err(AcfError::validation(format!("offset {} is beyond the {len} bytes stored for this stream", p.offset)));
        }
        let want = p.max_bytes.unwrap_or(MAX_OUTPUT_CHUNK_BYTES).min(MAX_OUTPUT_CHUNK_BYTES);
        let end = p.offset.saturating_add(want).min(len);
        Ok(OutputChunk {
            run_id: p.run_id.clone(),
            stream: p.stream,
            offset: p.offset,
            data_b64: STANDARD.encode(&bytes[p.offset as usize..end as usize]),
            stored_bytes: cap.kept_bytes,
            produced_bytes: cap.total_bytes,
            completeness: cap.status,
            eof: end == len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_never_splits_items_that_share_a_revision() {
        let items: Vec<(u64, u32)> = vec![(5, 1), (7, 2), (7, 3), (7, 4), (9, 5)];
        let page = paginate(items.clone(), 2, 0, "lin", 40);
        assert_eq!(page.items, vec![1, 2, 3, 4], "the three items of revision 7 stay together");
        assert!(page.more);
        assert_eq!(page.next, Cursor { lineage: "lin".into(), sequence: 7 });
        let rest: Vec<(u64, u32)> = items.into_iter().filter(|(rev, _)| *rev > 7).collect();
        let last = paginate(rest, 2, 0, "lin", 40);
        assert_eq!((last.items, last.more, last.next.sequence), (vec![5], false, 40), "the last page ends at the current sequence");
    }

    #[test]
    fn an_empty_listing_is_complete_up_to_the_current_sequence() {
        let page = paginate(Vec::<(u64, u32)>::new(), 10, 0, "lin", 12);
        assert!(page.items.is_empty() && !page.more);
        assert_eq!(page.next.sequence, 12);
    }

    #[test]
    fn pages_are_in_ascending_revision_order_whatever_order_the_store_yields() {
        let page = paginate(vec![(9, 'c'), (2, 'a'), (4, 'b')], 10, 0, "lin", 9);
        assert_eq!(page.items, vec!['a', 'b', 'c']);
    }

    /// API-11: whatever retention has forgotten, the `next` of a page is a cursor the host accepts.
    #[test]
    fn a_page_never_ends_below_the_change_floor() {
        let items: Vec<(u64, u32)> = vec![(3, 1), (4, 2), (8, 3), (12, 4), (15, 5)];
        let page = paginate(items.clone(), 1, 10, "lin", 20);
        assert_eq!(page.items, vec![1, 2, 3, 4], "extended past the floor, to the first item at or above it");
        assert!(page.more && page.next.sequence >= 10);
        let all_below = paginate(items[..3].to_vec(), 1, 10, "lin", 20);
        assert_eq!((all_below.items.len(), all_below.more, all_below.next.sequence), (3, false, 20));
        let above = paginate(items[3..].to_vec(), 1, 10, "lin", 20);
        assert_eq!((above.items, above.more, above.next.sequence), (vec![4], true, 12), "above the floor, the limit holds");
    }
}
