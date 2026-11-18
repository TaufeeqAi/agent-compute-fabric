//! T-RES and T-HOST: resources, identifiers, lifetime and host modes (§12.6, §19). T-RES-01 (the
//! admission arithmetic, L1) is in `resources/admission.rs`; the lifetime enforcer's own kill path
//! (L1, a real child process) is in `resources/lifetime.rs`. T-RES-02, T-RES-05 and T-HOST-01 need
//! a real kernel and VMM (L4).

use serde_json::json;

use crate::{
    domain::{ContainmentReason, HostMode, Issuer, LifecycleState, OperationState, OperationType},
    error::FailureClass,
    ids::SandboxRef,
    testing::rig::{Rig, alice, create_params, eventually, exec_params, footprint, ops, sandbox_of, snapshot_of, target},
};

fn jail(sb: &crate::api::SandboxView) -> String {
    SandboxRef { sandbox_id: sb.sandbox_id.clone(), generation: sb.generation }.jail_id()
}

/// T-RES-03: a `FAILED` or quarantined generation keeps its lease; the lease is released exactly
/// at `DESTROYED` (LS-1).
#[tokio::test]
async fn t_res_03_a_failed_or_quarantined_generation_keeps_its_lease_until_destroyed() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let mut all = Vec::new();
    for _ in 0..4 {
        all.push(a.ready(None).await);
    }
    // One runtime dies; one generation cannot be proven ours.
    rig.world.set_phase(&jail(&all[0]), crate::backend::VmmState::Absent);
    host.sweep_once().await;
    rig.forge_marker(&all[1]);
    assert_eq!(a.op("sandbox.destroy", target(&all[1])).await.state, OperationState::Failed);
    assert_eq!(a.inspect(&all[0].sandbox_id).await.state, LifecycleState::Failed);
    assert!(a.inspect(&all[1].sandbox_id).await.quarantined.is_some());

    // Both still count: a leaked runtime can never hide behind a free slot.
    assert_eq!(footprint(&host).1, 4);
    let refused = a.refused("sandbox.create", create_params(None)).await;
    assert_eq!(refused.class, FailureClass::ResourceExhausted);
    let slots = |host: &crate::coordinator::Host| -> Vec<u32> {
        host.journal.read(|s| s.live_generations().map(|g| g.reservation.uid_slot).collect()).unwrap()
    };
    assert_eq!(slots(&host).len(), 4);

    // Destroying the FAILED one releases exactly its lease and its identifier.
    let freed = host
        .journal
        .read(|s| s.generations.get(&(all[0].sandbox_id.clone(), all[0].generation)).map(|g| g.reservation.uid_slot))
        .unwrap()
        .unwrap();
    a.done("sandbox.destroy", target(&a.inspect(&all[0].sandbox_id).await)).await;
    assert_eq!(footprint(&host).1, 3);
    assert!(!slots(&host).contains(&freed));
    let fresh = a.create(None).await;
    assert_eq!(
        host.journal.read(|s| s.generations.get(&(fresh.sandbox_id.clone(), fresh.generation)).map(|g| g.reservation.uid_slot)).unwrap(),
        Some(freed),
        "the lowest free identifier is the one just released"
    );
    // The quarantined one still holds its lease, and still blocks a fifth sandbox.
    assert_eq!(a.refused("sandbox.create", create_params(None)).await.class, FailureClass::ResourceExhausted);
}

/// T-RES-04: no identifier is assigned while a live resource carries it, whatever the store says
/// (RS-3) — including after the store lost the record that leased it.
#[tokio::test]
async fn t_res_04_an_identifier_carried_by_a_live_resource_is_never_assigned() {
    let rig = Rig::new();
    rig.world.set_identifier_slots(4);
    let host = rig.serving().await;
    let a = alice(&host);
    let slot = |host: &crate::coordinator::Host, sb: &crate::api::SandboxView| {
        host.journal.read(|s| s.generations.get(&(sb.sandbox_id.clone(), sb.generation)).map(|g| g.reservation.uid_slot)).unwrap().unwrap()
    };

    // Processes of unknown origin run under the identifiers of slots 0 and 1.
    rig.world.set_busy_slots(&[0, 1]);
    let first = a.create(None).await;
    let second = a.create(None).await;
    assert_eq!((slot(&host, &first), slot(&host, &second)), (2, 3), "records show 0 and 1 free; observation shows them carried");
    // Every identifier is now leased or carried: there is none to give.
    let refused = a.refused("sandbox.create", create_params(None)).await;
    assert_eq!(refused.class, FailureClass::ResourceExhausted);
    assert!(refused.message.contains("identifier"), "{}", refused.message);
    assert_eq!(footprint(&host).1, 2);
    // Once the foreign processes are gone, the identifiers are usable.
    rig.world.set_busy_slots(&[]);
    assert_eq!(slot(&host, &a.create(None).await), 0);
}

/// LT-1 – LT-3 and the L2 part of T-HOST-01: every sandbox has an expiry within the profile's
/// ceiling; the lifetime enforcer is armed before the runtime is configured and disarmed when it is
/// proven gone; at expiry the host destroys the sandbox by its own operation; a restore in place
/// keeps the expiry; a reboot can only shorten what remains.
#[tokio::test]
async fn t_host_01_every_sandbox_has_an_expiry_and_the_host_destroys_it_then() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let short = sandbox_of(&a.done("sandbox.create", json!({"image": "python", "lifetime_secs": 60, "resources": {"vcpus": 1, "memory_mib": 256, "disk_mib": 128, "network": {"mode": "none"}}})).await);
    let default = a.create(None).await;
    let expiry_ms = |host: &crate::coordinator::Host, sb: &crate::api::SandboxView| {
        host.journal.read(|s| s.sandboxes.get(&sb.sandbox_id).map(|x| x.expiry.clone())).unwrap().unwrap()
    };
    assert_eq!(expiry_ms(&host, &short).lifetime_ms, 60_000);
    assert_eq!(expiry_ms(&host, &default).lifetime_ms, 3_600_000, "the profile's default");
    assert!(short.expires_at < default.expires_at);

    // PD-4: enforcement is armed the moment a runtime exists, with the sandbox's own expiry.
    assert!(rig.lifetime.tickets.lock().unwrap().is_empty(), "no runtime, no ticket");
    let short = sandbox_of(&a.done("sandbox.start", target(&short)).await);
    let ticket = rig.lifetime.tickets.lock().unwrap().get(&jail(&short)).cloned().expect("armed at launch");
    let tolerance_ns = host.cfg.lifetime.expiry_tolerance_ms * 1_000_000;
    assert_eq!(
        ticket.expires_mono_ns,
        expiry_ms(&host, &short).mono_ns + tolerance_ns / 2,
        "the enforcer acts after the host has had its chance, and within the tolerance"
    );
    assert_eq!(ticket.boot_id, host.clock.boot_id());

    // A restore in place keeps the sandbox's expiry (LT-1) and re-arms for the new runtime.
    let snap = snapshot_of(&a.done("snapshot.create", target(&short)).await);
    let restored = sandbox_of(&a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "existing", "sandbox_id": short.sandbox_id, "expected_generation": short.generation}})).await);
    assert_eq!(restored.expires_at, short.expires_at);
    let tickets: Vec<String> = rig.lifetime.tickets.lock().unwrap().keys().cloned().collect();
    assert_eq!(tickets, vec![jail(&restored)], "the old runtime is gone and disarmed; the new one is armed");
    // A restore as new is a new sandbox with its own expiry, never beyond the ceiling.
    let copy =
        sandbox_of(&a.done("snapshot.restore", json!({"snapshot": snap.snapshot, "target": {"kind": "new", "lifetime_secs": 7200}})).await);
    assert_eq!(expiry_ms(&host, &copy).lifetime_ms, 7_200_000);
    let too_long = json!({"snapshot": snap.snapshot, "target": {"kind": "new", "lifetime_secs": 7201}});
    assert_eq!(a.refused("snapshot.restore", too_long).await.class, FailureClass::SafetyControlDenied);

    // Before the expiry nothing happens; at the expiry the host issues `sandbox.destroy` (LT-3).
    rig.clock.advance_ms(59_000);
    host.sweep_once().await;
    assert_eq!(a.inspect(&short.sandbox_id).await.state, LifecycleState::Ready);
    rig.clock.advance_ms(1_000);
    let report = host.sweep_once().await;
    assert_eq!(report.contained, 1, "{report:?}");
    assert_eq!(a.inspect(&short.sandbox_id).await.state, LifecycleState::Destroyed);
    let by_host: Vec<_> = a.operations(json!({})).await.items.into_iter().filter(|o| o.issuer == Issuer::Host).collect();
    assert_eq!(by_host.len(), 1);
    assert_eq!((by_host[0].operation_type, by_host[0].state), (OperationType::SandboxDestroy, OperationState::Succeeded));
    assert!(!rig.lifetime.tickets.lock().unwrap().contains_key(&jail(&restored)), "disarmed once the runtime is proven gone");
    assert_eq!(a.inspect(&copy.sandbox_id).await.state, LifecycleState::Ready, "the copy has its own, later expiry");

    // LT-2: across a reboot the remainder comes from the wall clock and can only shrink.
    let left_before = crate::resources::lifetime::remaining_ms(host.clock.as_ref(), &expiry_ms(&host, &default));
    drop(a);
    drop(host);
    rig.clock.reboot_after(600_000); // the machine was down for ten minutes
    for vm in rig.world.jail_ids() {
        rig.world.set_phase(&vm, crate::backend::VmmState::Absent); // RC-8: after a reboot no runtime is present
    }
    let host = rig.serving().await;
    let left_after = crate::resources::lifetime::remaining_ms(host.clock.as_ref(), &expiry_ms(&host, &default));
    assert_eq!(left_after, left_before - 600_000, "downtime counts against the lifetime");
    assert_eq!(expiry_ms(&host, &default).boot_id, host.clock.boot_id(), "the expiry is re-expressed in the current boot");
    // Expiry also ends a sandbox that never ran, and one that is FAILED: the lease does not outlive it (LS-3).
    rig.clock.advance_ms(left_after + 3_600_000 * 2);
    host.sweep_once().await;
    assert_eq!(footprint(&host).1, 0, "nothing is leased past its expiry");
}

/// PD-4: when the lifetime enforcer is not running, a runtime launched now could outlive its
/// expiry. The host stops creating privilege until the enforcer reports again.
#[tokio::test]
async fn t_host_01_without_a_lifetime_enforcer_the_host_creates_no_privilege() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let sb = a.ready(None).await;
    rig.lifetime.down.store(true, std::sync::atomic::Ordering::SeqCst);
    host.sweep_once().await;
    assert_eq!(host.mode(), HostMode::Containment);
    assert!(host.containment_reasons().iter().any(|r| matches!(r, ContainmentReason::LifetimeEnforcerUnavailable(_))));
    assert_eq!(a.refused("sandbox.create", create_params(None)).await.class, FailureClass::HostNotServing);
    assert_eq!(a.refused("exec.run", exec_params(&sb, &["/bin/true"])).await.class, FailureClass::HostNotServing);
    a.done("sandbox.stop", target(&sb)).await; // containment is served
    // The enforcer is back: the reason is withdrawn and the host serves.
    rig.lifetime.down.store(false, std::sync::atomic::Ordering::SeqCst);
    host.sweep_once().await;
    assert_eq!(host.mode(), HostMode::Serving);
    a.create(None).await;
}

/// T-HOST-02: draining refuses granting operations, lets operations in flight end, and serves
/// containment (HM-3).
#[tokio::test]
async fn t_host_02_draining() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let (a, operator) = (alice(&host), ops(&host));
    let busy = a.ready(None).await;
    let idle = a.ready(None).await;
    rig.world.hold("exec");
    let in_flight = {
        let (a, sb) = (a.clone(), busy.clone());
        tokio::spawn(async move { a.exec(&sb, &["/bin/work"]).await })
    };
    eventually("the command reaches the guest", || rig.world.waiting("exec") == 1).await;

    // A caller cannot drain the host; an operator can, and it is a recorded operation.
    assert_eq!(a.refused("host.set_mode", json!({"mode": "DRAINING"})).await.class, FailureClass::AuthorizationDenied);
    let drain = operator.done("host.set_mode", json!({"mode": "DRAINING"})).await;
    assert_eq!(drain.operation_type, OperationType::HostSetMode);
    assert_eq!(a.info().await.mode, HostMode::Draining);
    assert_eq!(a.info().await.operations_in_flight, 1);

    // No new privilege...
    for (method, params) in
        [("sandbox.create", create_params(None)), ("exec.run", exec_params(&idle, &["/bin/true"])), ("snapshot.create", target(&idle))]
    {
        let r = a.refused(method, params).await;
        assert_eq!(r.class, FailureClass::HostNotServing, "{method}");
    }
    // ...containment and reads are served...
    a.done("sandbox.destroy", target(&idle)).await;
    assert_eq!(a.sandboxes(json!({})).await.items.len(), 1);
    // ...and what is in flight ends by itself: draining waits for it, it does not cut it.
    let waiting = {
        let host = std::sync::Arc::clone(&host);
        tokio::spawn(async move { host.drain().await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!waiting.is_finished(), "the drain waits for the execution");
    rig.world.release("exec");
    assert_eq!(in_flight.await.unwrap().state, OperationState::Succeeded);
    assert_eq!(waiting.await.unwrap(), 0, "nothing was left in flight");
}

/// T-HOST-03: a mandatory startup check fails while generations exist → `CONTAINMENT`: the host
/// does not exit, destroy works, create is refused (HM-2).
#[tokio::test]
async fn t_host_03_a_failed_mandatory_check_with_generations_present() {
    let rig = Rig::new();
    let host = rig.serving().await;
    let a = alice(&host);
    let running = a.ready(None).await;
    let other = a.ready(None).await;
    drop(a);
    drop(host);

    // The next start finds the machine no longer able to honour the isolation profile.
    let host = rig.boot_with(vec![ContainmentReason::MandatoryCheck(
        "cgroup_parent: /sys/fs/cgroup/acf does not delegate [\"pids\"] to children".into(),
    )]);
    let report = host.recover().await.unwrap();
    host.finish_starting();
    assert_eq!(host.mode(), HostMode::Containment, "the host runs");
    assert_eq!(report.adopted, 2, "what was running is still accounted for");
    let (a, operator) = (alice(&host), ops(&host));
    let info = operator.info().await;
    assert!(format!("{:?}", info.containment_reasons).contains("cgroup_parent"), "and says why: {:?}", info.containment_reasons);
    assert_eq!(info.live_sandboxes, 2);

    // It creates no privilege...
    for (method, params) in [
        ("sandbox.create", create_params(None)),
        ("exec.run", exec_params(&running, &["/bin/true"])),
        ("snapshot.create", target(&running)),
    ] {
        assert_eq!(a.refused(method, params).await.class, FailureClass::HostNotServing, "{method}");
    }
    // ...and it can still remove it: the reason a host in this state must not exit.
    a.done("sandbox.stop", target(&running)).await;
    a.done("sandbox.destroy", target(&running)).await;
    a.done("sandbox.destroy", target(&other)).await;
    assert_eq!((footprint(&host).1, rig.world.vm_count()), (0, 0));
    assert_eq!(operator.metrics().await["gauges"]["host_mode"], json!(3));
}
