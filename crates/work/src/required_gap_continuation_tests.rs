//! Required continuation tests use only genuine owned admission and physical closure.
use super::{durable_rows, executable, ScopeHarness};
use crate::run_journal::{RootOutcome, RunStage};
use crate::supervisor::{Boundary, CancelToken};

#[test]
fn live_required_off_repeats_after_actor_commit_with_distinct_pending_events() {
    let h = ScopeHarness::new(true);
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let allocation_bytes: String = store
        .conn
        .query_row("SELECT record FROM allocations", [], |r| r.get(0))
        .unwrap();
    let identity = h.allocation.identity.as_ref().unwrap();
    let marker = identity.private_git_dir.join("work-lease.json");
    let marker_bytes = std::fs::read(&marker).unwrap();
    let mut previous_head = identity.head.clone();
    let mut retained_gaps: Vec<(String, String, Vec<u8>)> = Vec::new();
    let mut events = std::collections::BTreeSet::new();
    let mut cancelled = None;

    // One chain, not four independent allocations. R3 is cancelled while the
    // owned launcher is still blocked; R4 must subsequently execute.
    for (index, expected) in [
        RootOutcome::Completed,
        RootOutcome::Failed,
        RootOutcome::Cancelled,
        RootOutcome::Completed,
    ]
    .into_iter()
    .enumerate()
    {
        let mut command = h.command.clone();
        if index != 0 {
            command.run_id = uuid::Uuid::now_v7();
            // Each owned child writes fresh manager properties for its own unit.
            std::fs::remove_file(h.temp.path().join("properties")).unwrap();
            std::fs::remove_file(h.temp.path().join("executed")).ok();
        }
        executable(
            &h.temp.path().join("delegate"),
            format!(
                "#!/bin/sh\nset -eu\n/usr/bin/git -c core.hooksPath=/dev/null commit --allow-empty -m required-gap-{index}\nprintf executed > '{}/executed'\nexit {}\n",
                h.temp.path().display(),
                if expected == RootOutcome::Failed { 7 } else { 0 },
            ),
        );
        let cancel = CancelToken::default();
        let mut permit_attempted = false;
        let result = crate::supervisor::supervise_off(
            &h.config,
            command.clone(),
            &h.driver,
            Some(h.io()),
            &cancel,
            |boundary, root| {
                if boundary == Boundary::Bound && expected == RootOutcome::Cancelled {
                    cancel.request();
                }
                if boundary == Boundary::PermitAttempt {
                    permit_attempted = true;
                }
                if boundary == Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        );
        // Before this deciding R2 assertion there are no new schema/type reads.
        let report = if index == 0 {
            result.expect("first required Off must execute and physically close")
        } else {
            result.expect("new required Off after owned live close must execute")
        };
        assert!(!report.existing);
        assert!(report.record.closed && report.lease_charged && report.task_open);
        assert!(!report.checkout_ready);
        assert_eq!(report.record.outcome, Some(expected));
        let head = crate::identity::CheckoutIdentity::inspect(&h.allocation.destination)
            .unwrap()
            .head;
        if expected == RootOutcome::Cancelled {
            assert!(!permit_attempted);
            assert_eq!(report.record.stage, RunStage::Bound);
            assert!(!h.temp.path().join("executed").exists());
            assert_eq!(head, previous_head);
            cancelled = Some(report.record.clone());
        } else {
            assert!(permit_attempted);
            assert!(h.temp.path().join("executed").exists());
            assert_ne!(head, previous_head, "only the released actor advances HEAD");
        }
        previous_head = head;
        let gap = report.gap.as_ref().unwrap();
        assert_eq!(gap.delivery, crate::attribution_gap::GapDelivery::Pending);
        assert!(gap.event_recorded && gap.transport_deferred);
        assert!(events.insert(gap.event_id.to_string()));
        let (state, ready): (String, bool) = store
            .conn
            .query_row("SELECT state,ready FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(state, "held");
        assert!(!ready);
        assert_eq!(
            store
                .charged(h.allocation.request.repository.as_ref().unwrap(), None)
                .unwrap(),
            1,
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT record FROM allocations", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            allocation_bytes,
        );
        assert_eq!(std::fs::read(&marker).unwrap(), marker_bytes);
        for (run, bytes, fingerprint) in &retained_gaps {
            let current: (String, Vec<u8>) = store
                .conn
                .query_row(
                    "SELECT record,fingerprint FROM attribution_gaps WHERE run=?1",
                    [run],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(&current.0, bytes);
            assert_eq!(&current.1, fingerprint);
        }
        let run = report.record.request.identity().run.to_string();
        let (bytes, fingerprint) = store
            .conn
            .query_row(
                "SELECT record,fingerprint FROM attribution_gaps WHERE run=?1",
                [&run],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .unwrap();
        retained_gaps.push((run, bytes, fingerprint));
        for table in [
            "writers",
            "capture_runs",
            "capture_finalizations",
            "capture_readiness",
            "task_finishes",
        ] {
            assert_eq!(
                store
                    .conn
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        let before = durable_rows(&store);
        let existing = crate::supervisor::supervise_off(
            &h.config,
            command,
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |_, _| panic!("same-ID acknowledgement must not enter runtime"),
        )
        .unwrap();
        assert!(existing.existing);
        assert_eq!(existing.record, report.record);
        assert_eq!(existing.gap, report.gap);
        assert_eq!(durable_rows(&store), before);
    }
    let cancelled = cancelled.unwrap();
    assert_eq!(
        store
            .run_snapshot(&cancelled.request.identity().run)
            .unwrap(),
        Some(cancelled.clone()),
        "R4 must not reinterpret R3's bound Cancelled outcome",
    );
    assert_eq!(events.len(), 4);
    let (successor, revision): (String, i64) = store
        .conn
        .query_row(
            "SELECT successor_run,successor_revision FROM gap_qualifications WHERE run=?1",
            [cancelled.request.identity().run.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(successor, retained_gaps[3].0, "R4 actually consumes Q3");
    let r4: serde_json::Value = serde_json::from_str(&retained_gaps[3].1).unwrap();
    assert_eq!(
        r4["context"]["continuation"]["predecessor"],
        cancelled.request.identity().run.to_string()
    );
    assert_eq!(
        r4["context"]["continuation"]["admission_revision"],
        revision
    );
    assert_eq!(
        revision, 10,
        "initial1 then three close/publication/admission transitions"
    );
}

#[test]
fn supported_holds_revoke_epochs_without_reversing_physical_closure() {
    let limits = crate::admission::Limits {
        repository: 10,
        owner: 10,
        available_bytes: None,
        floor_bytes: 0,
        warn_bytes: 0,
    };
    let cursor = |store: &crate::store::Store| {
        store
            .conn
            .query_row(
                "SELECT revision,disposition,qualification FROM gap_eligibility",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    let mut failures = Vec::new();
    for window in ["available", "awaiting", "admission", "prepermit"] {
        let (h, mut direct, prefix) = genuinely_published_initial();
        let before = durable_rows(&direct);
        direct
            .transfer(h.allocation.checkout, "alice", limits)
            .unwrap();
        assert_eq!(durable_rows(&direct), before, "same-owner no-op");
        assert!(direct
            .transfer(
                h.allocation.checkout,
                "bob",
                crate::admission::Limits { owner: 0, ..limits }
            )
            .is_err());
        assert_eq!(
            durable_rows(&direct),
            before,
            "capacity refusal has no epoch/event effect"
        );
        let retained: (String, Vec<u8>) = direct
            .conn
            .query_row(
                "SELECT record,fingerprint FROM gap_qualifications",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let facts = std::rc::Rc::new(std::cell::RefCell::new(None));
        let record_change = |store: &mut crate::store::Store| {
            let before = cursor(store).0;
            let events = store.pending_events(1000).unwrap().len();
            store
                .transfer(h.allocation.checkout, "bob", limits)
                .unwrap();
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT owner FROM checkouts", [], |r| r.get::<_, String>(0))
                    .unwrap(),
                "bob"
            );
            store
                .transfer(h.allocation.checkout, "alice", limits)
                .unwrap();
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT owner FROM checkouts", [], |r| r.get::<_, String>(0))
                    .unwrap(),
                "alice"
            );
            assert_eq!(
                store.pending_events(1000).unwrap().len(),
                events + 2,
                "two actual supported Changed commits"
            );
            *facts.borrow_mut() = Some((before, cursor(store)));
        };
        if window == "available" {
            record_change(&mut direct);
        }
        let observer = if window == "admission" {
            let mut contender = crate::store::Store::open_existing_registered_mut(
                h.config.trusted_registry.as_ref().unwrap(),
                h.config.store_dir.as_ref().unwrap(),
                &h.config.roots,
            )
            .unwrap();
            let checkout = h.allocation.checkout;
            let facts = facts.clone();
            Some(super::observing_admission(move |stage, _| {
                if stage == "reinspect" {
                    let before = cursor(&contender).0;
                    contender.transfer(checkout, "bob", limits).unwrap();
                    contender.transfer(checkout, "alice", limits).unwrap();
                    *facts.borrow_mut() = Some((before, cursor(&contender)));
                }
            }))
        } else {
            None
        };
        let mut command = h.command.clone();
        command.run_id = uuid::Uuid::now_v7();
        std::fs::remove_file(h.temp.path().join("properties")).unwrap();
        std::fs::remove_file(h.temp.path().join("executed")).unwrap();
        let result = crate::supervisor::supervise_off(
            &h.config,
            command,
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, root| {
                if boundary == Boundary::RootTerminal {
                    h.empty(root);
                }
                if (window == "awaiting" && boundary == Boundary::Closed)
                    || (window == "prepermit" && boundary == Boundary::PermitAttempt)
                {
                    record_change(&mut direct);
                }
            },
        );
        drop(observer);
        let (before_revision, after) = facts
            .borrow()
            .clone()
            .expect("actual owner-away/back boundary reached");
        if after != (before_revision + 2, "blocked".into(), None) {
            failures.push(format!(
                "{window}: two Changed transfers did not permanently revoke exact epoch"
            ));
        }
        if result.is_ok() {
            failures.push(format!(
                "{window}: restored owner incorrectly allowed publication/admission/release"
            ));
        }
        if window != "awaiting" && h.temp.path().join("executed").exists() {
            failures.push(format!("{window}: actor executed after revocation"));
        }
        let current: (String, Vec<u8>) = direct
            .conn
            .query_row(
                "SELECT record,fingerprint FROM gap_qualifications WHERE run=?1",
                [prefix.record.request.identity().run.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            current, retained,
            "revocation retains immutable predecessor Q"
        );
        assert_eq!(
            direct
                .charged(
                    h.allocation.request.repository.as_ref().unwrap(),
                    Some("alice")
                )
                .unwrap(),
            1
        );
    }
    for window in ["before-close", "between-publication", "after-publication"] {
        let (h, store, prefix) = genuinely_published_initial();
        let retained: (String, Vec<u8>) = store
            .conn
            .query_row(
                "SELECT record,fingerprint FROM gap_qualifications",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let mut holder = Some(
            crate::store::Store::open_existing_registered_mut(
                h.config.trusted_registry.as_ref().unwrap(),
                h.config.store_dir.as_ref().unwrap(),
                &h.config.roots,
            )
            .unwrap(),
        );
        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = reached.clone();
        let checkout = h.allocation.checkout;
        let observer = if window != "before-close" {
            let mut holder = holder.take().unwrap();
            Some(crate::gap_continuation::observing_publication(
                move |stage| {
                    let boundary = if window == "between-publication" {
                        "before_second_physical"
                    } else {
                        "after_commit"
                    };
                    if stage == boundary {
                        let before = cursor(&holder).0;
                        holder.transfer(checkout, "bob", limits).unwrap();
                        holder.transfer(checkout, "alice", limits).unwrap();
                        assert_eq!(cursor(&holder), (before + 2, "blocked".into(), None));
                        observed.set(true);
                    }
                },
            ))
        } else {
            None
        };
        let mut command = h.command.clone();
        command.run_id = uuid::Uuid::now_v7();
        let run = work_contract::RunId::parse(&command.run_id.to_string()).unwrap();
        std::fs::remove_file(h.temp.path().join("properties")).unwrap();
        std::fs::remove_file(h.temp.path().join("executed")).unwrap();
        let result = crate::supervisor::supervise_off(
            &h.config,
            command,
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, root| {
                if boundary == Boundary::RootTerminal {
                    if window == "before-close" {
                        let holder = holder.as_mut().unwrap();
                        holder.transfer(checkout, "bob", limits).unwrap();
                        holder.transfer(checkout, "alice", limits).unwrap();
                        assert_eq!(cursor(holder), (6, "blocked".into(), None));
                        reached.set(true);
                    }
                    h.empty(root);
                }
            },
        );
        drop(observer);
        assert!(reached.get(), "actual Changed revoker boundary {window}");
        assert_eq!(
            result.is_err(),
            window == "between-publication",
            "ineligibility must not veto proven physical closure or reopen committed Q: {window}"
        );
        assert!(
            h.temp.path().join("executed").exists(),
            "a postpermit hold cannot withdraw an issued permit"
        );
        let root = store.run_snapshot(&run).unwrap().unwrap();
        assert!(root.closed && !root.recovery_hold);
        assert_eq!(root.outcome, Some(RootOutcome::Completed));
        assert_eq!(
            cursor(&store),
            (
                if window == "after-publication" { 8 } else { 7 },
                "blocked".into(),
                None
            )
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            if window == "after-publication" { 2 } else { 1 }
        );
        assert_eq!(
            store
                .conn
                .query_row(
                    "SELECT record,fingerprint FROM gap_qualifications WHERE run=?1",
                    [prefix.record.request.identity().run.to_string()],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                )
                .unwrap(),
            retained
        );
    }
    let (h, mut store, _) = genuinely_published_initial();
    assert_eq!(store.retire_owner("alice", Some("bob"), limits).unwrap(), 1);
    if cursor(&store) != (4, "blocked".into(), None) {
        failures.push("changed owner escalation did not revoke".into());
    }
    let before = durable_rows(&store);
    assert_eq!(store.retire_owner("alice", Some("bob"), limits).unwrap(), 0);
    assert_eq!(
        durable_rows(&store),
        before,
        "zero transferred rows have no cursor effect"
    );
    assert_eq!(
        store
            .charged(
                h.allocation.request.repository.as_ref().unwrap(),
                Some("bob")
            )
            .unwrap(),
        1
    );
    // Reuse existing owned race helper, not a second owner/journal matrix.
    for release_first in [false, true] {
        failures.extend(super::lease_tests::revoker_case(
            super::lease_tests::Revoker::Owner,
            release_first,
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn changed_safety_holds_and_recovery_close_block_initialized_cursor() {
    use crate::run_journal::Transition;
    let cursor = |store: &crate::store::Store| {
        store
            .conn
            .query_row(
                "SELECT revision,disposition,qualification FROM gap_eligibility",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    let mut failures = Vec::new();
    let (h, mut store, prefix) = genuinely_published_initial();
    let retained: (String, Vec<u8>) = store
        .conn
        .query_row(
            "SELECT record,fingerprint FROM gap_qualifications",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let mut command = h.command.clone();
    command.run_id = uuid::Uuid::now_v7();
    let run = work_contract::RunId::parse(&command.run_id.to_string()).unwrap();
    std::fs::remove_file(h.temp.path().join("properties")).unwrap();
    std::fs::remove_file(h.temp.path().join("executed")).unwrap();
    let mut changed = false;
    let result = crate::supervisor::supervise_off(
        &h.config,
        command,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::Bound {
                assert_eq!(
                    cursor(&store).0,
                    4,
                    "genuine successor has already consumed predecessor Q"
                );
                assert_eq!(
                    store.record_recovery_hold(&root.request).unwrap(),
                    Transition::Changed
                );
                changed = true;
                if cursor(&store) != (5, "blocked".into(), None) {
                    failures.push(
                        "Changed prepermit group hold failed to revoke epoch4 atomically".into(),
                    );
                }
                let before = durable_rows(&store);
                assert_eq!(
                    store.record_recovery_hold(&root.request).unwrap(),
                    Transition::Existing
                );
                assert_eq!(
                    durable_rows(&store),
                    before,
                    "Existing hold never increments epoch"
                );
            }
        },
    );
    assert!(
        changed && result.is_err() && !h.temp.path().join("executed").exists(),
        "old hold/release refusal is preservation, not the missing epoch behavior"
    );
    let root = store.run_snapshot(&run).unwrap().unwrap();
    assert!(root.outcome.is_none() && !root.closed && root.stage == RunStage::Bound);
    h.empty(&root);
    let recovered =
        crate::run_recovery::recover_with_config(&mut store, &run, &h.driver, &h.config);
    if !matches!(recovered, Ok(crate::run_recovery::RecoveryState::Closed)) {
        failures.push("genuine unknown successor physical recovery close did not complete".into());
    }
    if cursor(&store) != (6, "blocked".into(), None) {
        failures.push("recovery/ineligible close did not increment and stay blocked".into());
    }
    let root = store.run_snapshot(&run).unwrap().unwrap();
    if !root.closed || root.outcome.is_some() {
        failures.push("recovery must close physically without inventing outcome".into());
    }
    let claim: (String, i64) = store
        .conn
        .query_row(
            "SELECT successor_run,successor_revision FROM gap_qualifications",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(claim, (run.to_string(), 4));
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT record,fingerprint FROM gap_qualifications WHERE run=?1",
                [prefix.record.request.identity().run.to_string()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            )
            .unwrap(),
        retained
    );
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "recovery never mints Q"
    );

    // Independent safety invocations are not Existing/no-op transitions even
    // when visible held flags and the already-populated reason stay identical.
    let (h, mut store, _) = genuinely_published_initial();
    let mut allocation = h.allocation.clone();
    for revision in [4, 5] {
        let before = durable_rows(&store);
        crate::recovery::hold(
            &mut store,
            &mut allocation,
            "capture required; root preparation pending",
        )
        .unwrap();
        let after = durable_rows(&store);
        assert_eq!(
            &after[..after.len() - 1],
            &before[..before.len() - 1],
            "independent hold preserves all non-cursor bytes when visible state is identical"
        );
        if cursor(&store) != (revision, "blocked".into(), None) {
            failures.push(format!(
                "independent unchanged-visible safety hold failed epoch{revision}"
            ));
        }
    }
    assert_eq!(
        store
            .charged(h.allocation.request.repository.as_ref().unwrap(), None)
            .unwrap(),
        1
    );

    // A child may share the genuine live root's execution host (the existing
    // roster explicitly supports/deduplicates shared hosts). Enroll through the
    // real Driver proof, not a raw host/enrollment row. Only the registrar's
    // owned fake-proc view is added, as in the existing ScopeHarness tests.
    let (h, mut store, prefix) = genuinely_published_initial();
    let mut command = h.command.clone();
    command.run_id = uuid::Uuid::now_v7();
    std::fs::remove_file(h.temp.path().join("properties")).unwrap();
    std::fs::remove_file(h.temp.path().join("executed")).unwrap();
    let mut child_changed = false;
    let result = crate::supervisor::supervise_off(
        &h.config,
        command,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::PermitAttempt {
                let binding = root.binding.as_ref().unwrap();
                let registrar = std::process::id();
                let path = h.temp.path().join(format!("proc/{registrar}"));
                std::fs::create_dir(&path).unwrap();
                std::fs::write(
                    path.join("stat"),
                    std::fs::read(format!("/proc/{registrar}/stat")).unwrap(),
                )
                .unwrap();
                std::fs::write(path.join("cgroup"), format!("0::{}\n", binding.cgroup)).unwrap();
                let members = h
                    .temp
                    .path()
                    .join("cg")
                    .join(binding.cgroup.trim_start_matches('/'))
                    .join("cgroup.procs");
                std::fs::write(&members, format!("{}\n{registrar}\n", binding.root_pid)).unwrap();
                let child = super::declared_child(
                    &root.request,
                    Some(crate::run_participants::ExpectedHost {
                        pid: binding.root_pid,
                        start_ticks: binding.root_start_ticks,
                        boot: binding.boot.clone(),
                    }),
                );
                assert_eq!(
                    store.register_child(&root.request, &child).unwrap(),
                    crate::run_journal::BeginRun::Created
                );
                let proof = store
                    .group_snapshot(&root.request.identity().run)
                    .unwrap()
                    .certify_child_enrollment(&h.driver, &child.run, None)
                    .unwrap();
                assert_eq!(
                    store
                        .record_child_enrollment(&root.request, &child, &proof)
                        .unwrap(),
                    Transition::Changed
                );
                assert_eq!(
                    cursor(&store),
                    (4, "unavailable".into(), None),
                    "normal registration/enrollment never revoke"
                );
                assert_eq!(
                    store.record_child_hold(&root.request, &child).unwrap(),
                    Transition::Changed
                );
                child_changed = true;
                if cursor(&store) != (5, "blocked".into(), None) {
                    failures.push(
                        "Changed contained-child hold did not immediately revoke epoch4".into(),
                    );
                }
                let before = durable_rows(&store);
                assert_eq!(
                    store.record_child_hold(&root.request, &child).unwrap(),
                    Transition::Existing
                );
                assert_eq!(
                    durable_rows(&store),
                    before,
                    "already-unverified child hold is Existing, no epoch"
                );
                std::fs::remove_dir_all(path).unwrap();
                std::fs::write(members, format!("{}\n", binding.root_pid)).unwrap();
            }
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    );
    assert!(child_changed);
    if result.is_ok() || h.temp.path().join("executed").exists() {
        failures.push("child-hold revocation did not prevent prepermit release".into());
    }
    let claim: (String, i64) = store
        .conn
        .query_row(
            "SELECT successor_run,successor_revision FROM gap_qualifications WHERE run=?1",
            [prefix.record.request.identity().run.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(claim.1, 4);
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );

    // Supported bare reservation makes allocator matching genuinely ambiguous;
    // no successful Gap/Q is forged. The tracked checkout is already held, so
    // this independent multi-match safety action must still revoke its epoch.
    let (h, mut store, _) = genuinely_published_initial();
    store
        .reserve(
            &crate::admission::Reservation {
                operation: uuid::Uuid::now_v7(),
                repository: h
                    .allocation
                    .identity
                    .as_ref()
                    .unwrap()
                    .common_git_dir
                    .clone(),
                actor: "alice".into(),
                owner: "alice".into(),
                task: h.allocation.request.task.clone(),
            },
            crate::admission::Limits {
                repository: 10,
                owner: 10,
                available_bytes: Some(10),
                floor_bytes: 0,
                warn_bytes: 0,
            },
        )
        .unwrap();
    let original: String = store
        .conn
        .query_row(
            "SELECT record FROM allocations WHERE checkout=?1",
            [h.allocation.checkout.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    let q: (String, Vec<u8>) = store
        .conn
        .query_row(
            "SELECT record,fingerprint FROM gap_qualifications",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let mut retry = h.allocation.request.clone();
    retry.operation = uuid::Uuid::now_v7();
    let error = crate::allocate::start(&h.config, retry).unwrap_err();
    assert_eq!(
        error.to_string(),
        "ambiguous matching allocations; hold for reconciliation",
        "must reach the actual independent safety path, not the single-target legacy veto"
    );
    if cursor(&store) != (4, "blocked".into(), None) {
        failures.push(
            "ambiguous allocator safety hold did not revoke already-held tracked checkout".into(),
        );
    }
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT record FROM allocations WHERE checkout=?1",
                [h.allocation.checkout.to_string()],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        original
    );
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT record,fingerprint FROM gap_qualifications",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            )
            .unwrap(),
        q
    );
    assert_eq!(
        store
            .charged(h.allocation.request.repository.as_ref().unwrap(), None)
            .unwrap(),
        2
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "Deferred pilot performance/budget qualification; run explicitly with --ignored"]
fn required_history_fold_is_linear_within_existing_budgets() {
    // Staged preservation: real existing captured 2/48-root/188-child helper,
    // unchanged workload, limits and assertions. Only classification is measured.
    crate::capture_readiness::tests::many_closed_history_stress(
        |_, store, allocation, original| {
            let record = store
                .run_snapshot(&original.identity().run)
                .unwrap()
                .unwrap();
            crate::gap_continuation::take_decoded_nodes();
            let classification = crate::gap_continuation::before_close(
                &store.conn,
                &record,
                None,
                store.authority_identity(),
            )
            .unwrap();
            assert!(!classification.required());
            assert_eq!(
                crate::gap_continuation::take_decoded_nodes(),
                0,
                "non-Gap close classification must not decode the captured history again"
            );
            assert!(!super::super::raw_history(&store.conn, allocation.checkout).unwrap());
            let before = durable_rows(store);
            let lease = store.authority_lease().unwrap();
            {
                let _phase = store.sql_phase();
                let tx = rusqlite::Transaction::new_unchecked(
                    &store.conn,
                    rusqlite::TransactionBehavior::Immediate,
                )
                .unwrap();
                crate::gap_continuation::revoke(
                    &tx,
                    store.authority_identity(),
                    &lease,
                    allocation.checkout,
                )
                .unwrap();
            }
            drop(lease);
            assert_eq!(
                crate::gap_continuation::take_decoded_nodes(),
                0,
                "no-Gap context mutation must not add a captured history fold"
            );
            assert_eq!(durable_rows(store), before);
        },
    );
    use sha2::{Digest, Sha256};
    for count in [2usize, 48] {
        let h = ScopeHarness::new(true);
        let (store, lease) = crate::allocate::locked(&h.config).unwrap();
        drop(lease);
        // Independent reference: fixed domains/fields from the public source
        // contract, not a call to the production fold or a per-prefix rescan.
        let mut seed = Sha256::new();
        seed.update(b"work.required-gap.frontier.v1\0");
        seed.update(h.allocation.checkout.as_bytes());
        let mut allocation = Sha256::new();
        allocation.update(b"work.required-gap.allocation.v1\0");
        allocation.update(serde_json::to_vec(&h.allocation).unwrap());
        seed.update(allocation.finalize());
        let mut reference: [u8; 32] = seed.finalize().into();
        for index in 0..count {
            let mut command = h.command.clone();
            if index != 0 {
                command.run_id = uuid::Uuid::now_v7();
                std::fs::remove_file(h.temp.path().join("properties")).unwrap();
                std::fs::remove_file(h.temp.path().join("executed")).unwrap();
            }
            let report = crate::supervisor::supervise_off(
                &h.config,
                command,
                &h.driver,
                Some(h.io()),
                &CancelToken::default(),
                |boundary, root| {
                    if boundary == Boundary::RootTerminal {
                        h.empty(root);
                    }
                },
            )
            .expect("genuine required chain must fit unchanged budgets");
            let root = &report.record;
            assert!(
                root.closed
                    && root.children.is_empty()
                    && !root.recovery_hold
                    && !report.checkout_ready
                    && !report.existing
            );
            assert_eq!(root.outcome, Some(RootOutcome::Completed));
            assert_eq!(root.stage, RunStage::PermitAttempt);
            assert!(h.temp.path().join("executed").exists());
            let gap: String = store
                .conn
                .query_row(
                    "SELECT record FROM attribution_gaps WHERE run=?1",
                    [root.request.identity().run.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            let mut fold = Sha256::new();
            fold.update(b"work.required-gap.frontier-node.v1\0");
            fold.update(reference);
            fold.update(Sha256::digest(gap.as_bytes()));
            fold.update(
                uuid::Uuid::parse_str(&root.request.identity().run.to_string())
                    .unwrap()
                    .as_bytes(),
            );
            fold.update(
                uuid::Uuid::parse_str(&root.request.identity().group.to_string())
                    .unwrap()
                    .as_bytes(),
            );
            fold.update(Sha256::digest(serde_json::to_vec(&root.request).unwrap()));
            fold.update([2]);
            let mut binding = Sha256::new();
            binding.update(b"work.required-gap.binding.v1\0");
            binding.update(serde_json::to_vec(&root.binding).unwrap());
            fold.update(binding.finalize());
            fold.update([1, 1, 0]);
            fold.update(root.revision.to_be_bytes());
            fold.update(Sha256::digest(b"work.required-gap.roster.v1\0"));
            reference = fold.finalize().into();
            let q: String = store
                .conn
                .query_row(
                    "SELECT record FROM gap_qualifications WHERE run=?1",
                    [root.request.identity().run.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            let q: serde_json::Value = serde_json::from_str(&q).unwrap();
            assert_eq!(
                serde_json::from_value::<[u8; 32]>(q["frontier"].clone()).unwrap(),
                reference
            );
            assert_eq!(q["publication_revision"], 3 * (index + 1));
            assert_eq!(
                store
                    .charged(h.allocation.request.repository.as_ref().unwrap(), None)
                    .unwrap(),
                1
            );
        }
        let measure = || {
            crate::gap_continuation::take_history_counts();
            let history = {
                let _phase = store.sql_phase();
                crate::run_journal::gap_history(&store.conn, h.allocation.checkout).unwrap()
            };
            assert_eq!(history.len(), count);
            assert_eq!(
                crate::gap_continuation::take_history_counts(),
                (count, count, count, count),
                "one target Root/Q/claim/fold pass"
            );
        };
        measure();
        // A real independently qualified checkout in the SAME authority is the
        // payload-isolation control. Only its JSON is corrupted, never raw refs.
        let mut start = h.allocation.request.clone();
        start.operation = uuid::Uuid::now_v7();
        start.task = "unrelated".into();
        start.branch = Some("unrelated".into());
        let sibling = crate::allocate::start(&h.config, start).unwrap();
        std::fs::remove_file(h.temp.path().join("properties")).unwrap();
        std::fs::remove_file(h.temp.path().join("executed")).unwrap();
        let mut command = h.command.clone();
        command.run_id = uuid::Uuid::now_v7();
        command.checkout = sibling.checkout;
        let unrelated = crate::supervisor::supervise_off(
            &h.config,
            command,
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, root| {
                if boundary == Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        )
        .unwrap();
        let run = unrelated.record.request.identity().run.to_string();
        let original_gap: String = store
            .conn
            .query_row(
                "SELECT record FROM attribution_gaps WHERE run=?1",
                [&run],
                |r| r.get(0),
            )
            .unwrap();
        let original_q: String = store
            .conn
            .query_row(
                "SELECT record FROM gap_qualifications WHERE run=?1",
                [&run],
                |r| r.get(0),
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE attribution_gaps SET record='{' WHERE run=?1",
                [&run],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE gap_qualifications SET record='{' WHERE run=?1",
                [&run],
            )
            .unwrap();
        measure();
        store
            .conn
            .execute(
                "UPDATE attribution_gaps SET record=?1 WHERE run=?2",
                (&original_gap, &run),
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE gap_qualifications SET record=?1 WHERE run=?2",
                (&original_q, &run),
            )
            .unwrap();
        assert!(
            store
                .run_snapshot(&unrelated.record.request.identity().run)
                .unwrap()
                .unwrap()
                .closed
        );
    }
}

#[test]
fn successor_claims_and_publication_failures_are_atomic_and_passive() {
    // Two native Stores are opened BEFORE either timed fresh observation. Each
    // thread independently inspects the real predecessor; neither receives a
    // decoded capability. Rendezvous is outside SQL/flock and uses the original
    // two-second proof window, never a renewed timestamp.
    {
        let (h, store, prefix) = genuinely_published_initial();
        let before_q: (String, Vec<u8>) = store
            .conn
            .query_row(
                "SELECT record,fingerprint FROM gap_qualifications",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let (a_ready, b_wait) = std::sync::mpsc::channel();
        let (b_ready, a_wait) = std::sync::mpsc::channel();
        let channels = [(a_ready, a_wait), (b_ready, b_wait)];
        let mut workers = Vec::new();
        for (index, (ready, wait)) in channels.into_iter().enumerate() {
            let native = crate::store::Store::open_existing_registered_mut(
                h.config.trusted_registry.as_ref().unwrap(),
                h.config.store_dir.as_ref().unwrap(),
                &h.config.roots,
            )
            .unwrap();
            let config = h.config.clone();
            let argv = h.command.argv.clone();
            let mut identity = prefix.record.request.identity().clone();
            identity.run = work_contract::RunId::generate();
            identity.group = work_contract::GroupId::generate();
            identity.run_ref = work_contract::RunRef::parse(&format!("contender-{index}")).unwrap();
            let root = crate::run_journal::RootRunRequest::new(
                identity,
                prefix.record.request.input().clone(),
            )
            .unwrap();
            workers.push(std::thread::spawn(move || {
                let observed = std::rc::Rc::new(std::cell::Cell::new(false));
                let seen = observed.clone();
                let _observer = super::observing_admission(move |stage, _| {
                    if stage == "reinspect" {
                        seen.set(true);
                        ready.send(()).unwrap();
                        wait.recv_timeout(std::time::Duration::from_secs(2)).expect("both independent observations must reach CAS without renewing proof age");
                    }
                });
                let id = root.identity().run.to_string();
                let result = super::super::begin_in_store(&config, native, &root, &argv);
                (id, observed.get(), result)
            }));
        }
        let mut winner = None;
        let mut losers = Vec::new();
        for worker in workers {
            let (id, observed, result) = worker.join().unwrap();
            assert!(
                observed,
                "each contender must have actual independent physical preproof"
            );
            match result {
                Ok((_, super::super::BeginGap::Created(live))) => {
                    assert!(winner.replace(id).is_none(), "one atomic claim winner");
                    drop(live);
                }
                Err(_) => losers.push(id),
                Ok(_) => panic!("distinct contender must not become Existing"),
            }
        }
        let winner = winner.expect("exactly one live winner");
        assert_eq!(losers.len(), 1);
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM runs WHERE id=?1", [&losers[0]], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM attribution_gaps", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        let claim: (String, i64) = store
            .conn
            .query_row(
                "SELECT successor_run,successor_revision FROM gap_qualifications",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(claim, (winner.clone(), 4));
        let cursor: (String, i64, String) = store
            .conn
            .query_row(
                "SELECT latest_run,revision,disposition FROM gap_eligibility",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(cursor, (winner, 4, "unavailable".into()));
        assert_eq!(
            store
                .conn
                .query_row(
                    "SELECT record,fingerprint FROM gap_qualifications",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                )
                .unwrap(),
            before_q
        );
    }
    // Lost acknowledgement AFTER genuine Q commit is not abandoned publication.
    // The fault seam supplies no Q/seal/Physical and is never a public retry.
    {
        let h = ScopeHarness::new(true);
        let (store, lease) = crate::allocate::locked(&h.config).unwrap();
        drop(lease);
        let observer = crate::gap_continuation::observing_publication(|stage| {
            if stage == "after_commit" {
                crate::gap_continuation::lose_publication_ack();
            }
        });
        let result = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, root| {
                if boundary == Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        );
        drop(observer);
        assert_eq!(
            store
                .conn
                .query_row("SELECT disposition FROM gap_eligibility", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "available"
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(
            result.is_err(),
            "committed Q lost acknowledgement must report error, not reopen or retry"
        );
        let before = durable_rows(&store);
        let receipt = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |_, _| panic!("Existing must stay passive after Q ACK loss"),
        )
        .unwrap();
        assert!(receipt.existing && receipt.record.closed && !receipt.record.recovery_hold);
        assert_eq!(durable_rows(&store), before);
        let mut next = h.command.clone();
        next.run_id = uuid::Uuid::now_v7();
        std::fs::remove_file(h.temp.path().join("properties")).unwrap();
        std::fs::remove_file(h.temp.path().join("executed")).unwrap();
        let successor = crate::supervisor::supervise_off(
            &h.config,
            next,
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, root| {
                if boundary == Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        )
        .expect(
            "a different fresh run may consume genuinely committed Q after lost acknowledgement",
        );
        assert!(successor.record.closed && !successor.existing);
        let claim: (String, i64) = store
            .conn
            .query_row(
                "SELECT successor_run,successor_revision FROM gap_qualifications WHERE run=?1",
                [receipt.record.request.identity().run.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            claim,
            (successor.record.request.identity().run.to_string(), 4)
        );
        assert_eq!(
            store
                .run_snapshot(&receipt.record.request.identity().run)
                .unwrap(),
            Some(receipt.record)
        );
    }
    // A real eligible close exists before this trigger can decide publication.
    // Aborting INSERT must not roll back already committed physical closure or
    // invent a successful publication acknowledgement. No fake Q is inserted.
    let h = ScopeHarness::new(true);
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    store.conn.execute_batch("CREATE TRIGGER abort_publication BEFORE INSERT ON gap_qualifications BEGIN SELECT RAISE(ABORT,'owned-publication-fault'); END").unwrap();
    let mut closed = false;
    let result = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
            if boundary == Boundary::Closed {
                closed = true;
            }
        },
    );
    assert!(closed, "genuine Changed closure prerequisite");
    let root = store
        .run_snapshot(&work_contract::RunId::parse(&h.command.run_id.to_string()).unwrap())
        .unwrap()
        .unwrap();
    assert!(root.closed && !root.recovery_hold);
    assert_eq!(root.outcome, Some(RootOutcome::Completed));
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let cursor: (i64, String, Option<String>) = store
        .conn
        .query_row(
            "SELECT revision,disposition,qualification FROM gap_eligibility",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(cursor, (2, "awaiting_qualification".into(), None));
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        result.is_err(),
        "publication failure must be attempted and reported after committed closure"
    );
    store
        .conn
        .execute_batch("DROP TRIGGER abort_publication")
        .unwrap();
    let before = durable_rows(&store);
    let existing = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |_, _| panic!("Existing must not republish/relaunch"),
    )
    .unwrap();
    assert!(existing.existing && existing.record.closed);
    assert_eq!(durable_rows(&store), before);

    // Prospective genuinely published predecessor. Each rollback point uses
    // the same intact available Q; failed attempts must not consume it.
    let h = ScopeHarness::new(true);
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let prefix = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    assert!(prefix.record.closed);
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "genuine Q prerequisite, not forged JSON"
    );
    let mut identity = prefix.record.request.identity().clone();
    identity.run = work_contract::RunId::generate();
    identity.group = work_contract::GroupId::generate();
    identity.run_ref = work_contract::RunRef::parse("atomic-successor").unwrap();
    let next =
        crate::run_journal::RootRunRequest::new(identity, prefix.record.request.input().clone())
            .unwrap();
    for (trigger, expected) in [
        ("CREATE TRIGGER abort_successor BEFORE INSERT ON attribution_gaps BEGIN SELECT RAISE(ABORT,'before-gap'); END", "before-gap"),
        ("CREATE TRIGGER abort_successor BEFORE UPDATE OF successor_run ON gap_qualifications BEGIN SELECT RAISE(ABORT,'claim'); END", "claim"),
        ("CREATE TRIGGER abort_successor BEFORE UPDATE ON gap_eligibility BEGIN SELECT RAISE(ABORT,'cursor'); END", "cursor"),
    ] {
        let before = durable_rows(&store);
        store.conn.execute_batch(trigger).unwrap();
        let result = super::super::begin(&h.config, &next, &h.command.argv);
        assert!(matches!(result, Err(crate::store::StoreError::Database(rusqlite::Error::SqliteFailure(_, Some(ref message)))) if message == expected), "must reach actual native trigger {expected}, not blanket admission refusal");
        assert_eq!(durable_rows(&store), before, "successor transaction rollback");
        store.conn.execute_batch("DROP TRIGGER abort_successor").unwrap();
    }
    super::ACK_LOSS.with(|slot| slot.set(true));
    assert!(
        super::super::begin(&h.config, &next, &h.command.argv).is_err(),
        "uncertain admission yields no live"
    );
    assert!(
        !super::take_ack_loss(),
        "actual admission consumed the ACK-loss seam"
    );
    let after = durable_rows(&store);
    let (_, existing) = super::super::begin(&h.config, &next, &h.command.argv).unwrap();
    assert!(matches!(existing, super::super::BeginGap::Existing(_)));
    assert_eq!(durable_rows(&store), after);
    let claim: (String, i64) = store
        .conn
        .query_row(
            "SELECT successor_run,successor_revision FROM gap_qualifications",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(claim, (next.identity().run.to_string(), 4));
}

/// Exercise every legacy mutation entry against the same immutable authority.
/// The caller supplies either genuinely admitted history or explicitly corrupt
/// raw rows; this helper never constructs a successful live capability.
fn assert_legacy_fences(
    temp: &std::path::Path,
    config: &crate::config::Config,
    allocation: &crate::allocate::Allocation,
    root: &crate::run_journal::RootRunRequest,
    store: &mut crate::store::Store,
) {
    struct Sink(std::cell::Cell<usize>);
    impl crate::finish::LocalSink for Sink {
        fn freeze(&self, _: &crate::finish::CaptureContext) -> crate::finish::CaptureResult {
            self.0.set(self.0.get() + 1);
            crate::finish::CaptureResult::Failed
        }
    }
    let before = durable_rows(store);
    let marker = allocation
        .identity
        .as_ref()
        .unwrap()
        .private_git_dir
        .join("work-lease.json");
    let marker_before = std::fs::read(&marker).unwrap();
    let sink = Sink(std::cell::Cell::new(0));
    let mut callbacks = 0;
    for integrated in [false, true] {
        let result = if integrated {
            crate::finish::finish(config, allocation.checkout)
        } else {
            crate::finish::finish_with_sink_observed(
                config,
                allocation.checkout,
                Some(&sink),
                |_| callbacks += 1,
            )
        };
        assert!(
            result.is_err(),
            "new finish must refuse before fence: integrated={integrated}"
        );
        assert_eq!(durable_rows(store), before);
    }
    assert_eq!(callbacks, 0, "no task-fence/completion callback");
    assert_eq!(sink.0.get(), 0, "no library receiver callback");
    assert!(crate::allocate::start(config, allocation.request.clone()).is_err());
    assert_eq!(
        durable_rows(store),
        before,
        "operation retry mutated authority"
    );
    let mut retry = allocation.request.clone();
    retry.operation = uuid::Uuid::now_v7();
    assert!(crate::allocate::start(config, retry).is_err());
    assert_eq!(
        durable_rows(store),
        before,
        "checkout retry mutated authority"
    );
    assert!(crate::allocate::verified_checkout(store, allocation.checkout).is_err());
    assert_eq!(
        durable_rows(store),
        before,
        "source/verification path mutated authority"
    );
    let mut copy = allocation.clone();
    assert!(crate::recovery::reconcile(store, &mut copy).is_err());
    assert_eq!(durable_rows(store), before);
    assert!(crate::allocate::save(store, allocation).is_err());
    assert_eq!(durable_rows(store), before);
    copy.stage = "ready".into();
    copy.reason = None;
    assert!(crate::allocate::save(store, &copy).is_err());
    assert_eq!(
        durable_rows(store),
        before,
        "generic Ready save must not revive required authority"
    );
    let default = crate::test_run_fixture::request(allocation.checkout);
    assert!(store.begin_run(&default).is_err());
    assert_eq!(durable_rows(store), before);
    assert!(store
        .acquire_writer(allocation.checkout, uuid::Uuid::now_v7())
        .is_err());
    assert_eq!(durable_rows(store), before);
    let spec = super::mixed_history_spec(temp, config, allocation, &default);
    assert!(store.begin_captured_run(&default, &spec).is_err());
    assert_eq!(
        durable_rows(store),
        before,
        "direct captured admission created rows"
    );
    assert!(crate::capture_setup::begin(config, &default, &spec).is_err());
    assert_eq!(durable_rows(store), before, "capture setup created rows");
    assert!(
        !temp.join("negative-state").exists(),
        "capture refusal precedes artifacts"
    );
    assert!(!temp.join("negative-producer").exists());
    assert_eq!(std::fs::read(marker).unwrap(), marker_before);
    assert!(super::super::raw_history(&store.conn, allocation.checkout).unwrap());
    assert!(super::super::guard_legacy_allocation(&store.conn, allocation.checkout).is_err());
    assert_eq!(durable_rows(store), before);
    // This argument ties callers to the target, not to a fabricated new root.
    assert_eq!(
        root.identity().checkout.to_string(),
        allocation.checkout.to_string()
    );
}

#[test]
fn both_required_origins_fence_legacy_default_capture_and_new_finish() {
    // Initial-only prerequisite is available now. The retained raw_history
    // guard predates this test: its coverage is AFTER-THE-FACT PRESERVATION,
    // under parent-c14-ordering-exception-authorization.md, never retroactive RED.
    let (temp, config, allocation, root, argv) = super::materialized(true);
    let (mut store, created) = super::super::begin(&config, &root, &argv).unwrap();
    assert!(matches!(created, super::super::BeginGap::Created(_)));
    drop(created);
    assert_legacy_fences(temp.path(), &config, &allocation, &root, &mut store);

    // Explicit raw CORRUPTION on an otherwise ordinary, Ready checkout. There
    // is no Gap, Root marker, requirement or writer to mask raw-presence fences.
    // Neither malformed Q nor cursor is ever used as positive authority.
    for qualification in [false, true] {
        let (temp, config, allocation, root, _) = super::materialized(false);
        let (mut store, lease) = crate::allocate::locked(&config).unwrap();
        drop(lease);
        let sql = rusqlite::Connection::open(temp.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        if qualification {
            sql.execute(
                "INSERT INTO gap_qualifications VALUES(?1,?2,'{malformed',zeroblob(32),NULL,NULL)",
                (
                    root.identity().run.to_string(),
                    allocation.checkout.to_string(),
                ),
            )
            .unwrap();
        } else {
            sql.execute(
                "INSERT INTO gap_eligibility VALUES(?1,?2,1,'unavailable',NULL)",
                (
                    allocation.checkout.to_string(),
                    root.identity().run.to_string(),
                ),
            )
            .unwrap();
        }
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM attribution_gaps", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(
            super::super::raw_history(&store.conn, allocation.checkout).unwrap(),
            "raw cursor/Q alone must fence"
        );
        assert_legacy_fences(temp.path(), &config, &allocation, &root, &mut store);
    }

    // Otherwise-eligible captured pending setup: raw cursor/Q alone must stop
    // integrated preparation BEFORE its first artifact/receiver observation.
    // After removing only the explicit negative rows, fresh actual setup is the
    // positive control; no rejected proof or decoded capability is reused.
    for qualification in [false, true] {
        let (temp, config, allocation, root, _) = super::materialized(true);
        let (store, lease) = crate::allocate::locked(&config).unwrap();
        drop(lease);
        let mut input = root.input().clone();
        input.attribution = None;
        let default =
            crate::run_journal::RootRunRequest::new(root.identity().clone(), input).unwrap();
        let spec = config
            .capture_spec(
                &default,
                &allocation,
                uuid::Uuid::now_v7(),
                vec![allocation.request.task.clone()],
                None,
            )
            .unwrap();
        let sql = rusqlite::Connection::open(temp.path().join("private/store.sqlite")).unwrap();
        sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        if qualification {
            sql.execute(
                "INSERT INTO gap_qualifications VALUES(?1,?2,'{',zeroblob(32),NULL,NULL)",
                (
                    root.identity().run.to_string(),
                    allocation.checkout.to_string(),
                ),
            )
            .unwrap();
        } else {
            sql.execute(
                "INSERT INTO gap_eligibility VALUES(?1,?2,1,'unavailable',NULL)",
                (
                    allocation.checkout.to_string(),
                    root.identity().run.to_string(),
                ),
            )
            .unwrap();
        }
        let before = durable_rows(&store);
        let mut observations = 0;
        assert!(
            crate::capture_preparation::prepare_observed(&config, &default, &spec, |_, _| {
                observations += 1
            })
            .is_err()
        );
        assert_eq!(
            observations, 0,
            "raw fence precedes RegistryRead/artifacts/BEGIN"
        );
        assert_eq!(durable_rows(&store), before);
        sql.execute_batch("DELETE FROM gap_eligibility; DELETE FROM gap_qualifications")
            .unwrap();
        let (_, control) = crate::capture_setup::begin(&config, &default, &spec).unwrap();
        assert!(
            matches!(
                control,
                crate::capture_journal::BeginCapturedRun::Created(_)
            ),
            "without corrupt raw authority this exact pending setup is genuinely eligible"
        );
    }

    // Genuine ordinary NoTarget receipt remains passive. New raw authority must
    // still be checked on Existing acknowledgement, including before_ack.
    let mut h = ScopeHarness::new(false);
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let report = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    assert!(report.record.closed);
    let receipt = crate::finish::finish(&h.config, h.allocation.checkout).unwrap();
    assert_eq!(receipt.local_freeze, crate::finish::Freeze::NotConfigured);
    assert_eq!(
        receipt.delivery,
        Some(crate::finish::Delivery::NotConfigured)
    );
    let pristine = durable_rows(&store);
    let sql = rusqlite::Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    let insert = || {
        sql.execute(
            "INSERT INTO gap_qualifications VALUES(?1,?2,'{malformed',zeroblob(32),NULL,NULL)",
            (
                uuid::Uuid::now_v7().to_string(),
                h.allocation.checkout.to_string(),
            ),
        )
        .unwrap();
    };
    for late in [false, true] {
        if !late {
            insert();
        }
        let mut corrupt = None;
        let result = crate::finish::finish_with_sink_observed(
            &h.config,
            h.allocation.checkout,
            None,
            |boundary| {
                if late && boundary == "before_ack" {
                    insert();
                    corrupt = Some(durable_rows(&store));
                }
            },
        );
        assert!(result.is_err(), "raw fence on passive receipt, late={late}");
        if late {
            assert_eq!(
                durable_rows(&store),
                corrupt.expect("reached final raw fence")
            );
        }
        assert!(crate::finish::finish(&h.config, h.allocation.checkout).is_err());
        sql.execute("DELETE FROM gap_qualifications", []).unwrap();
        assert_eq!(durable_rows(&store), pristine);
    }
    h.config.allocation.as_mut().unwrap().capture_sink = Some("devdiary".into());
    h.config.supervisor.as_mut().unwrap().actors.clear();
    assert_eq!(
        crate::finish::finish(&h.config, h.allocation.checkout).unwrap(),
        receipt
    );
    assert_eq!(durable_rows(&store), pristine);

    // Prospective genuine dependency: no SQL-forged Q/format2. This section is
    // deliberately executable now and must reach both real closed origins once
    // C6 supplies live-close/publication/claim. A prerequisite failure is NOT
    // C14 state RED and does not waive these assertions.
    let h = ScopeHarness::new(true);
    let (mut store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    for index in 0..2 {
        let mut command = h.command.clone();
        if index == 1 {
            command.run_id = uuid::Uuid::now_v7();
            std::fs::remove_file(h.temp.path().join("properties")).unwrap();
            std::fs::remove_file(h.temp.path().join("executed")).unwrap();
        }
        let report = crate::supervisor::supervise_off(
            &h.config,
            command,
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, root| {
                if boundary == Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        )
        .expect("C14 genuine live-close/continuation dependency");
        assert!(report.record.closed);
        let status =
            crate::run_recovery::status(&store, &report.record.request.identity().run).unwrap();
        assert_eq!(status.gap_limitations, Some("continuation requires a live-close qualification and fresh same-boot/actor/target checks; closure retains held/not_ready and charge; recovery never qualifies; generic Ready, new finish and transport remain unsupported"));
        assert_eq!(status.checkout_state, "held");
        assert!(!status.checkout_ready);
        assert_eq!(
            report.gap.as_ref().unwrap().origin,
            if index == 0 {
                "required_initial"
            } else {
                "required_continuation"
            }
        );
        assert_legacy_fences(
            h.temp.path(),
            &h.config,
            &h.allocation,
            &report.record.request,
            &mut store,
        );
        let before = durable_rows(&store);
        let spec = super::mixed_history_spec(
            h.temp.path(),
            &h.config,
            &h.allocation,
            &report.record.request,
        );
        super::inject_unprepared_capture(&store, &report.record.request, &spec);
        let mixed = durable_rows(&store);
        assert!(
            store
                .run_snapshot(&report.record.request.identity().run)
                .is_err(),
            "both origins reject mixed history"
        );
        assert!(crate::finish::finish(&h.config, h.allocation.checkout).is_err());
        assert_eq!(durable_rows(&store), mixed);
        store
            .conn
            .execute(
                "DELETE FROM capture_runs WHERE run=?1",
                [report.record.request.identity().run.to_string()],
            )
            .unwrap();
        assert_eq!(durable_rows(&store), before);
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            index + 1,
            "genuine published Q dependency"
        );
    }
}

#[test]
fn historical_claims_are_passive_and_new_target_checks_are_fresh() {
    // Prospective Q-dependent cases, authored before continuation admission or
    // publication policy. No synthetic Q or decoded live value is a prerequisite.
    let h = ScopeHarness::new(true);
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let first = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    assert!(first.record.closed);
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "genuinely published predecessor dependency"
    );
    let before = durable_rows(&store);
    let mut next = h.command.clone();
    next.run_id = uuid::Uuid::now_v7();
    let public_registry_bytes =
        std::fs::read(&h.config.capture.as_ref().unwrap().registry).unwrap();
    for policy in [
        "removed",
        "actor",
        "endpoint",
        "registry",
        "valid-registry-path",
        "valid-new-pin-and-name",
        "pin",
        "configured-name",
        "actor-ref",
    ] {
        let mut config = h.config.clone();
        let mut command = next.clone();
        match policy {
            "removed" => config.allocation.as_mut().unwrap().capture_sink = None,
            "actor" => {
                let profile = config.supervisor.as_ref().unwrap().actors["alice"].clone();
                config
                    .supervisor
                    .as_mut()
                    .unwrap()
                    .actors
                    .insert("bob".into(), profile);
                config
                    .capture
                    .as_mut()
                    .unwrap()
                    .actor_refs
                    .insert("bob".into(), "actor:alice".into());
                command.actor = Some("bob".into());
            }
            "endpoint" => {
                config.capture.as_mut().unwrap().endpoint_identity = "receiver:other".into()
            }
            "registry" => {
                config.capture.as_mut().unwrap().registry = h.temp.path().join("missing-registry")
            }
            "valid-registry-path" => {
                let other = h.temp.path().join("other-public-registry.json");
                std::fs::copy(&config.capture.as_ref().unwrap().registry, &other).unwrap();
                config.capture.as_mut().unwrap().registry = other;
            }
            "valid-new-pin-and-name" => {
                use sha2::Digest;
                let bytes = br#"{"ingest":{"key_env":"ROTATED_RECEIVER_NAME"}}"#;
                std::fs::write(&config.capture.as_ref().unwrap().registry, bytes).unwrap();
                config.capture.as_mut().unwrap().registry_sha256 =
                    format!("{:x}", sha2::Sha256::digest(bytes));
            }
            "pin" => config.capture.as_mut().unwrap().registry_sha256 = "0".repeat(64),
            "configured-name" => config
                .capture
                .as_mut()
                .unwrap()
                .receiver_credential_names
                .push("NEW_RECEIVER_TOKEN".into()),
            "actor-ref" => {
                config
                    .capture
                    .as_mut()
                    .unwrap()
                    .actor_refs
                    .insert("alice".into(), "actor:other".into());
            }
            _ => unreachable!(),
        }
        assert!(
            crate::supervisor::supervise_off(
                &config,
                command,
                &h.driver,
                Some(h.io()),
                &CancelToken::default(),
                |_, _| panic!("changed target entered runtime")
            )
            .is_err(),
            "policy={policy}"
        );
        assert_eq!(durable_rows(&store), before, "policy={policy}");
        if policy == "valid-new-pin-and-name" {
            std::fs::write(
                &h.config.capture.as_ref().unwrap().registry,
                &public_registry_bytes,
            )
            .unwrap();
        }
    }
    std::fs::remove_file(h.temp.path().join("properties")).unwrap();
    std::fs::remove_file(h.temp.path().join("executed")).unwrap();
    let second = crate::supervisor::supervise_off(
        &h.config,
        next.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .expect("genuine consumed-Q history dependency");
    assert!(second.record.closed);
    let claim: String = store
        .conn
        .query_row(
            "SELECT successor_run FROM gap_qualifications WHERE run=?1",
            [first.record.request.identity().run.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(claim, second.record.request.identity().run.to_string());
    let before = durable_rows(&store);
    let mut unavailable = h.config.clone();
    unavailable.supervisor.as_mut().unwrap().actors.clear();
    unavailable.capture.as_mut().unwrap().registry = h.temp.path().join("absent-registry");
    unavailable.capture.as_mut().unwrap().executable = h.temp.path().join("absent-producer");
    for (command, expected) in [(&h.command, &first), (&next, &second)] {
        let receipt = crate::supervisor::supervise_off(
            &unavailable,
            command.clone(),
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |_, _| panic!("historical receipt entered runtime"),
        )
        .unwrap();
        assert!(receipt.existing);
        assert_eq!(receipt.record, expected.record);
        assert_eq!(receipt.gap, expected.gap);
        assert_eq!(durable_rows(&store), before);
    }
    // A different boot declaration cannot consume same-boot Q. The observation
    // is actual; only the candidate declaration is changed, not a forged proof.
    let mut identity = second.record.request.identity().clone();
    identity.run = work_contract::RunId::generate();
    identity.group = work_contract::GroupId::generate();
    identity.run_ref = work_contract::RunRef::parse("boot-policy").unwrap();
    let mut input = second.record.request.input().clone();
    input.boot = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
    let bad = crate::run_journal::RootRunRequest::new(identity.clone(), input).unwrap();
    assert!(super::super::begin(&h.config, &bad, &h.command.argv).is_err());
    assert_eq!(durable_rows(&store), before);
    let good =
        crate::run_journal::RootRunRequest::new(identity, second.record.request.input().clone())
            .unwrap();
    let (_, control) = super::super::begin(&h.config, &good, &h.command.argv).unwrap();
    assert!(
        matches!(control, super::super::BeginGap::Created(_)),
        "same actual boot control is eligible"
    );
    drop(control);
    // Contrast C16's unrelated malformed-payload isolation: a raw orphan is
    // authority-wide corruption even when its checkout is unrelated to this read.
    let sql = rusqlite::Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    let stray = uuid::Uuid::now_v7().to_string();
    let before = durable_rows(&store);
    sql.execute(
        "INSERT INTO gap_qualifications VALUES(?1,?2,'{',zeroblob(32),NULL,NULL)",
        (&stray, uuid::Uuid::now_v7().to_string()),
    )
    .unwrap();
    let corrupt = durable_rows(&store);
    assert!(store
        .run_snapshot(&first.record.request.identity().run)
        .is_err());
    assert_eq!(durable_rows(&store), corrupt);
    sql.execute("DELETE FROM gap_qualifications WHERE run=?1", [&stray])
        .unwrap();
    assert_eq!(durable_rows(&store), before);
    key_rotation_and_unqualified_tails();
}

fn key_rotation_and_unqualified_tails() {
    use std::os::unix::fs::PermissionsExt;
    let mut h = ScopeHarness::new(true);
    let key = h.temp.path().join("owned-fixture-key");
    h.config.capture.as_mut().unwrap().key_file = Some(key.clone());
    std::fs::write(&key, b"fixture-value-before").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let prefix = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    assert!(prefix.record.closed);
    // Only owned fixture writes; neither test nor product reads key contents.
    // Same public target metadata, different private value and unreadable file.
    std::fs::write(&key, b"fixture-value-after").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut next = h.command.clone();
    next.run_id = uuid::Uuid::now_v7();
    std::fs::remove_file(h.temp.path().join("properties")).unwrap();
    std::fs::remove_file(h.temp.path().join("executed")).unwrap();
    let successor = crate::supervisor::supervise_off(
        &h.config,
        next,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    assert_eq!(
        successor.gap.as_ref().unwrap().origin,
        "required_continuation"
    );
    assert!(successor.record.closed);
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );

    // Authentic v14 no-reference reconstruction of an actually closed v1 Root:
    // empty additive migration preserves history but never backfills authority.
    let (h, store, prefix) = genuinely_published_initial();
    let prior_events = store.pending_events(100).unwrap();
    let prior_root = store
        .run_snapshot(&prefix.record.request.identity().run)
        .unwrap();
    store
        .conn
        .execute_batch(
            "DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; PRAGMA user_version=14",
        )
        .unwrap();
    drop(store);
    let (migrated, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    assert_eq!(migrated.pending_events(100).unwrap(), prior_events);
    assert_eq!(
        migrated
            .run_snapshot(&prefix.record.request.identity().run)
            .unwrap(),
        prior_root
    );
    let before = durable_rows(&migrated);
    let receipt = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |_, _| panic!("legacy receipt cannot relaunch"),
    )
    .unwrap();
    assert!(receipt.existing && receipt.record == prefix.record);
    let mut next = h.command.clone();
    next.run_id = uuid::Uuid::now_v7();
    assert!(crate::supervisor::supervise_off(
        &h.config,
        next,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |_, _| panic!("legacy close cannot create continuation")
    )
    .is_err());
    assert_eq!(durable_rows(&migrated), before);

    let (h, mut store, _) = genuinely_published_initial();
    let mut next = h.command.clone();
    next.run_id = uuid::Uuid::now_v7();
    let run = work_contract::RunId::parse(&next.run_id.to_string()).unwrap();
    std::fs::remove_file(h.temp.path().join("properties")).unwrap();
    std::fs::remove_file(h.temp.path().join("executed")).unwrap();
    assert!(crate::supervisor::supervise_off(
        &h.config,
        next,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::Bound {
                store.record_recovery_hold(&root.request).unwrap();
            }
        }
    )
    .is_err());
    let root = store.run_snapshot(&run).unwrap().unwrap();
    assert!(root.outcome.is_none());
    h.empty(&root);
    assert_eq!(
        crate::run_recovery::recover_with_config(&mut store, &run, &h.driver, &h.config).unwrap(),
        crate::run_recovery::RecoveryState::Closed
    );
    let before = durable_rows(&store);
    let mut later = h.command.clone();
    later.run_id = uuid::Uuid::now_v7();
    assert!(crate::supervisor::supervise_off(
        &h.config,
        later,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |_, _| panic!("unknown recovered tail cannot requalify")
    )
    .is_err());
    assert_eq!(durable_rows(&store), before);
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn legal_cursor_tails_remain_historical_without_requalification() {
    use rusqlite::OptionalExtension;
    let (_temp, config, allocation, root, argv) = super::materialized(true);
    let (store, created) = super::super::begin(&config, &root, &argv).unwrap();
    assert!(matches!(created, super::super::BeginGap::Created(_)));
    let cursor: Option<(String, i64, String, Option<String>)> = store.conn.query_row(
        "SELECT latest_run,revision,disposition,qualification FROM gap_eligibility WHERE checkout=?1",
        [allocation.checkout.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).optional().unwrap();
    assert_eq!(
        cursor,
        Some((
            root.identity().run.to_string(),
            1,
            "unavailable".into(),
            None
        )),
        "actual RequiredInitial admission initializes its unavailable cursor atomically"
    );
    let before = durable_rows(&store);
    assert!(
        !store
            .run_snapshot(&root.identity().run)
            .unwrap()
            .unwrap()
            .closed
    );
    let (_, existing) = super::super::begin(&config, &root, &argv).unwrap();
    assert!(matches!(existing, super::super::BeginGap::Existing(_)));
    assert_eq!(
        durable_rows(&store),
        before,
        "reads and Existing are passive"
    );
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );

    // A v1 with no remaining new references is historical metadata only. This
    // fixture removes provenance, never supplies or reconstructs live authority.
    drop(created);
    store
        .conn
        .execute(
            "DELETE FROM gap_eligibility WHERE checkout=?1",
            [allocation.checkout.to_string()],
        )
        .unwrap();
    let legacy = durable_rows(&store);
    assert!(store.run_snapshot(&root.identity().run).unwrap().is_some());
    let (_, existing) = super::super::begin(&config, &root, &argv).unwrap();
    assert!(matches!(existing, super::super::BeginGap::Existing(_)));
    assert_eq!(
        durable_rows(&store),
        legacy,
        "legacy Existing never backfills a cursor"
    );

    // Positive complete child roster on the actual owned root's shared host.
    // No raw host/enrollment/Q: certify through the Driver and then prove the
    // entire actual roster empty at physical close. Keep a genuine old proof
    // solely to test passive Existing close after a later admitted successor.
    let h = ScopeHarness::new(true);
    let (mut store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let mut closed = false;
    let mut old_close = None;
    let report = crate::supervisor::supervise_off(&h.config, h.command.clone(), &h.driver, Some(h.io()), &CancelToken::default(), |boundary, root| {
        if boundary == Boundary::PermitAttempt {
            let child = enroll_shared_root_host(&h, &mut store, root);
            assert_eq!(store.record_child_outcome(&root.request, &child, crate::run_participants::ChildOutcome::Completed).unwrap(), crate::run_journal::Transition::Changed);
            assert_eq!(store.conn.query_row("SELECT revision FROM gap_eligibility", [], |r| r.get::<_, i64>(0)).unwrap(), 1, "normal child progress does not revoke");
        }
        if boundary == Boundary::RootTerminal {
            h.empty(root);
            let snapshot = store.group_snapshot(&root.request.identity().run).unwrap();
            let proof = snapshot.certify_historical_empty(&h.driver).unwrap();
            old_close = Some((snapshot, proof));
        }
        if boundary == Boundary::Closed {
            closed = true;
            let cursor: (String, i64, String, Option<String>) = store.conn.query_row(
                "SELECT latest_run,revision,disposition,qualification FROM gap_eligibility WHERE checkout=?1",
                [h.allocation.checkout.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
            ).unwrap();
            assert_eq!(cursor, (root.request.identity().run.to_string(), 2, "awaiting_qualification".into(), None));
            assert!(root.closed && !root.recovery_hold);
            assert_eq!(root.outcome, Some(RootOutcome::Completed));
            assert_eq!(store.conn.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
            assert_eq!(store.conn.query_row("SELECT count(*) FROM gap_qualifications", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
            assert_eq!(store.run_snapshot(&root.request.identity().run).unwrap(), Some(root.clone()));
        }
    }).expect("eligible live Changed close must commit a coherent awaiting cursor");
    assert!(closed && report.record.closed);
    assert_eq!(report.record.children.len(), 1);
    assert_eq!(
        report.record.children[0].enrollment,
        crate::run_participants::Enrollment::Contained
    );
    assert_eq!(
        report.record.children[0].outcome,
        Some(crate::run_participants::ChildOutcome::Completed)
    );
    assert!(report.record.children[0].host.is_some());
    assert_eq!(
        store
            .conn
            .query_row("SELECT disposition FROM gap_eligibility", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "available"
    );
    let prefix_q: (String, Vec<u8>) = store
        .conn
        .query_row(
            "SELECT record,fingerprint FROM gap_qualifications",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let (snapshot, proof) = old_close.unwrap();
    let mut next = h.command.clone();
    next.run_id = uuid::Uuid::now_v7();
    let run = work_contract::RunId::parse(&next.run_id.to_string()).unwrap();
    std::fs::remove_file(h.temp.path().join("properties")).unwrap();
    std::fs::remove_file(h.temp.path().join("executed")).unwrap();
    let result = crate::supervisor::supervise_off(
        &h.config,
        next,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::Intent {
                let cursor: (String, i64, String) = store
                    .conn
                    .query_row(
                        "SELECT latest_run,revision,disposition FROM gap_eligibility",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .unwrap();
                assert_eq!(
                    cursor,
                    (
                        root.request.identity().run.to_string(),
                        4,
                        "unavailable".into()
                    )
                );
                let before = durable_rows(&store);
                assert_eq!(
                    store.close_supervised_group(&snapshot, &proof).unwrap(),
                    crate::run_journal::Transition::Existing
                );
                assert_eq!(
                    durable_rows(&store),
                    before,
                    "old Existing close never touches successor/Q/cursor"
                );
            }
            if boundary == Boundary::Bound {
                assert_eq!(
                    store.record_recovery_hold(&root.request).unwrap(),
                    crate::run_journal::Transition::Changed
                );
            }
        },
    );
    assert!(result.is_err() && !h.temp.path().join("executed").exists());
    let open = store.run_snapshot(&run).unwrap().unwrap();
    assert!(!open.closed && open.outcome.is_none());
    h.empty(&open);
    assert_eq!(
        crate::run_recovery::recover_with_config(&mut store, &run, &h.driver, &h.config).unwrap(),
        crate::run_recovery::RecoveryState::Closed
    );
    let blocked = store.run_snapshot(&run).unwrap().unwrap();
    assert!(blocked.closed && blocked.outcome.is_none());
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT revision,disposition,qualification FROM gap_eligibility",
                [],
                |r| Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?
                ))
            )
            .unwrap(),
        (6, "blocked".into(), None)
    );
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT record,fingerprint FROM gap_qualifications",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            )
            .unwrap(),
        prefix_q
    );
    let before = durable_rows(&store);
    assert_eq!(
        store.close_supervised_group(&snapshot, &proof).unwrap(),
        crate::run_journal::Transition::Existing
    );
    assert_eq!(durable_rows(&store), before);

    // Stranded awaiting without Q is valid metadata, never a reconstructed seal.
    let h = ScopeHarness::new(true);
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    store.conn.execute_batch("CREATE TRIGGER stranded BEFORE INSERT ON gap_qualifications BEGIN SELECT RAISE(ABORT,'stranded'); END").unwrap();
    assert!(crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        }
    )
    .is_err());
    store.conn.execute_batch("DROP TRIGGER stranded").unwrap();
    let before = durable_rows(&store);
    let receipt = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |_, _| panic!("stranded Existing cannot republish"),
    )
    .unwrap();
    assert!(receipt.existing && receipt.record.closed);
    assert_eq!(durable_rows(&store), before);
    let mut next = h.command.clone();
    next.run_id = uuid::Uuid::now_v7();
    assert!(crate::supervisor::supervise_off(
        &h.config,
        next,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |_, _| panic!("stranded tail cannot admit")
    )
    .is_err());
    assert_eq!(durable_rows(&store), before);

    // Revoked available retains its unclaimed Q as historical provenance.
    let (h, mut store, prefix) = genuinely_published_initial();
    let limits = crate::admission::Limits {
        repository: 10,
        owner: 10,
        available_bytes: None,
        floor_bytes: 0,
        warn_bytes: 0,
    };
    store
        .transfer(h.allocation.checkout, "bob", limits)
        .unwrap();
    store
        .transfer(h.allocation.checkout, "alice", limits)
        .unwrap();
    let before = durable_rows(&store);
    assert_eq!(
        store
            .run_snapshot(&prefix.record.request.identity().run)
            .unwrap(),
        Some(prefix.record)
    );
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT successor_run,successor_revision FROM gap_qualifications",
                [],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<i64>>(1)?))
            )
            .unwrap(),
        (None, None)
    );
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT revision,disposition,qualification FROM gap_eligibility",
                [],
                |r| Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?
                ))
            )
            .unwrap(),
        (5, "blocked".into(), None)
    );
    assert_eq!(durable_rows(&store), before);
}

fn enroll_shared_root_host(
    h: &ScopeHarness,
    store: &mut crate::store::Store,
    root: &crate::run_journal::RunRecord,
) -> crate::run_participants::ChildRequest {
    let binding = root.binding.as_ref().unwrap();
    let registrar = std::process::id();
    let path = h.temp.path().join(format!("proc/{registrar}"));
    std::fs::create_dir(&path).unwrap();
    std::fs::write(
        path.join("stat"),
        std::fs::read(format!("/proc/{registrar}/stat")).unwrap(),
    )
    .unwrap();
    std::fs::write(path.join("cgroup"), format!("0::{}\n", binding.cgroup)).unwrap();
    let members = h
        .temp
        .path()
        .join("cg")
        .join(binding.cgroup.trim_start_matches('/'))
        .join("cgroup.procs");
    std::fs::write(&members, format!("{}\n{registrar}\n", binding.root_pid)).unwrap();
    let child = super::declared_child(
        &root.request,
        Some(crate::run_participants::ExpectedHost {
            pid: binding.root_pid,
            start_ticks: binding.root_start_ticks,
            boot: binding.boot.clone(),
        }),
    );
    assert_eq!(
        store.register_child(&root.request, &child).unwrap(),
        crate::run_journal::BeginRun::Created
    );
    let proof = store
        .group_snapshot(&root.request.identity().run)
        .unwrap()
        .certify_child_enrollment(&h.driver, &child.run, None)
        .unwrap();
    assert_eq!(
        store
            .record_child_enrollment(&root.request, &child, &proof)
            .unwrap(),
        crate::run_journal::Transition::Changed
    );
    std::fs::remove_dir_all(path).unwrap();
    std::fs::write(members, format!("{}\n", binding.root_pid)).unwrap();
    child
}

fn genuinely_published_initial() -> (
    ScopeHarness,
    crate::store::Store,
    crate::supervisor::RunReport,
) {
    let h = ScopeHarness::new(true);
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let report = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    assert!(report.record.closed && !report.checkout_ready);
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "genuine publication prerequisite"
    );
    (h, store, report)
}

// Preserve every surrounding canonical byte while replacing one JSON field.
// This test-only parser never turns a decoded record into live authority.
fn json_field_range(bytes: &str, field: &str) -> std::ops::Range<usize> {
    let prefix = format!("\"{field}\":");
    let start = bytes.find(&prefix).unwrap() + prefix.len();
    let mut stream =
        serde_json::Deserializer::from_str(&bytes[start..]).into_iter::<serde_json::Value>();
    stream.next().unwrap().unwrap();
    start..start + stream.byte_offset()
}
fn replace_json_field(bytes: &str, field: &str, replacement: &str) -> String {
    let range = json_field_range(bytes, field);
    format!(
        "{}{}{}",
        &bytes[..range.start],
        replacement,
        &bytes[range.end..]
    )
}

fn qualification_negatives(wire: bool) {
    use sha2::Digest;
    let (_h, store, report) = genuinely_published_initial();
    let (bytes, fingerprint): (String, Vec<u8>) = store
        .conn
        .query_row(
            "SELECT record,fingerprint FROM gap_qualifications",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&bytes).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 16);
    assert_eq!(
        value["physical"]["directories"].as_array().unwrap().len(),
        4
    );
    assert_eq!(
        value["run"],
        report.record.request.identity().run.to_string()
    );
    assert_eq!(value["admission_revision"], 1);
    assert_eq!(value["close_revision"], 2);
    assert_eq!(value["publication_revision"], 3);
    let mut cases = if wire {
        vec![
            bytes.replacen(
                "\"format_version\":1",
                "\"format_version\":1,\"format_version\":1",
                1,
            ),
            bytes.replacen(
                "\"format_version\":1",
                "\"unknown\":0,\"format_version\":1",
                1,
            ),
            "null".into(),
            "[]".into(),
            bytes.replacen("\"physical\":{", "\"physical\":null,\"discarded\":{", 1),
        ]
    } else {
        vec![
            bytes.replacen("\"admission_revision\":1", "\"admission_revision\":2", 1),
            bytes.replacen("\"close_revision\":2", "\"close_revision\":5", 1),
            bytes.replacen(
                "\"publication_revision\":3",
                "\"publication_revision\":9223372036854775807",
                1,
            ),
        ]
    };
    if wire {
        assert_eq!(
            fingerprint,
            sha2::Sha256::digest(bytes.as_bytes()).as_slice()
        );
        for field in ["authority", "destination", "physical"] {
            let original = &bytes[json_field_range(&bytes, field)];
            cases.push(replace_json_field(&bytes, field, "null"));
            cases.push(replace_json_field(
                &bytes,
                field,
                &original.replacen('{', "{\"unknown\":0,", 1),
            ));
            let keys: &[&str] = match field {
                "authority" => &[
                    "registry",
                    "directory",
                    "directory_id",
                    "database_id",
                    "lock_id",
                ],
                "destination" => &[
                    "family",
                    "endpoint",
                    "registry",
                    "pin",
                    "actor_ref",
                    "configured_names",
                    "actual_name",
                    "removal_names",
                ],
                _ => &["checkout", "directories", "marker"],
            };
            let positional = format!(
                "[{}]",
                keys.iter()
                    .map(|key| &original[json_field_range(original, key)])
                    .collect::<Vec<_>>()
                    .join(",")
            );
            cases.push(replace_json_field(&bytes, field, &positional));
            let key = keys[0];
            let duplicate = format!(
                "{{\"{key}\":{},{}",
                &original[json_field_range(original, key)],
                &original[1..]
            );
            cases.push(replace_json_field(&bytes, field, &duplicate));
        }
        let physical = &bytes[json_field_range(&bytes, "physical")];
        let checkout = &physical[json_field_range(physical, "checkout")];
        let directory = &checkout[json_field_range(checkout, "directory")];
        for bad_directory in [
            "null".to_owned(),
            directory.replacen('{', "{\"extra\":0,", 1),
            "[1,2]".into(),
        ] {
            let changed_checkout = replace_json_field(checkout, "directory", &bad_directory);
            cases.push(replace_json_field(
                &bytes,
                "physical",
                &replace_json_field(physical, "checkout", &changed_checkout),
            ));
        }
        for bad_head in ["\"HEAD\"", "\"not-an-object\""] {
            let changed_checkout = replace_json_field(checkout, "head", bad_head);
            cases.push(replace_json_field(
                &bytes,
                "physical",
                &replace_json_field(physical, "checkout", &changed_checkout),
            ));
        }
        for count in [0usize, 3, 5] {
            let directories = serde_json::to_string(&vec![(1u64, 2u64); count]).unwrap();
            cases.push(replace_json_field(
                &bytes,
                "physical",
                &replace_json_field(physical, "directories", &directories),
            ));
        }
        cases.push(replace_json_field(&bytes, "source_path", "\"../relative\""));
        cases.push(replace_json_field(&bytes, "format_version", "2"));
        cases.push(format!(" {bytes}"));
    }
    if !wire {
        for field in ["frontier", "context_digest"] {
            let old = format!("\"{field}\":{}", value[field]);
            let new = format!("\"{field}\":{}", serde_json::json!(vec![0u8; 32]));
            cases.push(bytes.replacen(&old, &new, 1));
        }
    }
    let pristine = durable_rows(&store);
    for bad in cases {
        assert_ne!(
            bad, bytes,
            "negative must actually modify the canonical payload"
        );
        store
            .conn
            .execute(
                "UPDATE gap_qualifications SET record=?1,fingerprint=?2",
                rusqlite::params![bad, sha2::Sha256::digest(bad.as_bytes()).as_slice()],
            )
            .unwrap();
        let corrupt = durable_rows(&store);
        assert!(
            store
                .run_snapshot(&report.record.request.identity().run)
                .is_err(),
            "malformed Q accepted, wire={wire}"
        );
        assert_eq!(durable_rows(&store), corrupt);
        store
            .conn
            .execute(
                "UPDATE gap_qualifications SET record=?1,fingerprint=?2",
                rusqlite::params![bytes, fingerprint],
            )
            .unwrap();
        assert_eq!(durable_rows(&store), pristine);
        assert!(store
            .run_snapshot(&report.record.request.identity().run)
            .is_ok());
    }
}

#[test]
fn gap_close_reuses_prewrite_history_and_validates_postwrite() {
    let _diagnostics = crate::capture_diagnostics::Guard::new();
    let h = ScopeHarness::new(true);
    let (mut store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let mut old_close = None;
    let first = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
                let snapshot = store.group_snapshot(&root.request.identity().run).unwrap();
                let proof = snapshot.certify_historical_empty(&h.driver).unwrap();
                old_close = Some((snapshot, proof));
            }
        },
    )
    .expect("genuine first published close prerequisite");
    assert!(first.record.closed);
    let first_run = first.record.request.identity().run.to_string();
    let q: (String, Vec<u8>) = store
        .conn
        .query_row(
            "SELECT record,fingerprint FROM gap_qualifications WHERE run=?1",
            [&first_run],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let (old_snapshot, old_proof) = old_close.unwrap();
    let mut command = h.command.clone();
    command.run_id = uuid::Uuid::now_v7();
    std::fs::remove_file(h.temp.path().join("properties")).unwrap();
    std::fs::remove_file(h.temp.path().join("executed")).unwrap();
    let mut counter = None;
    let mut measured = None;
    let mut awaiting = false;
    let second = crate::supervisor::supervise_off(
        &h.config, command, &h.driver, Some(h.io()), &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::Intent {
                let before = durable_rows(&store);
                assert_eq!(store.close_supervised_group(&old_snapshot, &old_proof).unwrap(), crate::run_journal::Transition::Existing);
                assert_eq!(durable_rows(&store), before, "older Existing close remains passive with a current successor");
            }
            if boundary == Boundary::RootTerminal {
                h.empty(root);
                assert_eq!(root.outcome, Some(RootOutcome::Completed));
                for case in ["cursor", "qualification", "postwrite"] {
                    let snapshot = store.group_snapshot(&root.request.identity().run).unwrap();
                    let proof = snapshot.certify_historical_empty(&h.driver).unwrap();
                    let before = durable_rows(&store);
                    match case {
                        "cursor" => { assert_eq!(store.conn.execute("UPDATE gap_eligibility SET revision=5 WHERE revision=4 AND disposition='unavailable'", []).unwrap(), 1); }
                        "qualification" => { assert_eq!(store.conn.execute("UPDATE gap_qualifications SET record='{' WHERE run=?1", [&first_run]).unwrap(), 1); }
                        "postwrite" => {
                            // Corrupt only the actual close's cursor UPDATE. No
                            // RAISE/abort: the coherent postwrite validator must
                            // reject closed+unavailable and roll back every row.
                            store.conn.execute_batch("CREATE TEMP TRIGGER corrupt_close_cursor AFTER UPDATE OF disposition ON gap_eligibility WHEN NEW.disposition='blocked' BEGIN UPDATE gap_eligibility SET disposition='unavailable' WHERE checkout=NEW.checkout; END").unwrap();
                        }
                        _ => unreachable!(),
                    }
                    let corrupt = durable_rows(&store);
                    let observed = crate::run_journal::CloseHistoryCounter::new();
                    assert!(store.close_supervised_group(&snapshot, &proof).is_err(), "close refuses {case}");
                    let attempts = observed.take();
                    drop(observed);
                    if case == "postwrite" {
                        assert_eq!(attempts.len(), 1);
                        assert!(attempts[0].3 >= 4, "postwrite rejection must reach a second complete two-node fold");
                    }
                    assert_eq!(durable_rows(&store), corrupt, "failed close never mutates/repairs {case}");
                    match case {
                        "cursor" => { store.conn.execute("UPDATE gap_eligibility SET revision=4 WHERE revision=5", []).unwrap(); }
                        "qualification" => { store.conn.execute("UPDATE gap_qualifications SET record=?1 WHERE run=?2", (&q.0, &first_run)).unwrap(); }
                        "postwrite" => { store.conn.execute_batch("DROP TRIGGER corrupt_close_cursor").unwrap(); }
                        _ => unreachable!(),
                    }
                    assert_eq!(durable_rows(&store), before);
                }
                counter = Some(crate::run_journal::CloseHistoryCounter::new());
            }
            if boundary == Boundary::Closed {
                let collector = counter.take().expect("close counter armed before actual live close");
                measured = Some(collector.take());
                drop(collector);
                assert!(root.closed && !root.recovery_hold);
                assert_eq!(root.outcome, Some(RootOutcome::Completed));
                assert_eq!(store.conn.query_row("SELECT revision,disposition,qualification FROM gap_eligibility", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?))).unwrap(), (5, "awaiting_qualification".into(), None));
                assert_eq!(store.conn.query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
                assert_eq!(store.conn.query_row("SELECT state,ready FROM checkouts", [], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))).unwrap(), ("held".into(), false));
                assert_eq!(store.conn.query_row("SELECT successor_run,successor_revision FROM gap_qualifications WHERE run=?1", [&first_run], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap(), (root.request.identity().run.to_string(), 4));
                assert_eq!(store.conn.query_row("SELECT record,fingerprint FROM gap_qualifications WHERE run=?1", [&first_run], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))).unwrap(), q);
                awaiting = true;
            }
        },
    ).expect("genuine second close and subsequent publication prerequisite");
    assert!(awaiting && second.record.closed && !second.checkout_ready);
    assert_eq!(
        store
            .conn
            .query_row(
                "SELECT revision,disposition,qualification FROM gap_eligibility",
                [],
                |r| Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?
                ))
            )
            .unwrap(),
        (
            6,
            "available".into(),
            second.record.request.identity().run.to_string()
        )
    );
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    let before = durable_rows(&store);
    assert_eq!(
        store
            .close_supervised_group(&old_snapshot, &old_proof)
            .unwrap(),
        crate::run_journal::Transition::Existing
    );
    assert_eq!(durable_rows(&store), before);
    assert_eq!(
        measured.unwrap(),
        vec![(4, 2, 2, 4)],
        "Changed close needs one prewrite and one mandatory postwrite history pass"
    );
}

#[test]
fn gap_report_reuses_validated_history_in_one_snapshot() {
    let _diagnostics = crate::capture_diagnostics::Guard::new();
    let (h, store, first) = genuinely_published_initial();
    let mut command = h.command.clone();
    command.run_id = uuid::Uuid::now_v7();
    std::fs::remove_file(h.temp.path().join("properties")).unwrap();
    std::fs::remove_file(h.temp.path().join("executed")).unwrap();
    let second = crate::supervisor::supervise_off(
        &h.config,
        command,
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .expect("genuine two-root report prerequisite");
    assert!(first.record.closed && second.record.closed);
    let run = &second.record.request.identity().run;
    let pristine = durable_rows(&store);
    crate::gap_continuation::take_history_counts();
    let actual =
        crate::supervisor::report_for_test(&store, run, second.existing, second.exit_code).unwrap();
    let counts = crate::gap_continuation::take_history_counts();
    assert_eq!(actual.record, second.record);
    assert_eq!(
        (
            actual.gap,
            actual.existing,
            actual.exit_code,
            actual.lease_charged,
            actual.task_open,
            actual.checkout_ready,
            actual.attribution_not_configured,
            actual.capture_unfrozen,
            actual.capture_delivery
        ),
        (
            second.gap,
            second.existing,
            second.exit_code,
            second.lease_charged,
            second.task_open,
            second.checkout_ready,
            second.attribution_not_configured,
            second.capture_unfrozen,
            second.capture_delivery
        )
    );
    assert!(!actual.capture_unfrozen && actual.capture_delivery.is_none());
    assert_eq!(durable_rows(&store), pristine);
    assert_eq!(
        counts,
        (2, 2, 2, 2),
        "one complete two-root history fold in report's single snapshot, not four"
    );

    let first_run = first.record.request.identity().run.to_string();
    let (q, fingerprint): (String, Vec<u8>) = store
        .conn
        .query_row(
            "SELECT record,fingerprint FROM gap_qualifications WHERE run=?1",
            [&first_run],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let sql = rusqlite::Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    let orphan = uuid::Uuid::now_v7().to_string();
    for case in [
        "cursor",
        "qualification",
        "capture",
        "certificate",
        "raw-orphan",
    ] {
        match case {
            "cursor" => {
                store
                    .conn
                    .execute("UPDATE gap_eligibility SET revision=7 WHERE revision=6", [])
                    .unwrap();
            }
            "qualification" => {
                store
                    .conn
                    .execute(
                        "UPDATE gap_qualifications SET record='{' WHERE run=?1",
                        [&first_run],
                    )
                    .unwrap();
            }
            "capture" => {
                let spec = super::mixed_history_spec(
                    h.temp.path(),
                    &h.config,
                    &h.allocation,
                    &second.record.request,
                );
                spec.begin_request().encode().unwrap();
                spec.expected_git().validate().unwrap();
                super::inject_unprepared_capture(&store, &second.record.request, &spec);
            }
            "certificate" => {
                sql.execute(
                    "INSERT INTO capture_readiness VALUES(?1,?2,'{',0)",
                    (h.allocation.checkout.to_string(), run.to_string()),
                )
                .unwrap();
            }
            "raw-orphan" => {
                sql.execute(
                    "INSERT INTO gap_qualifications VALUES(?1,?2,'{',zeroblob(32),NULL,NULL)",
                    (&orphan, h.allocation.checkout.to_string()),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let corrupt = durable_rows(&store);
        assert_ne!(
            corrupt, pristine,
            "negative fixture changes authority: {case}"
        );
        assert!(
            crate::supervisor::report_for_test(&store, run, true, None).is_err(),
            "report must refuse {case}"
        );
        assert_eq!(durable_rows(&store), corrupt, "report never repairs {case}");
        match case {
            "cursor" => {
                store
                    .conn
                    .execute("UPDATE gap_eligibility SET revision=6 WHERE revision=7", [])
                    .unwrap();
            }
            "qualification" => {
                store
                    .conn
                    .execute(
                        "UPDATE gap_qualifications SET record=?1,fingerprint=?2 WHERE run=?3",
                        rusqlite::params![q, fingerprint, first_run],
                    )
                    .unwrap();
            }
            "capture" => {
                store
                    .conn
                    .execute("DELETE FROM capture_runs WHERE run=?1", [run.to_string()])
                    .unwrap();
            }
            "certificate" => {
                sql.execute(
                    "DELETE FROM capture_readiness WHERE checkout=?1",
                    [h.allocation.checkout.to_string()],
                )
                .unwrap();
            }
            "raw-orphan" => {
                sql.execute("DELETE FROM gap_qualifications WHERE run=?1", [&orphan])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(durable_rows(&store), pristine);
        let restored = crate::supervisor::report_for_test(&store, run, true, None).unwrap();
        assert_eq!(restored.record, second.record);
        assert!(restored.existing && restored.exit_code.is_none());
        assert!(!restored.capture_unfrozen && restored.capture_delivery.is_none());
    }

    // Non-Gap paths keep their original capture semantics. Genuine ordinary
    // admission and unprepared capture admission, without producer invocation.
    let (_temp, config, allocation, _, _) = super::materialized(false);
    let (mut ordinary, lease) = crate::allocate::locked(&config).unwrap();
    drop(lease);
    let root = crate::test_run_fixture::request(allocation.checkout);
    assert_eq!(
        ordinary.begin_run(&root).unwrap(),
        crate::run_journal::BeginRun::Created
    );
    let before = durable_rows(&ordinary);
    let report =
        crate::supervisor::report_for_test(&ordinary, &root.identity().run, true, None).unwrap();
    assert_eq!(report.record.request, root);
    assert!(report.gap.is_none() && report.checkout_ready && report.attribution_not_configured);
    assert!(report.lease_charged && report.task_open && report.existing);
    assert!(!report.capture_unfrozen && report.capture_delivery.is_none());
    assert_eq!(durable_rows(&ordinary), before);

    let (_temp, config, _, root, spec) = crate::capture_preparation::tests::qualified_fixture();
    let (captured, created) = crate::capture_setup::begin(&config, &root, &spec).unwrap();
    assert!(matches!(
        created,
        crate::capture_journal::BeginCapturedRun::Created(_)
    ));
    let before = durable_rows(&captured);
    let report =
        crate::supervisor::report_for_test(&captured, &root.identity().run, true, None).unwrap();
    assert_eq!(report.record.request, root);
    assert!(report.gap.is_none() && report.capture_unfrozen && report.capture_delivery.is_none());
    assert!(!report.attribution_not_configured);
    assert!(report.lease_charged && report.task_open && report.existing);
    assert_eq!(durable_rows(&captured), before);
    captured
        .conn
        .execute(
            "INSERT INTO capture_finalizations VALUES(?1,'{',NULL,1)",
            [root.identity().run.to_string()],
        )
        .unwrap();
    let corrupt = durable_rows(&captured);
    assert!(
        crate::supervisor::report_for_test(&captured, &root.identity().run, true, None).is_err()
    );
    assert_eq!(durable_rows(&captured), corrupt);
    captured
        .conn
        .execute(
            "DELETE FROM capture_finalizations WHERE run=?1",
            [root.identity().run.to_string()],
        )
        .unwrap();
    assert_eq!(durable_rows(&captured), before);
    assert!(
        crate::supervisor::report_for_test(&captured, &root.identity().run, true, None)
            .unwrap()
            .capture_unfrozen
    );
}

#[test]
fn recovery_enumeration_validates_complete_gap_histories() {
    recovery_enumeration_with_counts(&[2]);
}

#[test]
#[ignore = "Deferred pilot performance/budget qualification; run explicitly with --ignored"]
fn recovery_enumeration_large_history_qualification() {
    recovery_enumeration_with_counts(&[48]);
}

// Both tiers retain the initial cursor case and every corruption/order control.
fn recovery_enumeration_with_counts(counts: &[usize]) {
    let _diagnostics = crate::capture_diagnostics::Guard::new();
    let mut missed = Vec::new();
    {
        let (_temp, config, allocation, root, argv) = super::materialized(true);
        let (store, created) = super::super::begin(&config, &root, &argv).unwrap();
        assert!(matches!(created, super::super::BeginGap::Created(_)));
        drop(created);
        let original = store.run_snapshot(&root.identity().run).unwrap().unwrap();
        assert!(!original.closed);
        assert_eq!(store.recovery_runs().unwrap(), vec![original.clone()]);
        let pristine = durable_rows(&store);
        assert_eq!(store.conn.execute(
            "UPDATE gap_eligibility SET revision=2 WHERE checkout=?1 AND latest_run=?2 AND revision=1 AND disposition='unavailable' AND qualification IS NULL",
            (allocation.checkout.to_string(), root.identity().run.to_string()),
        ).unwrap(), 1);
        let corrupt = durable_rows(&store);
        if store.recovery_runs().is_ok() {
            missed.push("positive impossible initial revision accepted".to_owned());
        }
        assert_eq!(
            durable_rows(&store),
            corrupt,
            "enumeration never repairs cursor"
        );
        assert_eq!(
            store
                .conn
                .execute(
                    "UPDATE gap_eligibility SET revision=1 WHERE checkout=?1 AND revision=2",
                    [allocation.checkout.to_string()],
                )
                .unwrap(),
            1
        );
        assert_eq!(durable_rows(&store), pristine);
        assert_eq!(store.recovery_runs().unwrap(), vec![original]);
    }
    assert!(
        missed.is_empty(),
        "initial recovery enumeration accepted impossible unavailable cursor revision: {missed:?}"
    );

    for &count in counts {
        let h = ScopeHarness::new(true);
        let (mut store, lease) = crate::allocate::locked(&h.config).unwrap();
        drop(lease);
        let mut closed = Vec::new();
        for index in 0..count {
            let mut command = h.command.clone();
            if index != 0 {
                command.run_id = uuid::Uuid::now_v7();
                std::fs::remove_file(h.temp.path().join("properties")).unwrap();
                std::fs::remove_file(h.temp.path().join("executed")).unwrap();
            }
            let report = crate::supervisor::supervise_off(
                &h.config,
                command,
                &h.driver,
                Some(h.io()),
                &CancelToken::default(),
                |boundary, root| {
                    if boundary == Boundary::RootTerminal {
                        h.empty(root);
                    }
                },
            ).unwrap_or_else(|error| panic!("genuine closed required chain prerequisite count={count} index={index}: {error:?}"));
            assert!(report.record.closed && !report.existing);
            assert_eq!(report.record.outcome, Some(RootOutcome::Completed));
            closed.push(report.record);
        }
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            i64::try_from(count).expect("2/48-root workload fits SQLite integer domain")
        );
        let first = closed[0].request.identity().run.to_string();
        let (q, fingerprint, claim): (String, Vec<u8>, i64) = store
            .conn
            .query_row(
                "SELECT record,fingerprint,successor_revision FROM gap_qualifications WHERE run=?1",
                [&first],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(claim, 4);
        let pristine = durable_rows(&store);
        for case in ["payload", "fingerprint", "claim"] {
            match case {
                "payload" => {
                    store
                        .conn
                        .execute(
                            "UPDATE gap_qualifications SET record='{' WHERE run=?1",
                            [&first],
                        )
                        .unwrap();
                }
                "fingerprint" => {
                    store
                        .conn
                        .execute(
                            "UPDATE gap_qualifications SET fingerprint=zeroblob(32) WHERE run=?1",
                            [&first],
                        )
                        .unwrap();
                }
                "claim" => {
                    store
                        .conn
                        .execute(
                            "UPDATE gap_qualifications SET successor_revision=5 WHERE run=?1",
                            [&first],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let corrupt = durable_rows(&store);
            if store.recovery_runs().is_ok() {
                missed.push(format!(
                    "closed {count}-root {case} corruption filtered before validation"
                ));
            }
            assert_eq!(durable_rows(&store), corrupt);
            store.conn.execute(
                "UPDATE gap_qualifications SET record=?1,fingerprint=?2,successor_revision=?3 WHERE run=?4",
                rusqlite::params![q, fingerprint, claim, first],
            ).unwrap();
            assert_eq!(durable_rows(&store), pristine);
            assert!(store.recovery_runs().unwrap().is_empty());
        }

        // Distinct affected checkouts and ordinary/captured controls share the
        // same authority. Actual admissions, never fabricated positive Q/live.
        let mut expected = Vec::new();
        let mut captured = None;
        for label in ["open-a", "ordinary", "captured", "open-b"] {
            let mut config = h.config.clone();
            if label == "ordinary" {
                config.allocation.as_mut().unwrap().capture_sink = None;
            }
            let mut start = h.allocation.request.clone();
            start.operation = uuid::Uuid::now_v7();
            start.task = label.into();
            start.branch = Some(label.into());
            let allocation = crate::allocate::start(&config, start).unwrap();
            let mut identity = closed[0].request.identity().clone();
            identity.checkout =
                work_contract::CheckoutId::parse(&allocation.checkout.to_string()).unwrap();
            identity.run = work_contract::RunId::generate();
            identity.group = work_contract::GroupId::generate();
            identity.run_ref = work_contract::RunRef::parse(label).unwrap();
            let mut input = closed[0].request.input().clone();
            if matches!(label, "ordinary" | "captured") {
                input.attribution = None;
            }
            let root = crate::run_journal::RootRunRequest::new(identity, input).unwrap();
            match label {
                "ordinary" => assert_eq!(
                    store.begin_run(&root).unwrap(),
                    crate::run_journal::BeginRun::Created
                ),
                "captured" => {
                    let spec = config
                        .capture_spec(
                            &root,
                            &allocation,
                            uuid::Uuid::now_v7(),
                            vec![label.into()],
                            None,
                        )
                        .unwrap();
                    let (_, created) = crate::capture_setup::begin(&config, &root, &spec).unwrap();
                    assert!(matches!(
                        created,
                        crate::capture_journal::BeginCapturedRun::Created(_)
                    ));
                    let bytes: String = store
                        .conn
                        .query_row(
                            "SELECT spec FROM capture_runs WHERE run=?1",
                            [root.identity().run.to_string()],
                            |r| r.get(0),
                        )
                        .unwrap();
                    captured = Some((root.identity().run.to_string(), bytes));
                }
                _ => {
                    let (_, created) =
                        super::super::begin(&config, &root, &h.command.argv).unwrap();
                    assert!(matches!(created, super::super::BeginGap::Created(_)));
                }
            }
            expected.push(store.run_snapshot(&root.identity().run).unwrap().unwrap());
        }
        let pristine = durable_rows(&store);
        let (capture_run, capture_spec) = captured.unwrap();
        store
            .conn
            .execute(
                "UPDATE capture_runs SET spec='{' WHERE run=?1",
                [&capture_run],
            )
            .unwrap();
        let corrupt_capture = durable_rows(&store);
        crate::gap_continuation::take_history_counts();
        assert_eq!(
            store.recovery_runs().unwrap(),
            expected,
            "original insertion order, closed omitted, no unrelated capture JSON decode"
        );
        let counts = crate::gap_continuation::take_history_counts();
        if counts != (count + 2, count, count, count + 2) {
            missed.push(format!("{count}-root enumeration history counts {counts:?}: expected one fold per distinct affected checkout"));
        }
        assert_eq!(durable_rows(&store), corrupt_capture);
        store
            .conn
            .execute(
                "UPDATE capture_runs SET spec=?1 WHERE run=?2",
                (&capture_spec, &capture_run),
            )
            .unwrap();
        assert_eq!(durable_rows(&store), pristine);

        // Existing authority-wide namespace and closed-roster refusals remain.
        let event: String = store
            .conn
            .query_row(
                "SELECT event_id FROM attribution_gaps WHERE run=?1",
                [&first],
                |r| r.get(0),
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE attribution_gaps SET event_id=checkout WHERE run=?1",
                [&first],
            )
            .unwrap();
        let corrupt = durable_rows(&store);
        assert!(store.recovery_runs().is_err());
        assert_eq!(durable_rows(&store), corrupt);
        store
            .conn
            .execute(
                "UPDATE attribution_gaps SET event_id=?1 WHERE run=?2",
                (&event, &first),
            )
            .unwrap();
        let group = closed[0].request.identity().group.to_string();
        assert_eq!(
            store
                .conn
                .execute(
                    "UPDATE run_groups SET child_count=1 WHERE id=?1 AND child_count=0",
                    [&group]
                )
                .unwrap(),
            1
        );
        let corrupt = durable_rows(&store);
        assert!(store.recovery_runs().is_err());
        assert_eq!(durable_rows(&store), corrupt);
        store
            .conn
            .execute("UPDATE run_groups SET child_count=0 WHERE id=?1", [&group])
            .unwrap();
        assert_eq!(durable_rows(&store), pristine);
        assert_eq!(store.recovery_runs().unwrap(), expected);
    }
    assert!(
        missed.is_empty(),
        "incomplete recovery enumeration: {missed:?}"
    );
}

#[test]
fn conflicting_cursor_claim_graphs_refuse_without_repair() {
    let (temp, config, allocation, root, argv) = super::materialized(true);
    let (store, created) = super::super::begin(&config, &root, &argv).unwrap();
    assert!(matches!(created, super::super::BeginGap::Created(_)));
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_eligibility", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "real initialized-cursor prerequisite"
    );
    drop(created);
    let before = durable_rows(&store);
    let sql = rusqlite::Connection::open(temp.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    let mut missed = Vec::new();
    for (name, statement) in [
        (
            "missing latest",
            "UPDATE gap_eligibility SET latest_run='missing'",
        ),
        (
            "unavailable revision",
            "UPDATE gap_eligibility SET revision=2",
        ),
        ("zero revision", "UPDATE gap_eligibility SET revision=0"),
        (
            "wrong disposition",
            "UPDATE gap_eligibility SET disposition='ready'",
        ),
        (
            "available without Q",
            "UPDATE gap_eligibility SET disposition='available'",
        ),
        (
            "unavailable pointer",
            "UPDATE gap_eligibility SET qualification=latest_run",
        ),
        (
            "awaiting open",
            "UPDATE gap_eligibility SET disposition='awaiting_qualification',revision=2",
        ),
        (
            "blocked same epoch",
            "UPDATE gap_eligibility SET disposition='blocked'",
        ),
    ] {
        sql.execute_batch(statement).unwrap();
        let corrupt = durable_rows(&store);
        if store.run_snapshot(&root.identity().run).is_ok() {
            missed.push(name);
        }
        assert_eq!(durable_rows(&store), corrupt, "no repair: {name}");
        sql.execute("UPDATE gap_eligibility SET latest_run=?1,revision=1,disposition='unavailable',qualification=NULL WHERE checkout=?2", (root.identity().run.to_string(), allocation.checkout.to_string())).unwrap();
        assert_eq!(durable_rows(&store), before);
    }
    assert!(
        missed.is_empty(),
        "invalid cursor states accepted: {missed:?}"
    );
    qualification_negatives(false);
    linked_graph_negatives();
}

fn linked_graph_negatives() {
    use sha2::Digest;
    let (h, store, first) = genuinely_published_initial();
    let mut records = vec![first.record];
    for _ in 0..2 {
        let mut command = h.command.clone();
        command.run_id = uuid::Uuid::now_v7();
        std::fs::remove_file(h.temp.path().join("properties")).unwrap();
        std::fs::remove_file(h.temp.path().join("executed")).unwrap();
        let report = crate::supervisor::supervise_off(
            &h.config,
            command,
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, root| {
                if boundary == Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        )
        .expect("genuine three-node claim graph prerequisite");
        assert!(report.record.closed);
        records.push(report.record);
    }
    let ids = records
        .iter()
        .map(|r| r.request.identity().run.to_string())
        .collect::<Vec<_>>();
    let sql = rusqlite::Connection::open(h.temp.path().join("private/store.sqlite")).unwrap();
    sql.execute_batch(
        "PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;
        CREATE TEMP TABLE preserved_gaps AS SELECT * FROM attribution_gaps;
        CREATE TEMP TABLE preserved_q AS SELECT * FROM gap_qualifications;
        CREATE TEMP TABLE preserved_e AS SELECT * FROM gap_eligibility;",
    )
    .unwrap();
    let pristine = durable_rows(&store);
    for case in [
        "missing-cursor",
        "missing-Q",
        "fingerprint",
        "wrong-checkout",
        "half-claim",
        "wrong-revision",
        "unclaimed-prefix",
        "cycle",
        "unreachable",
        "branch-link",
        "latest",
        "overflow",
    ] {
        match case {
            "missing-cursor" => {
                sql.execute("DELETE FROM gap_eligibility", []).unwrap();
            }
            "missing-Q" => {
                sql.execute("DELETE FROM gap_qualifications WHERE run=?1", [&ids[0]])
                    .unwrap();
            }
            "fingerprint" => {
                sql.execute(
                    "UPDATE gap_qualifications SET fingerprint=zeroblob(32) WHERE run=?1",
                    [&ids[0]],
                )
                .unwrap();
            }
            "wrong-checkout" => {
                sql.execute(
                    "UPDATE gap_qualifications SET checkout=?1 WHERE run=?2",
                    (uuid::Uuid::now_v7().to_string(), &ids[0]),
                )
                .unwrap();
            }
            "half-claim" => {
                sql.execute(
                    "UPDATE gap_qualifications SET successor_revision=NULL WHERE run=?1",
                    [&ids[0]],
                )
                .unwrap();
            }
            "wrong-revision" => {
                sql.execute(
                    "UPDATE gap_qualifications SET successor_revision=5 WHERE run=?1",
                    [&ids[0]],
                )
                .unwrap();
            }
            "unclaimed-prefix" => {
                sql.execute("UPDATE gap_qualifications SET successor_run=NULL,successor_revision=NULL WHERE run=?1", [&ids[0]]).unwrap();
            }
            "cycle" => {
                sql.execute("UPDATE gap_qualifications SET successor_run=?1,successor_revision=10 WHERE run=?2", (&ids[0], &ids[2])).unwrap();
            }
            "unreachable" | "branch-link" => {
                let bytes: String = sql
                    .query_row(
                        "SELECT record FROM attribution_gaps WHERE run=?1",
                        [&ids[2]],
                        |r| r.get(0),
                    )
                    .unwrap();
                let mut wire: serde_json::Value = serde_json::from_str(&bytes).unwrap();
                wire["context"]["continuation"]["predecessor"] = if case == "unreachable" {
                    uuid::Uuid::now_v7().to_string()
                } else {
                    ids[0].clone()
                }
                .into();
                let gap: super::super::GapRecord = serde_json::from_value(wire).unwrap();
                let bytes = super::super::encode(&gap).unwrap();
                sql.execute(
                    "UPDATE attribution_gaps SET record=?1,fingerprint=?2 WHERE run=?3",
                    rusqlite::params![
                        bytes,
                        sha2::Sha256::digest(bytes.as_bytes()).as_slice(),
                        ids[2]
                    ],
                )
                .unwrap();
            }
            "latest" => {
                sql.execute("UPDATE gap_eligibility SET latest_run=?1", [&ids[0]])
                    .unwrap();
            }
            "overflow" => {
                sql.execute(
                    "UPDATE gap_eligibility SET revision=9223372036854775807",
                    [],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let corrupt = durable_rows(&store);
        assert!(
            store
                .run_snapshot(&records[0].request.identity().run)
                .is_err(),
            "corrupt claim graph accepted: {case}"
        );
        assert_eq!(durable_rows(&store), corrupt, "no repair: {case}");
        sql.execute_batch("BEGIN; DELETE FROM gap_eligibility; DELETE FROM gap_qualifications; DELETE FROM attribution_gaps;
            INSERT INTO attribution_gaps SELECT * FROM preserved_gaps;
            INSERT INTO gap_qualifications SELECT * FROM preserved_q;
            INSERT INTO gap_eligibility SELECT * FROM preserved_e; COMMIT;").unwrap();
        assert_eq!(durable_rows(&store), pristine);
        for record in &records {
            assert_eq!(
                store.run_snapshot(&record.request.identity().run).unwrap(),
                Some(record.clone())
            );
        }
    }
}

fn contended_original_windows() {
    // Native holders preopened before timed observations. The SQLite writer is
    // explicitly adversarial fixture SQL, not a cooperative lease bypass.
    for publication in [false, true] {
        let (h, store, prefix) = genuinely_published_initial();
        let holder = crate::store::Store::open_existing_registered_mut(
            h.config.trusted_registry.as_ref().unwrap(),
            h.config.store_dir.as_ref().unwrap(),
            &h.config.roots,
        )
        .unwrap();
        let mut holder = Some(holder);
        let waiter = std::rc::Rc::new(std::cell::RefCell::new(None));
        let joined = waiter.clone();
        let mut gate = move || {
            std::thread::sleep(std::time::Duration::from_millis(1750));
            // Move the PREOPENED native holder at the actual boundary. Do not
            // start an unrelated 2s channel deadline before the actor executes.
            let holder = holder.take().unwrap();
            let (ready, wait) = std::sync::mpsc::channel();
            *joined.borrow_mut() = Some(std::thread::spawn(move || {
                let lease = if publication {
                    holder.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
                    None
                } else {
                    Some(holder.authority_lease().unwrap())
                };
                ready.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(350));
                if publication {
                    holder.conn.execute_batch("COMMIT").unwrap();
                }
                drop(lease);
            }));
            wait.recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
        };
        let before = durable_rows(&store);
        let mut command = h.command.clone();
        command.run_id = uuid::Uuid::now_v7();
        let run = work_contract::RunId::parse(&command.run_id.to_string()).unwrap();
        if publication {
            let _observer = crate::gap_continuation::observing_publication(move |stage| {
                if stage == "before_lease" {
                    gate();
                }
            });
            std::fs::remove_file(h.temp.path().join("properties")).unwrap();
            std::fs::remove_file(h.temp.path().join("executed")).unwrap();
            let result = crate::supervisor::supervise_off(
                &h.config,
                command,
                &h.driver,
                Some(h.io()),
                &CancelToken::default(),
                |boundary, root| {
                    if boundary == Boundary::RootTerminal {
                        h.empty(root);
                    }
                },
            );
            waiter
                .borrow_mut()
                .take()
                .expect("actual SQL holder reached")
                .join()
                .unwrap();
            assert_eq!(
                result
                    .expect_err("contended original publication window expires")
                    .to_string(),
                "operation request conflicts"
            );
            let root = store.run_snapshot(&run).unwrap().unwrap();
            assert!(
                root.closed && !root.recovery_hold && root.outcome == Some(RootOutcome::Completed)
            );
            assert_eq!(
                store
                    .conn
                    .query_row(
                        "SELECT revision,disposition FROM gap_eligibility",
                        [],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                    )
                    .unwrap(),
                (5, "awaiting_qualification".into())
            );
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        } else {
            let _observer = super::observing_admission(move |stage, _| {
                if stage == "reinspect" {
                    gate();
                }
            });
            let mut identity = prefix.record.request.identity().clone();
            identity.run = run;
            identity.group = work_contract::GroupId::generate();
            identity.run_ref = work_contract::RunRef::parse("contended-admission").unwrap();
            let root = crate::run_journal::RootRunRequest::new(
                identity,
                prefix.record.request.input().clone(),
            )
            .unwrap();
            let result = super::super::begin(&h.config, &root, &command.argv);
            waiter
                .borrow_mut()
                .take()
                .expect("actual lease holder reached")
                .join()
                .unwrap();
            assert!(
                matches!(result, Err(crate::store::StoreError::Conflict)),
                "must wait then reject original age, not renew proof or fail before holder"
            );
            assert_eq!(
                durable_rows(&store),
                before,
                "expired admission rolls back all rows and claim"
            );
        }
    }
}

fn continuation_release_boundaries() {
    for case in ["kernel-age", "release-lease", "boot", "registry"] {
        let (h, store, _) = genuinely_published_initial();
        let holder = crate::store::Store::open_existing_registered_mut(
            h.config.trusted_registry.as_ref().unwrap(),
            h.config.store_dir.as_ref().unwrap(),
            &h.config.roots,
        )
        .unwrap();
        let mut holder = Some(holder);
        let waiter = std::rc::Rc::new(std::cell::RefCell::new(None));
        let joined = waiter.clone();
        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = reached.clone();
        super::RELEASE_OBSERVER.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                observed.set(true);
                if case == "kernel-age" {
                    std::thread::sleep(std::time::Duration::from_millis(1200));
                }
                if case == "release-lease" {
                    std::thread::sleep(std::time::Duration::from_millis(1850));
                    let holder = holder.take().unwrap();
                    let (ready, wait) = std::sync::mpsc::channel();
                    *joined.borrow_mut() = Some(std::thread::spawn(move || {
                        let lease = holder.authority_lease().unwrap();
                        ready.send(()).unwrap();
                        std::thread::sleep(std::time::Duration::from_millis(300));
                        drop(lease);
                    }));
                    wait.recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                }
            }))
        });
        let observer = super::ReleaseObserverGuard;
        let mut command = h.command.clone();
        command.run_id = uuid::Uuid::now_v7();
        let run = work_contract::RunId::parse(&command.run_id.to_string()).unwrap();
        std::fs::remove_file(h.temp.path().join("properties")).unwrap();
        std::fs::remove_file(h.temp.path().join("executed")).unwrap();
        let result = crate::supervisor::supervise_off(
            &h.config,
            command,
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, _| {
                if boundary == Boundary::PermitAttempt {
                    match case {
                    "kernel-age" => executable(&h.temp.path().join("manager"), format!("#!/bin/sh\n/usr/bin/sleep 0.55\nexec /usr/bin/cat '{}/properties'\n", h.temp.path().display())),
                    "boot" => std::fs::write(h.temp.path().join("proc/sys/kernel/random/boot_id"), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
                    "registry" => std::fs::write(h.temp.path().join("registry.json"), "{}").unwrap(),
                    _ => (),
                }
                }
            },
        );
        drop(observer);
        if let Some(worker) = waiter.borrow_mut().take() {
            worker.join().unwrap();
        }
        assert!(
            result.is_err() && !h.temp.path().join("executed").exists(),
            "continuation release {case}"
        );
        if case != "registry" {
            assert!(
                reached.get(),
                "fresh actual release proof before final gate: {case}"
            );
        }
        let root = store.run_snapshot(&run).unwrap().unwrap();
        assert!(!root.closed && root.outcome.is_none());
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM writers", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    // Actual Created continuation, not a release proof reconstructed from Q.
    let (h, store, prefix) = genuinely_published_initial();
    let mut identity = prefix.record.request.identity().clone();
    identity.run = work_contract::RunId::generate();
    identity.group = work_contract::GroupId::generate();
    identity.run_ref = work_contract::RunRef::parse("foreign-authority").unwrap();
    let root =
        crate::run_journal::RootRunRequest::new(identity, prefix.record.request.input().clone())
            .unwrap();
    let (_, began) = super::super::begin(&h.config, &root, &h.command.argv).unwrap();
    let super::super::BeginGap::Created(live) = began else {
        panic!("actual continuation live prerequisite")
    };
    let (_temp, foreign, _) = crate::test_run_fixture::fixture();
    let proof = live.release_proof().unwrap();
    let lease = foreign.authority_lease().unwrap();
    assert!(proof.validate_authority(&foreign, &lease).is_err());
    drop(lease);
    drop(proof);
    super::physical_fixture::replace_directory(&h.allocation.destination);
    assert!(
        live.release_proof().is_err(),
        "admitted continuation rejects replaced checkout before release"
    );
    assert_eq!(
        store
            .conn
            .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

fn continuation_admission_physics() {
    for case in ["registry", "private-directory"] {
        let (h, store, prefix) = genuinely_published_initial();
        let registry = h.config.capture.as_ref().unwrap().registry.clone();
        let private = h
            .allocation
            .identity
            .as_ref()
            .unwrap()
            .private_git_dir
            .clone();
        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = reached.clone();
        let _observer = super::observing_admission(move |stage, _| {
            if stage == "reinspect" {
                observed.set(true);
                if case == "registry" {
                    std::fs::write(&registry, "{}").unwrap();
                } else {
                    super::physical_fixture::replace_directory(&private);
                }
            }
        });
        let mut identity = prefix.record.request.identity().clone();
        identity.run = work_contract::RunId::generate();
        identity.group = work_contract::GroupId::generate();
        identity.run_ref = work_contract::RunRef::parse("late-physical").unwrap();
        let root = crate::run_journal::RootRunRequest::new(
            identity,
            prefix.record.request.input().clone(),
        )
        .unwrap();
        let before = durable_rows(&store);
        assert!(super::super::begin(&h.config, &root, &h.command.argv).is_err());
        assert!(
            reached.get(),
            "actual first inspection happened before mutation"
        );
        assert_eq!(
            durable_rows(&store),
            before,
            "late {case} must not claim Q or insert Root"
        );
    }
    // Actual released actor advances Q's HEAD anchor. Parent Git operations
    // below are ONLY explicit rewind/divergence/branch negative fixtures.
    let h = ScopeHarness::new(true);
    executable(&h.temp.path().join("delegate"), format!("#!/bin/sh\nset -eu\n/usr/bin/git -c core.hooksPath=/dev/null commit --allow-empty -m qualified-anchor\nprintf executed > '{}/executed'\n", h.temp.path().display()));
    let (store, lease) = crate::allocate::locked(&h.config).unwrap();
    drop(lease);
    let prefix = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &CancelToken::default(),
        |boundary, root| {
            if boundary == Boundary::RootTerminal {
                h.empty(root);
            }
        },
    )
    .unwrap();
    let qualified =
        crate::identity::query(&h.allocation.destination, &["rev-parse", "HEAD"]).unwrap();
    let allocation = &h.allocation.identity.as_ref().unwrap().head;
    assert_ne!(&qualified, allocation);
    let tree =
        crate::identity::query(&h.allocation.destination, &["rev-parse", "HEAD^{tree}"]).unwrap();
    let divergent = crate::identity::query(
        &h.allocation.destination,
        &["commit-tree", &tree, "-m", "negative-independent-root"],
    )
    .unwrap();
    let mut identity = prefix.record.request.identity().clone();
    identity.run = work_contract::RunId::generate();
    identity.group = work_contract::GroupId::generate();
    identity.run_ref = work_contract::RunRef::parse("head-anchor-negative").unwrap();
    let root =
        crate::run_journal::RootRunRequest::new(identity, prefix.record.request.input().clone())
            .unwrap();
    let before = durable_rows(&store);
    for head in [allocation, &divergent] {
        crate::identity::query(&h.allocation.destination, &["update-ref", "HEAD", head]).unwrap();
        assert!(super::super::begin(&h.config, &root, &h.command.argv).is_err());
        assert_eq!(
            durable_rows(&store),
            before,
            "allocation ancestry alone cannot authorize rewind/divergence"
        );
        crate::identity::query(
            &h.allocation.destination,
            &["update-ref", "HEAD", &qualified],
        )
        .unwrap();
    }
    crate::identity::query(
        &h.allocation.destination,
        &["symbolic-ref", "HEAD", "refs/heads/main"],
    )
    .unwrap();
    assert!(super::super::begin(&h.config, &root, &h.command.argv).is_err());
    assert_eq!(durable_rows(&store), before);
    crate::identity::query(
        &h.allocation.destination,
        &["symbolic-ref", "HEAD", "refs/heads/topic"],
    )
    .unwrap();
    assert_eq!(
        crate::identity::query(&h.allocation.destination, &["rev-parse", "HEAD"]).unwrap(),
        qualified
    );
}

#[test]
fn complete_physical_continuity_and_both_head_anchors_are_required() {
    contended_original_windows();
    continuation_release_boundaries();
    continuation_admission_physics();
    // Actual owned close/seal; observer mutates/delays, never supplies authority.
    for case in [
        "second-head",
        "registry",
        "original-age",
        "source",
        "checkout",
        "private",
        "common",
        "marker",
    ] {
        let h = ScopeHarness::new(true);
        let (store, lease) = crate::allocate::locked(&h.config).unwrap();
        drop(lease);
        let path = h.allocation.destination.clone();
        let registry = h.temp.path().join("registry.json");
        let identity = h.allocation.identity.as_ref().unwrap();
        let replacement = match case {
            "source" => Some(h.allocation.request.repository.clone().unwrap()),
            "checkout" => Some(identity.path.clone()),
            "private" => Some(identity.private_git_dir.clone()),
            "common" => Some(identity.common_git_dir.clone()),
            _ => None,
        };
        let marker = identity.private_git_dir.join("work-lease.json");
        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = reached.clone();
        let _observer = crate::gap_continuation::observing_publication(move |stage| {
            if stage
                == if case == "original-age" {
                    "before_lease"
                } else {
                    "before_second_physical"
                }
            {
                observed.set(true);
                match case {
                    "second-head" => {
                        crate::identity::query(
                            &path,
                            &[
                                "commit",
                                "--allow-empty",
                                "-m",
                                "between-publication-observations",
                            ],
                        )
                        .unwrap();
                    }
                    "registry" => std::fs::write(&registry, "{}").unwrap(),
                    "source" | "checkout" | "private" | "common" => {
                        super::physical_fixture::replace_directory(replacement.as_ref().unwrap())
                    }
                    "marker" => std::fs::write(&marker, "{}").unwrap(),
                    "original-age" => std::thread::sleep(std::time::Duration::from_millis(2100)),
                    _ => unreachable!(),
                }
            }
        });
        let result = crate::supervisor::supervise_off(
            &h.config,
            h.command.clone(),
            &h.driver,
            Some(h.io()),
            &CancelToken::default(),
            |boundary, root| {
                if boundary == Boundary::RootTerminal {
                    h.empty(root);
                }
            },
        );
        assert!(
            reached.get(),
            "real publication observation dependency: {case}"
        );
        assert!(result.is_err(), "publication must refuse {case}");
        let root = store
            .run_snapshot(&work_contract::RunId::parse(&h.command.run_id.to_string()).unwrap())
            .unwrap()
            .unwrap();
        assert!(root.closed && !root.recovery_hold);
        assert_eq!(root.outcome, Some(RootOutcome::Completed));
        assert_eq!(
            store
                .conn
                .query_row("SELECT disposition FROM gap_eligibility", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "awaiting_qualification"
        );
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM gap_qualifications", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    // Stage: genuine initial admission supplies the baseline Physical. These
    // direct physical observations are metadata tests, never Q/live/seal minting.
    // Git mutations below are explicit owned negative/ancestry fixtures, not
    // substitutes for C6's owned actor commits or a live closure/publication.
    let (_temp, config, allocation, root, argv) = super::materialized(true);
    let (_store, began) = super::super::begin(&config, &root, &argv).unwrap();
    let super::super::BeginGap::Created(live) = began else {
        panic!("genuine admission required")
    };
    let baseline = &live.proof.physical;
    let inspect = |anchor: &str| {
        crate::gap_continuation::inspect_physical(
            &allocation,
            &live.proof.context.repository,
            baseline,
            anchor,
        )
    };
    assert!(inspect(&baseline.checkout.head).is_ok());
    crate::identity::query(
        &allocation.destination,
        &["commit", "--allow-empty", "-m", "physical-descendant"],
    )
    .unwrap();
    assert!(
        crate::recovery::verify(&allocation).is_err(),
        "default pending-HEAD rule stays strict"
    );
    let descendant = inspect(&baseline.checkout.head).expect(
        "Gap-only physical inspection permits an actual descendant without refreshing allocation",
    );
    assert_ne!(descendant.checkout.head, baseline.checkout.head);
    assert_eq!(descendant.directories, baseline.directories);
    assert_eq!(descendant.marker, baseline.marker);
    crate::identity::query(
        &allocation.destination,
        &["update-ref", "HEAD", &baseline.checkout.head],
    )
    .unwrap();
    assert!(
        inspect(&descendant.checkout.head).is_err(),
        "allocation ancestry alone must not permit rewind behind predecessor anchor"
    );
    assert!(
        inspect("HEAD").is_err(),
        "mutable object names are not anchors"
    );
    assert!(inspect("not-an-object").is_err());
    drop(live);

    for directory in 0..4 {
        let (_temp, config, allocation, root, argv) = super::materialized(true);
        let (_store, began) = super::super::begin(&config, &root, &argv).unwrap();
        let super::super::BeginGap::Created(live) = began else {
            panic!("genuine admission required")
        };
        let physical = &live.proof.physical;
        let path = [
            allocation.request.repository.as_ref().unwrap(),
            &physical.checkout.path,
            &physical.checkout.private_git_dir,
            &physical.checkout.common_git_dir,
        ][directory];
        super::physical_fixture::replace_directory(path);
        assert!(
            crate::gap_continuation::inspect_physical(
                &allocation,
                &live.proof.context.repository,
                physical,
                &physical.checkout.head
            )
            .is_err(),
            "replaced directory index {directory}"
        );
        // Do not use this live handle again, even if paths could be restored.
    }
    for (file, replacement) in [
        ("dotgit", "hardlink"),
        ("gitdir", "hardlink"),
        ("commondir", "hardlink"),
        ("work-lease.json", "hardlink"),
        ("dotgit", "symlink"),
        ("gitdir", "socket"),
        ("work-lease.json", "bytes"),
    ] {
        let (temp, config, allocation, root, argv) = super::materialized(true);
        let (_store, began) = super::super::begin(&config, &root, &argv).unwrap();
        let super::super::BeginGap::Created(live) = began else {
            panic!("genuine admission required")
        };
        let physical = &live.proof.physical;
        let path = if file == "dotgit" {
            allocation.destination.join(".git")
        } else {
            physical.checkout.private_git_dir.join(file)
        };
        let backup = temp.path().join("metadata-backup");
        let mut socket = None;
        match replacement {
            "hardlink" => std::fs::hard_link(&path, &backup).unwrap(),
            "symlink" => {
                std::fs::rename(&path, &backup).unwrap();
                std::os::unix::fs::symlink(&backup, &path).unwrap();
            }
            "socket" => {
                std::fs::remove_file(&path).unwrap();
                socket = Some(std::os::unix::net::UnixListener::bind(&path).unwrap());
            }
            "bytes" => std::fs::write(&path, "{}").unwrap(),
            _ => unreachable!(),
        }
        assert!(
            crate::gap_continuation::inspect_physical(
                &allocation,
                &live.proof.context.repository,
                physical,
                &physical.checkout.head
            )
            .is_err(),
            "{file}/{replacement}"
        );
        drop(socket);
    }
}

#[test]
fn schema15_validation_preserves_sql_literal_semantics() {
    let (_temp, config, _, _, _) = super::materialized(true);
    let (store, lease) = crate::allocate::locked(&config).unwrap();
    drop(lease);
    let schema = || {
        store
            .conn
            .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    let open = || {
        crate::store::Store::open_existing_registered_mut(
            config.trusted_registry.as_ref().unwrap(),
            config.store_dir.as_ref().unwrap(),
            &config.roots,
        )
    };
    let original: String = store
        .conn
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='gap_eligibility'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let pristine_schema = schema();
    let pristine_rows = durable_rows(&store);
    assert!(pristine_rows[14].is_empty() && pristine_rows[15].is_empty());
    crate::gap_continuation::validate_schema(&store.conn).unwrap();
    drop(open().expect("native schema17 is accepted before malformed DDL qualification"));
    let mut accepted = Vec::new();
    for literal in ["'UNAVAILABLE'", "'un available'", "'un\"available'"] {
        // Only literal contents change; column, constraint, FK and index shapes
        // remain intact. Exact bytes, not the validator's normalization, are the oracle.
        let changed = original.replacen("'unavailable'", literal, 1);
        assert_ne!(changed, original);
        store
            .conn
            .execute_batch("DROP TABLE gap_eligibility")
            .unwrap();
        store.conn.execute_batch(&changed).unwrap();
        let malformed_schema = schema();
        let actual: String = store
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name='gap_eligibility'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(actual, changed);
        if crate::gap_continuation::validate_schema(&store.conn).is_ok() {
            accepted.push(format!("direct validator accepted {literal}"));
        }
        if open().is_ok() {
            accepted.push(format!("public opening accepted {literal}"));
        }
        assert_eq!(schema(), malformed_schema, "refusal must not repair DDL");
        assert_eq!(durable_rows(&store), pristine_rows);
        assert_eq!(
            store
                .conn
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            17
        );
        store
            .conn
            .execute_batch("DROP TABLE gap_eligibility")
            .unwrap();
        store.conn.execute_batch(&original).unwrap();
        assert_eq!(schema(), pristine_schema);
        crate::gap_continuation::validate_schema(&store.conn).unwrap();
        drop(open().expect("exact native DDL restoration is accepted"));
    }
    assert!(
        accepted.is_empty(),
        "changed CHECK semantics accepted: {accepted:?}"
    );
}

#[test]
fn schema15_and_strict_v2_preserve_legacy_bytes_without_backfill() {
    qualification_negatives(true);
    use sha2::Digest;
    let (_temp, config, allocation, root, argv) = super::materialized(true);
    let (store, _) = super::super::begin(&config, &root, &argv).unwrap();
    assert_eq!(
        store
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        17,
        "current native authority must migrate to schema17",
    );
    let expected = [
        ("gap_qualifications", "table", "CREATE TABLE gap_qualifications(run TEXT PRIMARY KEY REFERENCES attribution_gaps(run), checkout TEXT NOT NULL REFERENCES checkouts(id), record TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), successor_run TEXT UNIQUE REFERENCES attribution_gaps(run), successor_revision INTEGER, CHECK((successor_run IS NULL AND successor_revision IS NULL) OR (successor_run IS NOT NULL AND successor_revision IS NOT NULL AND successor_revision>0)))"),
        ("gap_qualifications_checkout", "index", "CREATE INDEX gap_qualifications_checkout ON gap_qualifications(checkout)"),
        ("gap_eligibility", "table", "CREATE TABLE gap_eligibility(checkout TEXT PRIMARY KEY REFERENCES checkouts(id), latest_run TEXT NOT NULL UNIQUE REFERENCES attribution_gaps(run), revision INTEGER NOT NULL CHECK(revision>0), disposition TEXT NOT NULL CHECK(disposition IN ('unavailable','awaiting_qualification','available','blocked')), qualification TEXT REFERENCES gap_qualifications(run), CHECK((disposition='available' AND qualification IS NOT NULL) OR (disposition<>'available' AND qualification IS NULL)))"),
    ];
    let normalize = |s: &str| {
        s.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    for (name, kind, ddl) in expected {
        let actual: String = store
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name=?1 AND type=?2",
                (name, kind),
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(normalize(&actual), normalize(ddl));
    }
    let old_gap: (String, Vec<u8>) = store
        .conn
        .query_row(
            "SELECT record,fingerprint FROM attribution_gaps WHERE run=?1",
            [root.identity().run.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let old_root: String = store
        .conn
        .query_row(
            "SELECT request FROM runs WHERE id=?1",
            [root.identity().run.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    let v1: super::super::GapRecord = serde_json::from_str(&old_gap.0).unwrap();
    assert_eq!(super::super::encode(&v1).unwrap(), old_gap.0);
    assert!(!old_gap.0.contains("continuation"));
    assert_eq!(serde_json::to_string(&root).unwrap(), old_root);
    let prior_events = store.pending_events(100).unwrap();

    // Reconstruct populated historical14 with no new references. This is a
    // migration fixture only: never returned as a fresh live capability.
    store
        .conn
        .execute_batch(
            "DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; PRAGMA user_version=14;",
        )
        .unwrap();
    drop(store);
    let (mut migrated, lease) = crate::allocate::locked(&config).unwrap();
    drop(lease);
    for table in ["gap_qualifications", "gap_eligibility"] {
        assert_eq!(
            migrated
                .conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0,
            "no backfill: {table}"
        );
    }
    assert_eq!(migrated.pending_events(100).unwrap(), prior_events);
    assert!(migrated
        .run_snapshot(&root.identity().run)
        .unwrap()
        .is_some());
    assert_eq!(
        super::super::encode(&super::super::read_record(&migrated.conn, &root).unwrap()).unwrap(),
        old_gap.0
    );
    assert_eq!(
        migrated
            .conn
            .query_row(
                "SELECT request FROM runs WHERE id=?1",
                [root.identity().run.to_string()],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        old_root
    );

    // Wire-only shape qualification. These bytes are not a Q, a live run or a
    // positive continuation-admission fixture. Historical checks still refuse
    // this synthetic link because no predecessor qualification exists.
    let mut v2: serde_json::Value = serde_json::from_str(&old_gap.0).unwrap();
    v2["format_version"] = 2.into();
    v2["origin"] = "required_continuation".into();
    v2["context"]["state"] = "held".into();
    v2["context"]["continuation"] = serde_json::json!({
        "predecessor": uuid::Uuid::now_v7().to_string(),
        "fingerprint": vec![1u8; 32],
        "publication_revision": 3,
        "admission_revision": 4,
    });
    let decoded: super::super::GapRecord =
        serde_json::from_value(v2.clone()).expect("v2 declared wire shape");
    let canonical = super::super::encode(&decoded).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&canonical).unwrap(),
        v2
    );
    assert!(
        super::super::decode_record(&canonical).is_ok(),
        "canonical v2 wire must decode without granting history/live authority"
    );
    assert_eq!(
        super::super::encode(&super::super::decode_record(&old_gap.0).unwrap()).unwrap(),
        old_gap.0
    );
    let mut candidates = Vec::new();
    for (version, origin) in [
        (1, "required_continuation"),
        (2, "required_initial"),
        (2, "ordinary_unconfigured"),
    ] {
        let mut bad = v2.clone();
        bad["format_version"] = version.into();
        bad["origin"] = origin.into();
        candidates.push(serde_json::to_string(&bad).unwrap());
    }
    for bad_link in [
        serde_json::Value::Null,
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!({"predecessor":"not-an-id", "fingerprint":[1], "publication_revision":0, "admission_revision":1}),
    ] {
        let mut bad = v2.clone();
        bad["context"]["continuation"] = bad_link;
        candidates.push(serde_json::to_string(&bad).unwrap());
    }
    let mut missing = v2.clone();
    missing["context"]
        .as_object_mut()
        .unwrap()
        .remove("continuation");
    candidates.push(serde_json::to_string(&missing).unwrap());
    candidates.push(canonical.replacen("\"predecessor\":", "\"unknown\":0,\"predecessor\":", 1));
    candidates.push(canonical.replacen(
        "\"publication_revision\":3",
        "\"publication_revision\":3,\"publication_revision\":3",
        1,
    ));
    for field in ["publication_revision", "admission_revision"] {
        for value in [0, i64::MAX as u64 + 1] {
            let mut bad = v2.clone();
            bad["context"]["continuation"][field] = value.into();
            // Preserve canonical field order before semantic decoding.
            if let Ok(wire) = serde_json::from_value::<super::super::GapRecord>(bad) {
                candidates.push(super::super::encode(&wire).unwrap());
            }
        }
    }
    let mut bad = decoded.clone();
    bad.format_version = 1;
    candidates.push(super::super::encode(&bad).unwrap());
    let mut explicit_null: serde_json::Value = serde_json::from_str(&old_gap.0).unwrap();
    explicit_null["context"]["continuation"] = serde_json::Value::Null;
    candidates.push(serde_json::to_string(&explicit_null).unwrap());
    for bytes in &candidates {
        assert!(
            super::super::decode_record(bytes).is_err(),
            "malformed wire was accepted"
        );
    }
    candidates.push(canonical);
    for bytes in candidates {
        migrated
            .conn
            .execute(
                "UPDATE attribution_gaps SET record=?1,fingerprint=?2 WHERE run=?3",
                rusqlite::params![
                    bytes,
                    sha2::Sha256::digest(bytes.as_bytes()).as_slice(),
                    root.identity().run.to_string()
                ],
            )
            .unwrap();
        assert!(
            migrated.run_snapshot(&root.identity().run).is_err(),
            "synthetic/malformed v2 is not historical authority"
        );
        migrated
            .conn
            .execute(
                "UPDATE attribution_gaps SET record=?1,fingerprint=?2 WHERE run=?3",
                rusqlite::params![old_gap.0, old_gap.1, root.identity().run.to_string()],
            )
            .unwrap();
    }
    assert!(migrated
        .run_snapshot(&root.identity().run)
        .unwrap()
        .is_some());
    assert_eq!(
        migrated
            .charged(allocation.request.repository.as_ref().unwrap(), None)
            .unwrap(),
        1
    );

    // Malformed/view preexistence refuses atomically, never IF-NOT-EXISTS repair.
    for ddl in [
        "CREATE VIEW gap_eligibility AS SELECT 1 AS checkout",
        "CREATE TABLE gap_eligibility(checkout TEXT)",
    ] {
        let directory = config.store_dir.as_ref().unwrap();
        let sidecars = ["store.sqlite-wal", "store.sqlite-shm"].map(|name| directory.join(name));
        // This raw client is only for inspection/repair, not schema ownership.
        let sql = rusqlite::Connection::open(directory.join("store.sqlite")).unwrap();
        sql.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .unwrap();
        migrated.conn.execute_batch("DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; PRAGMA user_version=14;").unwrap();
        migrated.conn.execute_batch(ddl).unwrap();
        drop(migrated);
        for sidecar in &sidecars {
            assert!(std::fs::symlink_metadata(sidecar)
                .unwrap()
                .file_type()
                .is_file());
        }
        // Independent existing-lock free control: SH self-contention must not
        // masquerade as rejection of the malformed schema. Drop this probe
        // before asking the real opener to acquire its own initialization lock.
        {
            let probe = std::fs::File::open(
                config
                    .trusted_registry
                    .as_ref()
                    .unwrap()
                    .join("initialization.lock"),
            )
            .unwrap();
            rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .unwrap();
        }
        assert!(crate::allocate::locked(&config).is_err());
        assert_eq!(
            sql.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            14
        );
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='gap_qualifications'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        sql.execute_batch(if ddl.contains("VIEW") {
            "DROP VIEW gap_eligibility"
        } else {
            "DROP TABLE gap_eligibility"
        })
        .unwrap();
        for sidecar in &sidecars {
            assert!(std::fs::symlink_metadata(sidecar)
                .unwrap()
                .file_type()
                .is_file());
        }
        drop(sql);
        for sidecar in &sidecars {
            assert!(std::fs::symlink_metadata(sidecar)
                .unwrap()
                .file_type()
                .is_file());
        }
        let (reopened, lease) = crate::allocate::locked(&config).unwrap();
        drop(lease);
        migrated = reopened;
    }

    // Exact new DDL under the unchanged native cumulative SQL budget: an
    // interrupted transaction must leave neither tables nor the version bump.
    migrated
        .conn
        .execute_batch(
            "DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; PRAGMA user_version=14;",
        )
        .unwrap();
    {
        let _phase = migrated.sql_phase();
        let tx = rusqlite::Transaction::new_unchecked(
            &migrated.conn,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        tx.execute_batch(crate::gap_continuation::SCHEMA).unwrap();
        let result = tx.query_row("WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT sum(x) FROM n", [], |r| r.get::<_, i64>(0));
        assert!(
            matches!(result, Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::OperationInterrupted)
        );
        // Rollback on drop, not a commit/retry or a replacement budget callback.
    }
    assert_eq!(
        migrated
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        14
    );
    assert_eq!(migrated.conn.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN ('gap_eligibility','gap_qualifications')", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    drop(migrated);
    let (_, lease) = crate::allocate::locked(&config).unwrap();
    drop(lease);

    let default = crate::test_run_fixture::request(allocation.checkout);
    let input = serde_json::to_value(default.input()).unwrap();
    assert!(input.get("attribution").is_none());
    let fields = [
        "command_digest",
        "input_digest",
        "context_ref",
        "intent_ref",
        "boot",
    ];
    let legacy: Vec<_> = fields.iter().map(|field| input[*field].clone()).collect();
    assert_eq!(
        serde_json::from_value::<crate::run_journal::RunInput>(legacy.clone().into()).unwrap(),
        *default.input()
    );
    for marker in [serde_json::Value::Null, serde_json::json!("off")] {
        let mut sixth = legacy.clone();
        sixth.push(marker);
        assert!(serde_json::from_value::<crate::run_journal::RunInput>(sixth.into()).is_err());
    }

    // Existing bounded captured-history fixture, not a fabricated Gap/Q chain.
    // Pilot functional coverage retains two Roots, contained children, FINISH
    // and receipt-v1 bytes; the separate stress wrapper retains 2/48 Roots.
    crate::capture_readiness::tests::many_closed_history_owned(|config, store, allocation, _| {
        crate::finish::finish(config, allocation.checkout).unwrap();
        let receipt: String = store
            .conn
            .query_row("SELECT record FROM task_finishes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&receipt).unwrap()["version"],
            1
        );
        let before = durable_rows(&store);
        store.conn.execute_batch("DROP TABLE quarantine_actions; DROP TABLE retirement_intents; DROP TABLE gap_eligibility; DROP TABLE gap_qualifications; PRAGMA user_version=14;").unwrap();
        drop(store);
        let (opened, lease) = crate::allocate::locked(config).unwrap();
        drop(lease);
        assert_eq!(
            durable_rows(&opened),
            before,
            "migration must preserve all captured/receipt/outbox bytes"
        );
    });
}
