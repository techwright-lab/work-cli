use super::{durable_rows, executable, ScopeHarness};
use crate::{admission::Limits, run_journal::RootRunRequest, store::Store};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Revoker {
    Owner,
    Journal,
}

// Each case owns a genuine blocked child, a preopened native revoker Store and
// one finite attempt. No raw SQL mutation stands in for a participating writer.
pub(super) fn revoker_case(revoker: Revoker, release_first: bool) -> Vec<String> {
    let h = ScopeHarness::new(true);
    let mut store = Store::open_existing_registered_mut(
        h.config.trusted_registry.as_ref().unwrap(),
        h.config.store_dir.as_ref().unwrap(),
        &h.config.roots,
    )
    .unwrap();
    let path = h.temp.path().to_owned();
    let (send, receive) = mpsc::channel::<RootRunRequest>();
    let (finished, completion) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let request = receive.recv_timeout(Duration::from_secs(10)).ok()?;
        if release_first {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !path.join("gate-entered").exists() {
                if Instant::now() >= deadline {
                    let _ = finished.send(());
                    return None;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let before = durable_rows(&store);
        let owner_before: String = store
            .conn
            .query_row("SELECT owner FROM checkouts", [], |r| r.get(0))
            .unwrap();
        let events_before = store.pending_events(1000).unwrap().len();
        let started = Instant::now();
        let result = match revoker {
            Revoker::Owner => store.transfer(
                h_checkout(&request),
                "bob",
                Limits {
                    owner: 10,
                    repository: 10,
                    available_bytes: None,
                    floor_bytes: 0,
                    warn_bytes: 0,
                },
            ),
            Revoker::Journal => store.record_recovery_hold(&request).map(|_| ()),
        };
        let elapsed = started.elapsed();
        let contention = matches!(&result, Err(crate::store::StoreError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock);
        let after = durable_rows(&store);
        let owner_after: String = store
            .conn
            .query_row("SELECT owner FROM checkouts", [], |r| r.get(0))
            .unwrap();
        let held = store
            .run_snapshot(&request.identity().run)
            .unwrap()
            .unwrap()
            .recovery_hold;
        let events_after = store.pending_events(1000).unwrap().len();
        let marker_before_publication = path.join("executed").exists();
        std::fs::write(path.join("attempt-done"), "done").unwrap();
        let _ = finished.send(());
        Some((
            result.is_ok(),
            contention,
            before == after,
            owner_before,
            owner_after,
            held,
            events_before,
            events_after,
            elapsed,
            marker_before_publication,
        ))
    });
    let mut observer_error = None;
    let result = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &crate::supervisor::CancelToken::default(),
        |boundary, root| {
            if boundary == crate::supervisor::Boundary::PermitAttempt {
                if release_first {
                    // Only the first final-release inspection waits. Subsequent
                    // closure observations retain the original manager response.
                    executable(&h.temp.path().join("manager"), format!(
                        "#!/bin/sh\nif mkdir '{0}/gate-once' 2>/dev/null; then\n  : > '{0}/gate-entered'\n  n=0\n  while [ ! -f '{0}/attempt-done' ]; do\n    n=$((n+1))\n    [ \"$n\" -lt 150 ] || exit 1\n    /usr/bin/sleep 0.01\n  done\nfi\nexec /usr/bin/cat '{0}/properties'\n", h.temp.path().display()));
                }
                if send.send(root.request.clone()).is_err() {
                    observer_error = Some("revoker request channel closed");
                } else if !release_first && completion.recv_timeout(Duration::from_secs(2)).is_err()
                {
                    observer_error = Some("revoker-first attempt did not finish");
                }
            }
            if boundary == crate::supervisor::Boundary::RootTerminal {
                h.empty(root);
            }
        },
    );
    // Joining precedes assertions, including failed admission/fixture paths.
    drop(send);
    let observation = worker.join().expect("owned revoker thread panicked");
    let mut failures = Vec::new();
    if let Some(error) = observer_error {
        failures.push(error.into());
    }
    let Some((
        committed,
        contention,
        unchanged,
        before_owner,
        after_owner,
        held,
        before_events,
        after_events,
        elapsed,
        premature_marker,
    )) = observation
    else {
        failures.push("fixture: public revoker never reached its scheduled attempt".into());
        return failures;
    };
    let check = |ok: bool, message: &str, failures: &mut Vec<String>| {
        if !ok {
            failures.push(format!(
                "{revoker:?}/release_first={release_first}: {message}"
            ));
        }
    };
    check(
        !premature_marker,
        "actor marker existed before revoker completed/kernel gate returned",
        &mut failures,
    );
    let store = Store::open_existing_registered_mut(
        h.config.trusted_registry.as_ref().unwrap(),
        h.config.store_dir.as_ref().unwrap(),
        &h.config.roots,
    )
    .unwrap();
    let writers: i64 = store
        .conn
        .query_row("SELECT count(*) FROM writers", [], |r| r.get(0))
        .unwrap();
    let charged: i64 = store
        .conn
        .query_row(
            "SELECT count(*) FROM checkouts WHERE state!='retired'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    check(charged == 1, "checkout charge lost", &mut failures);
    if release_first {
        check(
            !committed,
            "public revoker incorrectly COMMITTED during kernel gate while permit not published",
            &mut failures,
        );
        check(
            unchanged && before_events == after_events && before_owner == after_owner && !held,
            "losing attempt changed durable state/event/owner/hold",
            &mut failures,
        );
        check(
            contention && elapsed >= Duration::from_millis(500) && elapsed < Duration::from_secs(1),
            "losing attempt was not the bounded 500ms lease-contention refusal",
            &mut failures,
        );
        check(
            result.is_ok(),
            "release-first execution/closure refused",
            &mut failures,
        );
        check(
            h.temp.path().join("executed").exists(),
            "release-first actor did not execute",
            &mut failures,
        );
        check(
            writers == 0,
            "genuine empty closure retained writer",
            &mut failures,
        );
    } else {
        check(
            committed && !unchanged && after_events > before_events,
            "revoker-first did not durably commit",
            &mut failures,
        );
        check(
            match revoker {
                Revoker::Owner => before_owner == "alice" && after_owner == "bob",
                Revoker::Journal => held,
            },
            "revoker-first durable effect absent",
            &mut failures,
        );
        check(
            result.is_err(),
            "revoker-first release was not refused",
            &mut failures,
        );
        check(
            !h.temp.path().join("executed").exists(),
            "revoker-first actor executed",
            &mut failures,
        );
        check(writers == 1, "refused release lost writer", &mut failures);
    }
    failures
}

fn h_checkout(request: &RootRunRequest) -> uuid::Uuid {
    uuid::Uuid::parse_str(&request.identity().checkout.to_string()).unwrap()
}

#[test]
fn nested_allocator_and_direct_library_mutations_share_one_lease() {
    use crate::run_journal::{BeginRun, RootOutcome, Transition};
    let (_temp, config, allocation, _, _) = super::ordinary();
    let retried = crate::allocate::start(&config, allocation.request.clone()).unwrap();
    assert_eq!(retried.checkout, allocation.checkout);
    let (mut store, lease) = crate::allocate::locked(&config).unwrap();
    let mut current =
        crate::allocate::verified_checkout_under_lease(&mut store, allocation.checkout, &lease)
            .unwrap();
    crate::recovery::reconcile_under_lease(&mut store, &mut current, &lease).unwrap();
    crate::recovery::hold_under_lease(&mut store, &mut current, "nested safety hold", &lease)
        .unwrap();
    assert_eq!(current.stage, "held");
    drop(lease);
    assert_eq!(
        crate::allocate::load(&mut store, allocation.request.operation)
            .unwrap()
            .unwrap()
            .stage,
        "held"
    );
    crate::recovery::hold(&mut store, &mut current, "standalone safety hold").unwrap();
    crate::allocate::save(&mut store, &current).unwrap();
    assert_eq!(
        store
            .charged(allocation.request.repository.as_ref().unwrap(), None)
            .unwrap(),
        1
    );

    let h = ScopeHarness::new(true);
    // The actor itself must acquire allocation.lock before exiting. Holding the
    // release token across actor lifetime would fail this bounded acquisition.
    executable(&h.temp.path().join("delegate"), format!(
        "#!/bin/sh\n/usr/bin/flock -w 0.5 '{0}/private/allocation.lock' /usr/bin/touch '{0}/actor-acquired' || exit 42\nprintf executed > '{0}/executed'\n", h.temp.path().display()));
    let mut direct = Store::open_existing_registered_mut(
        h.config.trusted_registry.as_ref().unwrap(),
        h.config.store_dir.as_ref().unwrap(),
        &h.config.roots,
    )
    .unwrap();
    let limits = Limits {
        repository: 10,
        owner: 10,
        available_bytes: None,
        floor_bytes: 0,
        warn_bytes: 0,
    };
    let mut sleeper = super::OwnedSleeper(None);
    let mut child_pid = None;
    let result = crate::supervisor::supervise_off(
        &h.config,
        h.command.clone(),
        &h.driver,
        Some(h.io()),
        &crate::supervisor::CancelToken::default(),
        |boundary, root| {
            if boundary == crate::supervisor::Boundary::PermitAttempt {
                direct
                    .transfer(h.allocation.checkout, "bob", limits)
                    .unwrap();
                let before = durable_rows(&direct);
                direct
                    .transfer(h.allocation.checkout, "bob", limits)
                    .unwrap();
                assert_eq!(durable_rows(&direct), before);
                direct
                    .transfer(h.allocation.checkout, "alice", limits)
                    .unwrap();
                let binding = root.binding.as_ref().unwrap();
                let child = std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .spawn()
                    .unwrap();
                let pid = child.id();
                sleeper.0 = Some(child);
                child_pid = Some(pid);
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
                let start_ticks = stat
                    .rsplit_once(") ")
                    .unwrap()
                    .1
                    .split_whitespace()
                    .nth(19)
                    .unwrap()
                    .parse()
                    .unwrap();
                let proc = h.temp.path().join(format!("proc/{pid}"));
                std::fs::create_dir(&proc).unwrap();
                std::fs::write(proc.join("stat"), stat).unwrap();
                std::fs::write(proc.join("cgroup"), format!("0::{}\n", binding.cgroup)).unwrap();
                let registrar = std::process::id();
                let registrar_proc = h.temp.path().join(format!("proc/{registrar}"));
                std::fs::create_dir(&registrar_proc).unwrap();
                std::fs::write(
                    registrar_proc.join("stat"),
                    std::fs::read(format!("/proc/{registrar}/stat")).unwrap(),
                )
                .unwrap();
                std::fs::write(
                    registrar_proc.join("cgroup"),
                    format!("0::{}\n", binding.cgroup),
                )
                .unwrap();
                let members = h
                    .temp
                    .path()
                    .join("cg")
                    .join(binding.cgroup.trim_start_matches('/'))
                    .join("cgroup.procs");
                std::fs::write(
                    &members,
                    format!("{}\n{pid}\n{registrar}\n", binding.root_pid),
                )
                .unwrap();
                let child = super::declared_child(
                    &root.request,
                    Some(crate::run_participants::ExpectedHost {
                        pid,
                        start_ticks,
                        boot: binding.boot.clone(),
                    }),
                );
                assert_eq!(
                    direct.register_child(&root.request, &child).unwrap(),
                    BeginRun::Created
                );
                let before = durable_rows(&direct);
                assert_eq!(
                    direct.register_child(&root.request, &child).unwrap(),
                    BeginRun::Existing
                );
                assert_eq!(durable_rows(&direct), before);
                let proof = direct
                    .group_snapshot(&root.request.identity().run)
                    .unwrap()
                    .certify_child_enrollment(&h.driver, &child.run, None)
                    .unwrap();
                assert_eq!(
                    direct
                        .record_child_enrollment(&root.request, &child, &proof)
                        .unwrap(),
                    Transition::Changed
                );
                let before = durable_rows(&direct);
                assert_eq!(
                    direct
                        .record_child_enrollment(&root.request, &child, &proof)
                        .unwrap(),
                    Transition::Existing
                );
                assert_eq!(durable_rows(&direct), before);
                let outcome = crate::run_participants::ChildOutcome::Completed;
                assert_eq!(
                    direct
                        .record_child_outcome(&root.request, &child, outcome)
                        .unwrap(),
                    Transition::Changed
                );
                let before = durable_rows(&direct);
                assert_eq!(
                    direct
                        .record_child_outcome(&root.request, &child, outcome)
                        .unwrap(),
                    Transition::Existing
                );
                assert_eq!(durable_rows(&direct), before);
                std::fs::remove_dir_all(registrar_proc).unwrap();
                std::fs::write(members, format!("{}\n{pid}\n", binding.root_pid)).unwrap();
            }
            if boundary == crate::supervisor::Boundary::RootTerminal {
                assert_eq!(root.outcome, Some(RootOutcome::Completed));
                let before = durable_rows(&direct);
                assert_eq!(
                    direct
                        .record_root_outcome(&root.request, RootOutcome::Completed)
                        .unwrap(),
                    Transition::Existing
                );
                assert_eq!(durable_rows(&direct), before);
                assert_eq!(
                    direct.record_recovery_hold(&root.request).unwrap(),
                    Transition::Changed
                );
                let before = durable_rows(&direct);
                assert_eq!(
                    direct.record_recovery_hold(&root.request).unwrap(),
                    Transition::Existing
                );
                assert_eq!(durable_rows(&direct), before);
                let mut child = sleeper.0.take().unwrap();
                child.kill().unwrap();
                child.wait().unwrap();
                std::fs::remove_dir_all(h.temp.path().join(format!("proc/{}", child_pid.unwrap())))
                    .unwrap();
                h.empty(root);
            }
        },
    )
    .unwrap();
    assert!(result.record.closed && result.lease_charged && !result.checkout_ready);
    assert!(h.temp.path().join("actor-acquired").exists());
    assert!(h.temp.path().join("executed").exists());
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

#[test]
fn public_revokers_cannot_commit_during_gap_kernel_gate() {
    let mut failures = Vec::new();
    for (revoker, release_first) in [
        (Revoker::Owner, false),
        (Revoker::Journal, false),
        (Revoker::Owner, true),
        (Revoker::Journal, true),
    ] {
        failures.extend(revoker_case(revoker, release_first));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
