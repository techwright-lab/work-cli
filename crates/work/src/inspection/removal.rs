//! Explicit cooperative removal of ordinary completed interactive allocations.
//! No process-quiescence claim, force flag, recursive fallback, or replay of an
//! uncertain dispatch. Existing retained inspection is the physical authority.
use super::*;
use crate::{
    config::Config,
    removal_journal::{self as journal, Record},
};
use serde::Serialize;
type Result<T> = std::result::Result<T, String>;
fn checked<T, E: std::fmt::Debug>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| format!("{e:?}"))
}
#[derive(Serialize)]
pub(crate) struct Report {
    pub checkout: Uuid,
    pub path: PathBuf,
    pub outcome: &'static str,
    pub charge_retained: bool,
    pub preserved_refs: Vec<String>,
    pub next_action: &'static str,
}
fn references(checkout: Uuid, roots: &[String]) -> Vec<String> {
    roots
        .iter()
        .map(|oid| format!("refs/work-preserved/{checkout}/{oid}"))
        .collect()
}
fn report(checkout: Uuid, path: PathBuf, roots: &[String], removed: bool) -> Report {
    Report {
        checkout,
        path,
        outcome: if removed { "removed" } else { "preview" },
        charge_retained: !removed,
        preserved_refs: references(checkout, roots),
        next_action: if removed {
            "none; branches and local recovery refs retained"
        } else {
            "stop all agents and editors, then repeat with --confirm-stopped"
        },
    }
}
fn completion(store: &Store, checkout: Uuid) -> Result<crate::allocate::Allocation> {
    let _phase = store.sql_phase();
    checked(crate::finish::interactive_completion(&store.conn, checkout))
}
fn history(store: &Store, checkout: Uuid) -> Result<Option<journal::History>> {
    let _phase = store.sql_phase();
    checked(journal::history(&store.conn, checkout))
}
fn clean(store: &mut Store, checkout: Uuid) -> Result<(Captured, Vec<String>)> {
    let policies = checked(crate::disposal::validate(crate::disposal::PolicyDocument {
        format: 1,
        policies: vec![],
    }))?;
    let mut captured = checked(collect(
        store,
        checkout,
        &policies,
        #[cfg(test)]
        None,
    ))?;
    if captured.observation.coverage() != Coverage::Complete {
        return Err(format!(
            "inspection incomplete: {:?}",
            captured.observation.reasons()
        ));
    }
    if !captured.observation.findings().is_empty() {
        return Err("dirty, untracked or ignored content; commit or move it before removal".into());
    }
    let physical = captured
        .physical
        .as_mut()
        .ok_or("missing retained inspection")?;
    let inputs = &mut physical.before;
    let b = &mut captured.budget;
    for name in checked(inputs.private.list(b"", b))? {
        if ![
            b"HEAD".as_slice(),
            b"index",
            b"commondir",
            b"gitdir",
            b"work-lease.json",
            b"ORIG_HEAD",
            b"logs",
            b"refs",
            b"COMMIT_EDITMSG",
        ]
        .contains(&name.as_slice())
        {
            return Err("unsupported private Git artifact; retained for inspection".into());
        }
        if name == b"logs"
            && checked(inputs.private.list(b"logs", b))?
                .iter()
                .any(|name| name != b"HEAD")
        {
            return Err("unsupported private reflog".into());
        }
    }
    let roots = checked(preservation::interactive_roots(inputs, b))?;
    // A completed commit message is redundant only if its exact text is in a
    // commit being preserved. An edited/draft message remains a hold.
    if let Some(message) = checked(inputs.private.optional(b"COMMIT_EDITMSG", b))? {
        let path = &captured
            .context
            .as_ref()
            .ok_or("context missing")?
            .allocation
            .destination;
        let mut found = false;
        for root in &roots {
            let bytes = checked(git_success(
                Some(path),
                &["show", "-s", "--format=%B", root],
                b"",
                b,
            ))?;
            if bytes.strip_suffix(b"\n") == Some(message.as_slice()) {
                found = true;
                break;
            }
        }
        if !found {
            return Err("unpreserved private commit message".into());
        }
    }
    checked(physical.recheck(b)).map_err(|e| format!("retained physical recheck: {e}"))?;
    Ok((captured, roots))
}
fn identity(a: &crate::allocate::Allocation) -> Result<&crate::identity::CheckoutIdentity> {
    a.identity
        .as_ref()
        .ok_or_else(|| "missing checkout identity".into())
}
fn record(
    store: &Store,
    a: &crate::allocate::Allocation,
    roots: Vec<String>,
    b: &mut Budget,
) -> Result<Record> {
    let identity = identity(a)?;
    let common = checked(filesystem::Manifest::new(&identity.common_git_dir, b))?;
    let parent = checked(filesystem::Manifest::new(
        a.destination.parent().ok_or("missing parent")?,
        b,
    ))?;
    let private_parent = checked(filesystem::Manifest::new(
        identity
            .private_git_dir
            .parent()
            .ok_or("missing private parent")?,
        b,
    ))?;
    let _phase = store.sql_phase();
    let (allocation,finish_operation)=checked(store.conn.query_row("SELECT a.record,f.operation FROM allocations a JOIN task_finishes f ON a.checkout=f.checkout WHERE a.checkout=?1",[a.checkout.to_string()],|r|Ok((r.get(0)?,r.get(1)?))))?;
    Ok(Record {
        version: 1,
        allocation,
        finish_operation,
        common: common.root_dev_ino(),
        parent: parent.root_dev_ino(),
        private_parent: private_parent.root_dev_ino(),
        roots,
    })
}
fn preserve(a: &crate::allocate::Allocation, roots: &[String], b: &mut Budget) -> Result<()> {
    for (reference, root) in references(a.checkout, roots).iter().zip(roots) {
        let output = checked(git(
            Some(&a.destination),
            &["show-ref", "--verify", "--hash", reference],
            b"",
            b,
        ))?;
        if output.code == 0 {
            if output.stdout != format!("{root}\n").as_bytes() {
                return Err("recovery ref collision".into());
            }
        } else {
            // CAS never replaces existing refs. Unsupported/malformed state fails.
            checked(git_success(
                Some(&a.destination),
                &[
                    "-c",
                    "core.logAllRefUpdates=false",
                    "update-ref",
                    "--no-deref",
                    reference,
                    root,
                    &"0".repeat(root.len()),
                ],
                b"",
                b,
            ))?;
        }
    }
    Ok(())
}
fn verify_refs(
    common: &mut filesystem::Manifest,
    roots: &[String],
    checkout: Uuid,
    format: ObjectFormat,
    b: &mut Budget,
) -> Result<()> {
    let mut refs = match checked(common.optional(b"packed-refs", b))? {
        Some(bytes) => checked(packed_refs(&bytes, format))?,
        None => BTreeMap::new(),
    };
    checked(collect_refs(common, b"refs", 0, format, b, &mut refs))?;
    for (reference, root) in references(checkout, roots).iter().zip(roots) {
        if refs.get(reference.as_bytes()).map(Vec::as_slice) != Some(root.as_bytes()) {
            return Err("preservation ref missing or changed".into());
        }
    }
    Ok(())
}
/// Fresh native absence plus retained parent identities. Never merely Path::exists.
fn absent(a: &crate::allocate::Allocation, record: &Record, b: &mut Budget) -> Result<()> {
    let identity = identity(a)?;
    let mut parent = checked(filesystem::Manifest::new(
        a.destination.parent().ok_or("missing parent")?,
        b,
    ))?;
    if parent.root_dev_ino() != record.parent {
        return Err("removal parent identity changed".into());
    }
    checked(
        parent.absent(
            a.destination
                .file_name()
                .ok_or("missing basename")?
                .as_bytes(),
            b,
        ),
    )?;
    checked(parent.sync_path(b"", true, b))?;
    checked(parent.recheck(b))?;
    let mut common = checked(filesystem::Manifest::new(&identity.common_git_dir, b))?;
    if common.root_dev_ino() != record.common {
        return Err("common identity changed".into());
    }
    // Native Git removes the now-empty worktrees directory when deleting its
    // last registration. Anchor that absence at the retained common directory.
    match common.absent(b"worktrees", b) {
        Ok(()) => checked(common.sync_path(b"", true, b))?,
        Err(IncompleteReason::UnsupportedGit) => {
            let mut parent = checked(filesystem::Manifest::new(
                identity
                    .private_git_dir
                    .parent()
                    .ok_or("missing private parent")?,
                b,
            ))?;
            if parent.root_dev_ino() != record.private_parent {
                return Err("private parent identity changed".into());
            }
            checked(
                parent.absent(
                    identity
                        .private_git_dir
                        .file_name()
                        .ok_or("missing private basename")?
                        .as_bytes(),
                    b,
                ),
            )?;
            checked(parent.sync_path(b"", true, b))?;
            checked(parent.recheck(b))?;
        }
        Err(e) => return Err(format!("private registration absence: {e:?}")),
    }
    let format = if record.roots[0].len() == 40 {
        ObjectFormat::Sha1
    } else {
        ObjectFormat::Sha256
    };
    verify_refs(&mut common, &record.roots, a.checkout, format, b)?;
    let common_path = identity
        .common_git_dir
        .to_str()
        .ok_or("unsupported common path")?;
    let listing = checked(git_success(
        None,
        &[
            "--git-dir",
            common_path,
            "worktree",
            "list",
            "--porcelain",
            "-z",
        ],
        b"",
        b,
    ))?;
    let mut target = b"worktree ".to_vec();
    target.extend(a.destination.as_os_str().as_bytes());
    if listing.split(|c| *c == 0).any(|field| field == target) {
        return Err("registration still present".into());
    }
    checked(common.recheck(b)).map_err(|e| format!("absence common recheck: {e}"))?;
    Ok(())
}
#[allow(clippy::too_many_arguments)] // Keep retained guard, context and budget explicit at the commit boundary.
fn publish(
    store: &mut Store,
    guard: &crate::checkout_guard::CheckoutGuard,
    a: &crate::allocate::Allocation,
    operation: Uuid,
    record: &Record,
    phase: &str,
    context: Option<&Context>,
    b: &mut Budget,
) -> Result<()> {
    let lease = checked(store.authority_lease())?;
    checked(guard.revalidate_under_lease(store, &lease))?;
    let authority = store.authority_identity().clone();
    let schema = store.schema_participation();
    let role = store.schema_role();
    let _phase = store.sql_phase();
    let tx = checked(
        store
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
    )?;
    checked(role.validate(&tx))?;
    checked(crate::finish::interactive_completion(&tx, a.checkout))?;
    let previous = checked(journal::history(&tx, a.checkout))?;
    match (phase, previous) {
        ("intent", None) => {}
        ("native_succeeded", Some(h))
            if h.phase == "intent" && h.operation == operation && h.record == *record => {}
        ("removed", Some(h))
            if h.phase == "native_succeeded" && h.operation == operation && h.record == *record => {
        }
        _ => return Err("removal journal changed".into()),
    }
    if let Some(context) = context {
        let fresh = checked(snapshot_in_transaction(
            &tx, &authority, &schema, role, a.checkout, b,
        ))?;
        if fresh.canonical != context.canonical {
            return Err("lifecycle context changed".into());
        }
    }
    if phase == "removed" {
        let changed = checked(tx.execute(
            "UPDATE checkouts SET state='retired',ready=0 WHERE id=?1 AND state='held' AND ready=0",
            [a.checkout.to_string()],
        ))?;
        if changed != 1 {
            return Err("charge state changed".into());
        }
    }
    checked(journal::emit(&tx, a.checkout, operation, phase, record))?;
    checked(b.check())?;
    checked(tx.commit())
}
pub(crate) fn command(config: &Config, checkout: Uuid, confirmed: bool) -> Result<Report> {
    let mut store = checked(Store::open_existing_registered_mut(
        config
            .trusted_registry
            .as_deref()
            .ok_or("missing registry")?,
        config.store_dir.as_deref().ok_or("missing store")?,
        &config.roots,
    ))?;
    let guard = checked(crate::checkout_guard::CheckoutGuard::exclusive(
        &store, checkout,
    ))?;
    let allocation = completion(&store, checkout)?;
    let a = &allocation;
    let mut common = checked(AllocationCommonLock::acquire(
        &store,
        &identity(a)?.common_git_dir,
    ))?;
    if let Some(h) = history(&store, checkout)? {
        if h.phase == "intent" {
            return Err("previous removal outcome unknown; capacity held; manual investigation required (no replay)".into());
        }
        let mut b = Budget::new();
        absent(a, &h.record, &mut b)?;
        checked(common.revalidate(&store))?;
        checked(guard.revalidate(&store))?;
        if h.phase == "native_succeeded" {
            if !confirmed {
                return Err(
                    "native removal recorded; repeat with --confirm-stopped to reconcile capacity"
                        .into(),
                );
            }
            publish(
                &mut store,
                &guard,
                a,
                h.operation,
                &h.record,
                "removed",
                None,
                &mut b,
            )?;
        }
        return Ok(report(
            checkout,
            a.destination.clone(),
            &h.record.roots,
            true,
        ));
    }
    let (mut first, roots) =
        clean(&mut store, checkout).map_err(|e| format!("initial collection: {e}"))?;
    if !confirmed {
        return Ok(report(checkout, a.destination.clone(), &roots, false));
    }
    let record = record(&store, a, roots.clone(), &mut first.budget)?;
    checked(
        first
            .physical
            .as_ref()
            .ok_or("missing physical inputs")?
            .recheck(&mut first.budget),
    )?;
    preserve(a, &roots, &mut first.budget)?;
    // Our create-only refs changed common administration. Start a fresh retained
    // collection; do not waive the earlier collector's change detection.
    let (mut final_capture, final_roots) =
        clean(&mut store, checkout).map_err(|e| format!("final collection: {e}"))?;
    if roots != final_roots {
        return Err("private roots changed during preservation".into());
    }
    let physical = final_capture
        .physical
        .as_mut()
        .ok_or("missing final inputs")?;
    let b = &mut final_capture.budget;
    verify_refs(
        &mut physical.before.common,
        &roots,
        checkout,
        physical.before.format,
        b,
    )?;
    checked(recovery_refs::sync::sync_objects(
        &physical.before.common,
        b,
    ))
    .map_err(|e| format!("object sync: {e}"))?;
    checked(recovery_refs::sync::sync_refs(
        &physical.before.common,
        &references(checkout, &roots),
        physical.before.common.contains(b"packed-refs"),
        b,
    ))?;
    // Validate connectivity and object contents for every root before erasing
    // the only private reflog which may name it.
    let args: Vec<_> = std::iter::once("fsck")
        .chain(["--full", "--no-reflogs"])
        .chain(roots.iter().map(String::as_str))
        .collect();
    checked(git_success(Some(&a.destination), &args, b"", b))?;
    checked(physical.recheck(b)).map_err(|e| format!("retained physical recheck: {e}"))?;
    checked(common.revalidate(&store))?;
    checked(guard.revalidate(&store))?;
    let operation = Uuid::now_v7();
    publish(
        &mut store,
        &guard,
        a,
        operation,
        &record,
        "intent",
        final_capture.context.as_ref(),
        b,
    )?;
    #[cfg(test)]
    tests::boundary("after_intent")?;
    checked(common.revalidate(&store))?;
    checked(guard.revalidate(&store))?;
    checked(physical.recheck(b)).map_err(|e| format!("retained physical recheck: {e}"))?;
    let identity = identity(a)?;
    checked(git_success(
        None,
        &[
            "--git-dir",
            identity
                .common_git_dir
                .to_str()
                .ok_or("unsupported common path")?,
            "worktree",
            "remove",
            "--",
            a.destination.to_str().ok_or("unsupported checkout path")?,
        ],
        b"",
        b,
    ))?;
    #[cfg(test)]
    tests::boundary("after_native")?;
    absent(a, &record, b).map_err(|e| format!("absence check: {e}"))?;
    publish(
        &mut store,
        &guard,
        a,
        operation,
        &record,
        "native_succeeded",
        None,
        b,
    )?;
    #[cfg(test)]
    tests::boundary("after_result")?;
    absent(a, &record, b).map_err(|e| format!("absence check: {e}"))?;
    checked(common.revalidate(&store))?;
    publish(
        &mut store, &guard, a, operation, &record, "removed", None, b,
    )?;
    Ok(report(checkout, a.destination.clone(), &roots, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspection::fixture::ManagedFixture;
    use std::process::{Command, Output};
    thread_local! {
        static STOP: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    }
    pub(super) fn boundary(stage: &str) -> Result<()> {
        if STOP.with_borrow(|stop| stop.as_deref() == Some(stage)) {
            Err("injected interruption".into())
        } else {
            Ok(())
        }
    }
    #[test]
    fn cli_child() {
        let Ok(args) = std::env::var("WORK_REMOVAL_TEST_ARGS") else {
            return;
        };
        STOP.with_borrow_mut(|stop| *stop = std::env::var("WORK_REMOVAL_TEST_STOP").ok());
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        crate::cli::dispatch_public(&args.into_iter().map(Into::into).collect::<Vec<_>>());
        std::process::exit(0);
    }
    fn invoke(f: &ManagedFixture, args: &[&str], stop: Option<&str>) -> Output {
        let config = f.temp.path().join("interactive.toml");
        std::fs::write(
            &config,
            format!(
                "store_dir={:?}\ntrusted_registry={:?}\nroots=[{:?}]\n",
                f.temp.path().join("authority"),
                f.temp.path().join("registry"),
                f.root
            ),
        )
        .unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "inspection::removal::tests::cli_child",
                "--nocapture",
            ])
            .env("WORK_CONFIG", config)
            .env(
                "WORK_REMOVAL_TEST_ARGS",
                serde_json::to_string(args).unwrap(),
            )
            .env_remove("WORK_REMOVAL_TEST_STOP");
        if let Some(stop) = stop {
            command.env("WORK_REMOVAL_TEST_STOP", stop);
        }
        command.output().unwrap()
    }
    #[track_caller]
    fn json(output: Output) -> serde_json::Value {
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        serde_json::from_str(
            stdout
                .lines()
                .find(|line| line.starts_with('{'))
                .expect("JSON output"),
        )
        .unwrap()
    }
    #[test]
    fn recorded_native_success_reconciles_capacity_once_through_cli() {
        let f = ManagedFixture::new("sha1", "2");
        json(invoke(&f, &["finish", "inspection"], None));
        let interrupted = invoke(
            &f,
            &["remove", "inspection", "--confirm-stopped"],
            Some("after_result"),
        );
        assert!(!interrupted.status.success(), "{interrupted:?}");
        assert!(!f.allocation.destination.exists());
        assert_eq!(json(invoke(&f, &["status", "--json"], None))["charged"], 1);
        assert_eq!(
            json(invoke(
                &f,
                &["remove", "inspection", "--confirm-stopped"],
                None
            ))["outcome"],
            "removed"
        );
        let id = f.allocation.checkout.to_string();
        assert_eq!(
            json(invoke(&f, &["remove", &id, "--confirm-stopped"], None))["outcome"],
            "removed"
        );
        assert_eq!(json(invoke(&f, &["status", "--json"], None))["charged"], 0);
    }
    #[test]
    fn uncertain_dispatch_never_replays_or_deletes_a_recreated_path() {
        for stage in ["after_intent", "after_native", "after_result"] {
            let f = ManagedFixture::new("sha1", "2");
            json(invoke(&f, &["finish", "inspection"], None));
            let result = invoke(
                &f,
                &["remove", "inspection", "--confirm-stopped"],
                Some(stage),
            );
            assert!(!result.status.success(), "{stage}: {result:?}");
            assert_eq!(f.allocation.destination.exists(), stage == "after_intent");
            std::fs::create_dir_all(&f.allocation.destination).unwrap();
            let sentinel = f.allocation.destination.join("keep");
            std::fs::write(&sentinel, "new work").unwrap();
            let retry = invoke(&f, &["remove", "inspection", "--confirm-stopped"], None);
            assert!(!retry.status.success(), "{stage}: {retry:?}");
            assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "new work");
            assert_eq!(json(invoke(&f, &["status", "--json"], None))["charged"], 1);
        }
    }
}
