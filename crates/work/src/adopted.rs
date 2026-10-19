//! Adopted checkout/session declarations. No launch or quiescence authority.
use crate::{
    participants::{ParticipantRecord, Ref},
    run_journal::{BeginRun, RunIdentity},
    store::{Result, Store, StoreError},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use work_contract::RunId;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedRequest {
    pub operation: Uuid,
    pub identity: RunIdentity,
    pub source: Ref,
    pub session: Ref,
    pub agent: Ref,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdoptedStatus {
    pub request: AdoptedRequest,
    pub revision: u64,
    pub reconciliation_requested: bool,
    pub participants: Vec<ParticipantRecord>,
    pub writer_held: bool,
    pub adopted_basis: &'static str,
    pub runtime: &'static str,
    pub git_identity_controlled: bool,
    pub automatic_quiescence: bool,
}
// Full UTF-8 domain of 32 two-field ChainText entries (4096 scalars each),
// including JSON escaping, plus bounded identity references. Not a read-only cap.
pub(crate) const INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Fresh allocation verification, with no supervisor profile or runtime backend.
pub fn begin(
    config: &crate::config::Config,
    request: &AdoptedRequest,
) -> std::io::Result<BeginRun> {
    use crate::allocate::{db, err};
    request
        .validate()
        .map_err(|_| err("invalid adopted declaration"))?;
    if config
        .allocation
        .as_ref()
        .is_some_and(|p| p.capture_sink.is_some())
    {
        return Err(err("capture bridge unsupported"));
    }
    let (mut store, lock) = crate::allocate::locked(config)?;
    // Exact retries confer no new grant and do not refresh activity or Git metadata.
    if store.adopted_status(&request.identity.run).is_ok() {
        return db(store.begin_adopted(request));
    }
    crate::allocate::verified_checkout(
        &mut store,
        uuid(&request.identity.checkout).map_err(|_| err("invalid checkout"))?,
    )?;
    let result = db(store.begin_adopted(request));
    drop(lock);
    result
}
#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Read a typed AdoptedRequest JSON from dedicated stdin; never launch an actor
    Begin,
    /// Read typed Activity JSON from dedicated hook-process stdin (not delegate stdio)
    Event,
    /// Read-only adopted declarations; never inspect or certify runtime
    Status { run: Uuid },
}
fn paths(config: &crate::config::Config) -> Result<(&std::path::Path, &std::path::Path)> {
    if config.roots.is_empty() {
        return Err(StoreError::Unsafe);
    }
    Ok((
        config
            .trusted_registry
            .as_deref()
            .ok_or(StoreError::Unsafe)?,
        config.store_dir.as_deref().ok_or(StoreError::Unsafe)?,
    ))
}
fn input<T: serde::de::DeserializeOwned>() -> Result<T> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > INPUT_BYTES {
        return Err(StoreError::Invalid);
    }
    serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)
}
pub fn command(config: &crate::config::Config, command: Command) -> Result<String> {
    match command {
        Command::Begin => {
            let request: AdoptedRequest = input()?;
            let result = begin(config, &request).map_err(|_| StoreError::Invalid)?;
            Ok(if result == BeginRun::Created {
                "created"
            } else {
                "existing"
            }
            .into())
        }
        Command::Event => {
            let event: crate::participants::Activity = input()?;
            if config
                .allocation
                .as_ref()
                .is_some_and(|p| p.capture_sink.is_some())
            {
                return Err(StoreError::Invalid);
            }
            let (registry, dir) = paths(config)?;
            let mut store = Store::open_existing_registered_mut(registry, dir, &config.roots)?;
            let result = store.record_activity(&event)?;
            Ok(if result == crate::run_journal::Transition::Changed {
                "changed"
            } else {
                "existing"
            }
            .into())
        }
        Command::Status { run } => {
            let run = RunId::parse(&run.to_string()).map_err(|_| StoreError::Invalid)?;
            let (registry, dir) = paths(config)?;
            let store = Store::open_existing_registered_readonly(registry, dir, &config.roots)?;
            json(&store.adopted_status(&run)?)
        }
    }
}
impl AdoptedRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        let i = &self.identity;
        let ids = [
            self.operation.to_string(),
            i.checkout.to_string(),
            i.group.to_string(),
            i.run.to_string(),
        ];
        if self.operation.get_version_num() != 7
            || self.operation.get_variant() != uuid::Variant::RFC4122
            || ids
                .iter()
                .enumerate()
                .any(|(n, id)| ids[n + 1..].contains(id))
        {
            return Err(StoreError::Invalid);
        }
        Ref::new(i.actor.as_str().into())?;
        Ref::new(i.run_ref.as_str().into())?;
        if let Some(parent) = &i.parent_run_ref {
            Ref::new(parent.as_str().into())?;
        }
        Ok(())
    }
}
pub(crate) fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| StoreError::Invalid)
}
pub(crate) fn uuid(value: &impl std::fmt::Display) -> Result<Uuid> {
    Uuid::parse_str(&value.to_string()).map_err(|_| StoreError::Invalid)
}
pub(crate) fn read(
    conn: &rusqlite::Connection,
    run: &RunId,
) -> Result<Option<(AdoptedRequest, u64, bool)>> {
    use rusqlite::OptionalExtension;
    type StoredGroup = (String, i64, bool, String, String, String, String, String);
    let row: Option<StoredGroup> = conn.query_row(
        "SELECT CASE WHEN length(CAST(request AS BLOB))<=4194304 THEN request ELSE '' END,revision,reconcile,id,checkout,run_id,run_ref,operation FROM adopted_groups WHERE run_id=?1",
        [run.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
    row.map(
        |(body, revision, reconcile, group, checkout, id, run_ref, operation)| {
            let request: AdoptedRequest =
                serde_json::from_str(&body).map_err(|_| StoreError::Invalid)?;
            request.validate()?;
            let i = &request.identity;
            if revision <= 0
                || i.group.to_string() != group
                || i.checkout.to_string() != checkout
                || i.run.to_string() != id
                || i.run_ref.as_str() != run_ref
                || request.operation.to_string() != operation
            {
                return Err(StoreError::Invalid);
            }
            Ok((request, revision as u64, reconcile))
        },
    )
    .transpose()
}
pub(crate) fn journal_event(
    conn: &rusqlite::Connection,
    request: &AdoptedRequest,
    revision: u64,
) -> Result<()> {
    crate::store::emit(
        conn,
        &crate::events::Event::AdoptedJournalChanged {
            checkout: uuid(&request.identity.checkout)?,
            group: uuid(&request.identity.group)?,
            run: uuid(&request.identity.run)?,
            revision,
        },
    )
}
impl Store {
    /// Low-level transaction on an active/ready allocation. Integrated callers
    /// MUST use begin(), which performs fresh lease verification under the allocator lock.
    pub fn begin_adopted(&mut self, request: &AdoptedRequest) -> Result<BeginRun> {
        request.validate()?;
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let i = &request.identity;
        if let Some((existing, _, _)) = read(&tx, &i.run)? {
            if &existing != request {
                return Err(StoreError::Conflict);
            }
            held(&tx, request)?;
            return Ok(BeginRun::Existing);
        }
        let ids = [
            i.group.to_string(),
            i.run.to_string(),
            request.operation.to_string(),
        ];
        let conflict: bool = tx.query_row("SELECT
            EXISTS(SELECT 1 FROM runs WHERE run_ref=?1 OR id IN (?2,?3,?4) OR group_id IN (?2,?3,?4))
            OR EXISTS(SELECT 1 FROM run_groups WHERE id IN (?2,?3,?4))
            OR EXISTS(SELECT 1 FROM adopted_groups WHERE run_ref=?1 OR id IN (?2,?3,?4) OR run_id IN (?2,?3,?4) OR operation IN (?2,?3,?4))
            OR EXISTS(SELECT 1 FROM checkouts WHERE id IN (?2,?3,?4) OR operation IN (?2,?3,?4))
            OR EXISTS(SELECT 1 FROM writers WHERE group_id IN (?2,?3,?4))",
            (i.run_ref.as_str(), &ids[0], &ids[1], &ids[2]), |r| r.get(0))?;
        if conflict {
            return Err(StoreError::Conflict);
        }
        crate::store::acquire_writer_tx(&tx, uuid(&i.checkout)?, uuid(&i.group)?, false)?;
        tx.execute("INSERT INTO adopted_groups(id,checkout,run_id,run_ref,operation,request,revision) VALUES(?1,?2,?3,?4,?5,?6,1)",
            (i.group.to_string(),i.checkout.to_string(),i.run.to_string(),i.run_ref.as_str(),request.operation.to_string(),json(request)?))?;
        tx.execute("INSERT INTO adopted_sessions(group_id,source,session,agent,actor,parent,closed,depth) VALUES(?1,?2,?3,?4,?5,NULL,0,0)",
            (i.group.to_string(),request.source.as_str(),request.session.as_str(),request.agent.as_str(),i.actor.as_str()))?;
        journal_event(&tx, request, 1)?;
        tx.commit()?;
        Ok(BeginRun::Created)
    }
    /// Read-only declarations; never inspect processes or infer physical exit.
    pub fn adopted_status(&self, run: &RunId) -> Result<AdoptedStatus> {
        let _phase = self.sql_phase();
        let (request, revision, reconciliation_requested) =
            read(&self.conn, run)?.ok_or(StoreError::Invalid)?;
        held(&self.conn, &request)?;
        let participants = crate::participants::roster(&self.conn, &request)?;
        Ok(AdoptedStatus {
            request,
            revision,
            reconciliation_requested,
            participants,
            writer_held: true,
            adopted_basis: "checkout/session declaration",
            runtime: "unknown",
            git_identity_controlled: false,
            automatic_quiescence: false,
        })
    }
}
pub(crate) fn held(conn: &rusqlite::Connection, request: &AdoptedRequest) -> Result<()> {
    let held: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM writers WHERE checkout=?1 AND group_id=?2)",
        (
            request.identity.checkout.to_string(),
            request.identity.group.to_string(),
        ),
        |r| r.get(0),
    )?;
    if !held {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
