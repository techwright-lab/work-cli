use crate::{
    events::Event,
    store::{
        canonical, count, emit, exclude_journal_identity, identity, Result, Store, StoreError,
    },
};
use rusqlite::{OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Reservation {
    pub operation: Uuid,
    pub repository: PathBuf,
    pub actor: String,
    pub owner: String,
    pub task: String,
}
/// Byte units are explicit. Measurements are supplied by the caller, outside
/// transactions. None means unknown, never zero or unlimited.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub repository: u64,
    pub owner: u64,
    pub available_bytes: Option<u64>,
    pub floor_bytes: u64,
    pub warn_bytes: u64,
}
impl Store {
    pub fn reserve(&mut self, request: &Reservation, limits: Limits) -> Result<Uuid> {
        self.reserve_recorded(request, limits, |_| Ok(None))
    }
    /// Attach the exact lifecycle intent to the charge in the same FULL commit.
    pub(crate) fn reserve_recorded(
        &mut self,
        request: &Reservation,
        limits: Limits,
        record: impl FnOnce(Uuid) -> Result<Option<(String, String)>>,
    ) -> Result<Uuid> {
        if request.operation.get_version_num() != 7
            || request.operation.get_variant() != uuid::Variant::RFC4122
        {
            return Err(StoreError::Invalid);
        }
        for value in [&request.actor, &request.owner, &request.task] {
            identity(value)?;
        }
        let repo = canonical(&request.repository)?;
        // Length-framed fields avoid concatenation ambiguity; policy/measurements are
        // deliberately not request identity, so retries work under reduced capacity.
        let mut hash = Sha256::new();
        for field in [
            "work-reservation-v1",
            &repo,
            &request.actor,
            &request.owner,
            &request.task,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        let digest = hash.finalize().to_vec();
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Check before exact retry acknowledgement as well as new charging.
        exclude_journal_identity(&tx, request.operation)?;
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1)
                OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1)",
            [request.operation.to_string()],
            |r| r.get(0),
        )?;
        if reserved {
            return Err(StoreError::Conflict);
        }
        // Its own prior checkouts.operation is deliberately not excluded:
        // immutable-digest reservation retries precede current capacity checks.
        let prior: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT id,digest FROM checkouts WHERE operation=?1",
                [request.operation.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, stored)) = prior {
            if stored != digest {
                return Err(StoreError::Conflict);
            }
            return Uuid::parse_str(&id).map_err(|_| StoreError::Invalid);
        }
        let retired: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM retired_owners WHERE owner=?1)",
            [&request.owner],
            |r| r.get(0),
        )?;
        if retired
            || limits.warn_bytes < limits.floor_bytes
            || limits
                .available_bytes
                .is_none_or(|b| b < limits.floor_bytes)
            || count(&tx, &repo, None)? >= limits.repository
            || count(&tx, &repo, Some(&request.owner))? >= limits.owner
        {
            return Err(StoreError::Capacity);
        }
        let checkout = Uuid::now_v7();
        exclude_journal_identity(&tx, checkout)?;
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkouts WHERE id=?1 OR operation=?1)
                OR EXISTS(SELECT 1 FROM writers WHERE group_id=?1)",
            [checkout.to_string()],
            |r| r.get(0),
        )?;
        if reserved || checkout == request.operation {
            return Err(StoreError::Conflict);
        }
        // Keep the original request digest immutable, including for pre-mapping
        // retries, while all new charges use the authority's common identity.
        tx.execute("INSERT INTO checkouts(id,operation,digest,repository,actor,task,owner) VALUES(?1,?2,?3,COALESCE((SELECT common FROM repository_aliases WHERE alias=?4),?4),?5,?6,?7)", rusqlite::params![checkout.to_string(),request.operation.to_string(),digest,repo,request.actor,request.task,request.owner])?;
        emit(
            &tx,
            &Event::Reserved {
                checkout,
                low_disk: limits
                    .available_bytes
                    .is_some_and(|b| b < limits.warn_bytes),
            },
        )?;
        if let Some((request_json, record_json)) = record(checkout)? {
            tx.execute(
                "INSERT INTO allocations VALUES(?1,?2,?3)",
                rusqlite::params![checkout.to_string(), request_json, record_json],
            )?;
        }
        tx.commit()?;
        Ok(checkout)
    }
}
