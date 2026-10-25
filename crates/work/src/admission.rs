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
pub(crate) struct AllocationIntent {
    pub(crate) request: String,
    pub(crate) record: String,
    pub(crate) capture_required: bool,
}
pub(crate) enum ReservationPurpose<'a> {
    SqlOnly,
    Allocation(&'a [(PathBuf, PathBuf)]),
}

pub(crate) struct RecordedReservation {
    pub(crate) checkout: Uuid,
    pub(crate) guard: Option<crate::checkout_guard::CheckoutGuard>,
}

/// Read-only selection against the union of durable and staged aliases. Retain
/// both the effective map and missing delta for the final transaction comparison;
/// an equal union alone cannot detect publication racing the guarded selection.
#[derive(PartialEq, Eq)]
pub(crate) struct AllocationSelection {
    aliases: std::collections::BTreeMap<String, String>,
    // Computed from the durable map, never accepted as caller-provided truth.
    pub(crate) missing_aliases: Vec<(PathBuf, PathBuf)>,
    prior: Option<Uuid>,
    pub(crate) matches: Vec<Uuid>,
}

pub(crate) fn allocation_selection(
    conn: &rusqlite::Connection,
    request: &Reservation,
    staged: &[(PathBuf, PathBuf)],
) -> Result<AllocationSelection> {
    let mut aliases = std::collections::BTreeMap::<String, String>::new();
    let mut stmt = conn.prepare("SELECT alias,common FROM repository_aliases ORDER BY alias")?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (alias, common) = row?;
        aliases.insert(alias, common);
    }
    let mut missing_aliases = Vec::new();
    for (alias, common) in staged {
        let alias = alias.to_str().ok_or(StoreError::Invalid)?;
        let common = common.to_str().ok_or(StoreError::Invalid)?;
        if aliases.get(alias).is_some_and(|stored| stored != common) {
            return Err(StoreError::Conflict);
        }
        if !aliases.contains_key(alias) {
            missing_aliases.push((PathBuf::from(alias), PathBuf::from(common)));
        }
        aliases.insert(alias.to_owned(), common.to_owned());
    }
    let prior: Option<String> = conn
        .query_row(
            "SELECT id FROM checkouts WHERE operation=?1",
            [request.operation.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let repo = request.repository.to_str().ok_or(StoreError::Invalid)?;
    let common = aliases.get(repo).map(String::as_str).unwrap_or(repo);
    let mut matches = Vec::new();
    let mut stmt = conn.prepare("SELECT id,repository FROM checkouts WHERE actor=?1 AND task=?2 AND state!='retired' ORDER BY id")?;
    for row in stmt.query_map((&request.actor, &request.task), |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })? {
        let (id, repository) = row?;
        if aliases
            .get(&repository)
            .map(String::as_str)
            .unwrap_or(&repository)
            == common
        {
            matches.push(crate::retirement_journal::parse_uuid(&id)?);
        }
    }
    Ok(AllocationSelection {
        aliases,
        missing_aliases,
        prior: prior
            .as_deref()
            .map(crate::retirement_journal::parse_uuid)
            .transpose()?,
        matches,
    })
}

pub(crate) fn allocation_scope(
    missing_aliases: &[(PathBuf, PathBuf)],
    checkouts: Vec<Uuid>,
) -> Result<crate::retirement_journal::Scope> {
    let mut repositories = std::collections::BTreeSet::new();
    for (alias, common) in missing_aliases {
        repositories.insert(alias.to_str().ok_or(StoreError::Invalid)?.to_owned());
        repositories.insert(common.to_str().ok_or(StoreError::Invalid)?.to_owned());
    }
    Ok(crate::retirement_journal::Scope::Allocation {
        checkouts: checkouts.into_iter().collect(),
        repositories,
    })
}

/// Called only after the by-value outer fence and guarded selection comparison.
pub(crate) fn publish_aliases(
    conn: &rusqlite::Connection,
    staged: &[(PathBuf, PathBuf)],
) -> Result<()> {
    for (alias, common) in staged {
        let alias = alias.to_str().ok_or(StoreError::Invalid)?;
        let common = common.to_str().ok_or(StoreError::Invalid)?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT common FROM repository_aliases WHERE alias=?1",
                [alias],
                |r| r.get(0),
            )
            .optional()?;
        if existing.as_deref().is_some_and(|value| value != common) {
            return Err(StoreError::Conflict);
        }
        conn.execute(
            "INSERT OR IGNORE INTO repository_aliases VALUES(?1,?2)",
            (alias, common),
        )?;
    }
    Ok(())
}

fn candidate() -> Uuid {
    let checkout = Uuid::now_v7();
    #[cfg(test)]
    let checkout = candidate_fixture::CHECKOUT
        .with(|slot| slot.take())
        .unwrap_or(checkout);
    checkout
}

impl Store {
    pub fn reserve(&mut self, request: &Reservation, limits: Limits) -> Result<Uuid> {
        let lease = self.authority_lease()?;
        self.reserve_recorded_under_lease(
            request,
            limits,
            |_| Ok(None),
            &lease,
            ReservationPurpose::SqlOnly,
        )
        .map(|recorded| recorded.checkout)
    }
    /// Borrow the allocator's exact lease; never recursively acquire it. Physical
    /// allocation owns SH from the read selection through the caller's final ACK.
    pub(crate) fn reserve_recorded_under_lease(
        &mut self,
        request: &Reservation,
        limits: Limits,
        record: impl FnOnce(Uuid) -> Result<Option<AllocationIntent>>,
        lease: &crate::allocate::AuthorityLease,
        purpose: ReservationPurpose<'_>,
    ) -> Result<RecordedReservation> {
        lease.check(self)?;
        let authority = self.authority_identity().clone();
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
        let staged = match purpose {
            ReservationPurpose::SqlOnly => &[][..],
            ReservationPurpose::Allocation(aliases) => aliases,
        };
        let selection = if matches!(purpose, ReservationPurpose::Allocation(_)) {
            let phase = self.sql_phase();
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Deferred)?;
            let selection = allocation_selection(&tx, request, staged)?;
            tx.rollback()?;
            drop(phase);
            Some(selection)
        } else {
            None
        };
        let checkout = selection
            .as_ref()
            .and_then(|value| value.prior.or_else(|| value.matches.first().copied()))
            .unwrap_or_else(candidate);
        // Sole permitted reverse-order acquisition: one nonblocking SH while
        // already leased, with no live transaction and no caller writes yet.
        let guard = if selection.is_some() {
            Some(crate::checkout_guard::CheckoutGuard::shared(
                self, checkout,
            )?)
        } else {
            None
        };
        let other_guards =
            if let Some(selected) = selection.as_ref().filter(|value| value.prior.is_none()) {
                selected
                    .matches
                    .iter()
                    .filter(|id| **id != checkout)
                    .map(|id| crate::checkout_guard::CheckoutGuard::shared(self, *id))
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
        for held in guard.iter().chain(other_guards.iter()) {
            held.revalidate(self)?;
        }
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT id,digest FROM checkouts WHERE operation=?1",
                [request.operation.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let mut selected = selection
            .as_ref()
            .map(|value| value.matches.clone())
            .unwrap_or_default();
        selected.push(checkout);
        if let Some((id, _)) = &prior {
            selected.push(crate::retirement_journal::parse_uuid(id)?);
        }
        let current = selection
            .as_ref()
            .map(|_| allocation_selection(&tx, request, staged))
            .transpose()?;
        if let Some(current) = &current {
            selected.extend(current.matches.iter().copied());
        }
        // Exact retries publish no aliases. New allocation publication fences
        // only its actual missing delta, resolved again in this same transaction.
        let missing = current
            .as_ref()
            .filter(|value| value.prior.is_none())
            .map(|value| value.missing_aliases.as_slice())
            .unwrap_or_default();
        let scope = if let Some((id, _)) = &prior {
            crate::retirement_journal::Scope::Checkout(crate::retirement_journal::parse_uuid(id)?)
        } else if selection.is_none() {
            crate::retirement_journal::Scope::Checkout(checkout)
        } else {
            allocation_scope(missing, selected)?
        };
        let tx = crate::retirement_journal::fence(
            tx,
            lease,
            &authority,
            scope,
            crate::retirement_journal::Attempt::Reserve,
        )?;
        if let Some(expected) = &selection {
            if current.as_ref() != Some(expected)
                || (expected.prior.is_none() && !expected.matches.is_empty())
            {
                return Err(StoreError::Conflict);
            }
        }
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
            let id = crate::retirement_journal::parse_uuid(&id)?;
            if guard.is_some() && id != checkout {
                return Err(StoreError::Conflict);
            }
            tx.commit()?;
            return Ok(RecordedReservation {
                checkout: id,
                guard,
            });
        }
        // Staged aliases become visible only with the successful charge. The
        // existing count implementation now sees legacy charges through them;
        // capacity/collision/callback failures roll the aliases back as well.
        publish_aliases(&tx, missing)?;
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
        if let Some(intent) = record(checkout)? {
            tx.execute(
                "INSERT INTO allocations VALUES(?1,?2,?3)",
                rusqlite::params![checkout.to_string(), intent.request, intent.record],
            )?;
            if intent.capture_required {
                crate::capture_requirement::insert(&tx, checkout, request.operation)?;
            }
        }
        tx.commit()?;
        Ok(RecordedReservation { checkout, guard })
    }
}
#[cfg(test)]
mod allocation_tests {
    use super::*;
    use crate::checkout_guard::CheckoutGuard;

    fn fixture() -> (
        tempfile::TempDir,
        Store,
        Reservation,
        Vec<(PathBuf, PathBuf)>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let common = root.join("common");
        std::fs::create_dir(&common).unwrap();
        let store = Store::open(&dir.path().join("private"), std::slice::from_ref(&root)).unwrap();
        let aliases = vec![(root, common.clone())];
        let request = Reservation {
            operation: Uuid::now_v7(),
            repository: common,
            actor: "actor".into(),
            owner: "actor".into(),
            task: "task".into(),
        };
        (dir, store, request, aliases)
    }

    fn limits() -> Limits {
        Limits {
            repository: 10,
            owner: 10,
            available_bytes: Some(100),
            floor_bytes: 0,
            warn_bytes: 0,
        }
    }

    fn rows(store: &Store) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        [
            "checkouts",
            "allocations",
            "capture_requirements",
            "repository_aliases",
            "outbox",
        ]
        .into_iter()
        .map(|table| {
            let mut statement = store
                .conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns).map(|column| row.get(column)).collect()
                })
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        })
        .collect()
    }

    // Structural journal evidence only, not a public prepared capability.
    fn seed_prepared(store: &Store, checkout: Uuid) -> Uuid {
        use crate::retirement_journal::{
            encode_record, ImmutableBinding, IntentRecord, Mode, Stage,
        };
        let operation = Uuid::now_v7();
        let digest = "01".repeat(32);
        let record = IntentRecord {
            version: 1,
            operation: operation.to_string(),
            checkout: checkout.to_string(),
            mode: Mode::Supervised,
            revision: 1,
            stage: Stage::Prepared,
            assertion: None,
            declaration: None,
            predecessor_hex: digest.clone(),
            source_hex: digest.clone(),
            history_predecessor_hex: digest.clone(),
            prior_history_count: 0,
            immutable_binding: ImmutableBinding {
                version: 1,
                authority_allocation: digest.clone(),
                source_sql: digest.clone(),
                managed_physical: digest.clone(),
                census: digest.clone(),
                git_private: digest.clone(),
                local_git: digest.clone(),
                git_inputs: digest.clone(),
                source_commitment: digest.clone(),
                approval_semantic: digest.clone(),
                approval_invalidation: digest.clone(),
                protection: digest.clone(),
                protection_count: 0,
                config_manifests: [digest.clone(), digest.clone()],
                inspection_policy: digest.clone(),
                combined_policy: digest.clone(),
                operator: digest.clone(),
                source_repository: digest.clone(),
            },
            quiescence: "empty".into(),
            task_completion: "supervised_empty".into(),
            policy_digest: digest.clone(),
            combined_policy_digest: digest,
            prepared_wall_ms: 1,
            remote_cleanup: "not_required".into(),
        };
        let record = encode_record(&record).unwrap();
        store.conn.execute("INSERT INTO retirement_intents(operation,checkout,revision,stage,mode,predecessor,source,record) VALUES(?1,?2,1,'prepared','supervised',?3,?3,?4)",
            rusqlite::params![operation.to_string(), checkout.to_string(), &[1u8;32][..], record]).unwrap();
        operation
    }

    #[test]
    fn reserved_retry_commits_retirement_hold_before_existing_once() {
        for allocation in [false, true] {
            let (_dir, mut store, request, aliases) = fixture();
            let checkout = store.reserve(&request, limits()).unwrap();
            let operation = seed_prepared(&store, checkout);
            let before = rows(&store);
            for _ in 0..2 {
                let result = if allocation {
                    let lease = store.authority_lease().unwrap();
                    store
                        .reserve_recorded_under_lease(
                            &request,
                            limits(),
                            |_| panic!("fenced retry must not call intent"),
                            &lease,
                            ReservationPurpose::Allocation(&aliases),
                        )
                        .map(|record| record.checkout)
                } else {
                    store.reserve(&request, limits())
                };
                assert!(matches!(result, Err(StoreError::RetirementFenced)));
                let (revision, stage, reason): (i64, String, String) = store.conn.query_row(
                    "SELECT revision,stage,held_reason FROM retirement_intents WHERE operation=?1",
                    [operation.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                assert_eq!(
                    (revision, stage.as_str(), reason.as_str()),
                    (2, "held", "reserve")
                );
                let after = rows(&store);
                assert_eq!(&after[..4], &before[..4]);
                assert_eq!(after[4].len(), before[4].len() + 1);
            }
        }
    }

    #[test]
    fn published_aliases_do_not_fence_independent_allocation() {
        let (_dir, mut store, request, aliases) = fixture();
        publish_aliases(&store.conn, &aliases).unwrap();
        let legacy = Reservation {
            operation: Uuid::now_v7(),
            actor: "other".into(),
            task: "other".into(),
            ..request.clone()
        };
        let a = store.reserve(&legacy, limits()).unwrap();
        let operation = seed_prepared(&store, a);
        let history = crate::retirement_journal::load_operation(&store.conn, operation).unwrap();
        let lease = store.authority_lease().unwrap();
        let result = store
            .reserve_recorded_under_lease(
                &request,
                limits(),
                |_| Ok(None),
                &lease,
                ReservationPurpose::Allocation(&aliases),
            )
            .unwrap();
        assert_ne!(result.checkout, a);
        assert_eq!(
            crate::retirement_journal::load_operation(&store.conn, operation).unwrap(),
            history
        );
        let after = rows(&store);
        let retry = store
            .reserve_recorded_under_lease(
                &request,
                limits(),
                |_| panic!("Existing does not call intent"),
                &lease,
                ReservationPurpose::Allocation(&aliases),
            )
            .unwrap();
        assert_eq!(retry.checkout, result.checkout);
        assert_eq!(rows(&store), after);
    }

    #[test]
    fn allocation_retry_scopes_actual_checkout_without_publishing_missing_aliases() {
        let (_dir, mut store, request, aliases) = fixture();
        let other = Reservation {
            operation: Uuid::now_v7(),
            ..request.clone()
        };
        let a = store.reserve(&other, limits()).unwrap();
        let b = store.reserve(&request, limits()).unwrap();
        let operation = seed_prepared(&store, a);
        let history = crate::retirement_journal::load_operation(&store.conn, operation).unwrap();
        let before = rows(&store);
        let lease = store.authority_lease().unwrap();
        let retry = store
            .reserve_recorded_under_lease(
                &request,
                limits(),
                |_| panic!("retry must not publish intent"),
                &lease,
                ReservationPurpose::Allocation(&aliases),
            )
            .unwrap();
        assert_eq!(retry.checkout, b);
        assert_eq!(rows(&store), before);
        assert_eq!(
            crate::retirement_journal::load_operation(&store.conn, operation).unwrap(),
            history
        );
    }

    #[test]
    fn selection_detects_published_delta_even_when_effective_alias_map_is_identical() {
        let (_dir, store, request, aliases) = fixture();
        let lease = store.authority_lease().unwrap();
        lease.check(&store).unwrap();
        let before = allocation_selection(&store.conn, &request, &aliases).unwrap();
        publish_aliases(&store.conn, &aliases).unwrap();
        let after = allocation_selection(&store.conn, &request, &aliases).unwrap();
        assert!(
            before != after,
            "final CAS must bind durable map as well as its effective union"
        );
    }

    #[test]
    fn all_staged_alias_repositories_are_fenced_in_one_atomic_batch() {
        let (_dir, mut store, request, mut aliases) = fixture();
        let other = aliases[0].0.join("other");
        std::fs::create_dir(&other).unwrap();
        let mut checkouts = Vec::new();
        for repository in [&aliases[0].0, &other] {
            let legacy = Reservation {
                operation: Uuid::now_v7(),
                repository: repository.clone(),
                actor: "old".into(),
                owner: "old".into(),
                task: "old".into(),
            };
            let checkout = store.reserve(&legacy, limits()).unwrap();
            seed_prepared(&store, checkout);
            checkouts.push(checkout);
        }
        aliases.push((other.clone(), other));
        checkouts.sort();
        // The later hold write fails: no earlier held row/event may commit.
        store.conn.execute_batch(&format!("CREATE TRIGGER refuse_hold BEFORE UPDATE ON retirement_intents WHEN NEW.checkout='{}' BEGIN SELECT RAISE(ABORT,'owned hold fault'); END;", checkouts[1])).unwrap();
        let before = rows(&store);
        let lease = store.authority_lease().unwrap();
        let result = store.reserve_recorded_under_lease(
            &request,
            limits(),
            |_| panic!("fence precedes caller intent"),
            &lease,
            ReservationPurpose::Allocation(&aliases),
        );
        assert!(matches!(result, Err(StoreError::Database(_))));
        assert_eq!(rows(&store), before);
        assert_eq!(
            store
                .conn
                .query_row(
                    "SELECT count(*) FROM retirement_intents WHERE stage='prepared'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        store
            .conn
            .execute_batch("DROP TRIGGER refuse_hold;")
            .unwrap();
        for _ in 0..2 {
            let result = store.reserve_recorded_under_lease(
                &request,
                limits(),
                |_| panic!("fence precedes caller intent"),
                &lease,
                ReservationPurpose::Allocation(&aliases),
            );
            assert!(matches!(result, Err(StoreError::RetirementFenced)));
            assert_eq!(
                store
                    .conn
                    .query_row(
                        "SELECT count(*) FROM retirement_intents WHERE stage='held' AND revision=2",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                2
            );
            let after = rows(&store);
            assert_eq!(&after[..4], &before[..4]);
            assert_eq!(after[4].len(), before[4].len() + 2);
        }
    }

    #[test]
    fn candidate_guard_contention_precedes_every_caller_write() {
        let (_dir, mut store, request, aliases) = fixture();
        let checkout = Uuid::now_v7();
        let exclusive = CheckoutGuard::exclusive(&store, checkout).unwrap();
        candidate_fixture::CHECKOUT.with(|slot| slot.set(Some(checkout)));
        let lease = store.authority_lease().unwrap();
        let before = rows(&store);
        let mut called = false;
        let result = store.reserve_recorded_under_lease(
            &request,
            limits(),
            |_| {
                called = true;
                Ok(None)
            },
            &lease,
            ReservationPurpose::Allocation(&aliases),
        );
        assert!(matches!(result, Err(StoreError::OperationsInFlight)));
        assert!(!called);
        assert_eq!(rows(&store), before);
        drop(exclusive);
    }

    #[test]
    fn borrowed_lease_keeps_atomic_intent_capture_and_owned_guard() {
        let (_dir, mut store, request, aliases) = fixture();
        let lease = store.authority_lease().unwrap();
        let reservation = store
            .reserve_recorded_under_lease(
                &request,
                limits(),
                |checkout| {
                    Ok(Some(AllocationIntent {
                        request: format!("request:{checkout}"),
                        record: format!("record:{checkout}"),
                        capture_required: true,
                    }))
                },
                &lease,
                ReservationPurpose::Allocation(&aliases),
            )
            .unwrap();
        let checkout = reservation.checkout;
        let guard = reservation.guard.unwrap();
        guard.require_matching(&store, checkout).unwrap();
        assert!(matches!(
            CheckoutGuard::exclusive(&store, checkout),
            Err(StoreError::OperationsInFlight)
        ));
        assert_eq!(
            store
                .conn
                .query_row(
                    "SELECT count(*) FROM allocations WHERE checkout=?1",
                    [checkout.to_string()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert!(crate::capture_requirement::present(&store.conn, checkout).unwrap());
        let before = rows(&store);
        let retry = store
            .reserve_recorded_under_lease(
                &request,
                Limits {
                    repository: 0,
                    ..limits()
                },
                |_| panic!("retry must not recreate intent"),
                &lease,
                ReservationPurpose::Allocation(&aliases),
            )
            .unwrap();
        assert_eq!(retry.checkout, checkout);
        assert_eq!(rows(&store), before);
        drop(retry);
        drop(guard);
        CheckoutGuard::exclusive(&store, checkout).unwrap();
    }

    #[test]
    fn staged_alias_capacity_failure_keeps_legacy_charge_and_rolls_back_aliases() {
        let (_dir, mut store, request, aliases) = fixture();
        let legacy = Reservation {
            repository: aliases[0].0.clone(),
            actor: "legacy".into(),
            owner: "legacy".into(),
            task: "legacy".into(),
            operation: Uuid::now_v7(),
        };
        store.reserve(&legacy, limits()).unwrap();
        let before = rows(&store);
        let lease = store.authority_lease().unwrap();
        let result = store.reserve_recorded_under_lease(
            &request,
            Limits {
                repository: 1,
                ..limits()
            },
            |_| panic!("capacity denial precedes intent"),
            &lease,
            ReservationPurpose::Allocation(&aliases),
        );
        assert!(matches!(result, Err(StoreError::Capacity)));
        assert_eq!(rows(&store), before);
        assert_eq!(store.charged(&legacy.repository, None).unwrap(), 1);
    }

    #[test]
    fn candidate_collision_rolls_back_staged_aliases() {
        let (_dir, mut store, request, aliases) = fixture();
        candidate_fixture::CHECKOUT.with(|slot| slot.set(Some(request.operation)));
        let before = rows(&store);
        let lease = store.authority_lease().unwrap();
        let result = store.reserve_recorded_under_lease(
            &request,
            limits(),
            |_| panic!("collision precedes intent"),
            &lease,
            ReservationPurpose::Allocation(&aliases),
        );
        assert!(matches!(result, Err(StoreError::Conflict)));
        assert_eq!(rows(&store), before);
    }
}

#[cfg(test)]
pub(crate) mod candidate_fixture {
    thread_local! {
        pub(crate) static CHECKOUT: std::cell::Cell<Option<uuid::Uuid>> = const { std::cell::Cell::new(None) };
    }
}
