//! Small interactive interface over the existing lifecycle authority.
use crate::{
    config::Config,
    store::{Result, Store, StoreError},
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub(crate) struct Status {
    pub initialized: bool,
    pub charged: usize,
    pub checkouts: Vec<Checkout>,
}
#[derive(Serialize)]
pub(crate) struct Checkout {
    pub checkout: Uuid,
    pub task: String,
    pub owner: String,
    pub path: std::path::PathBuf,
    pub state: String,
    pub task_finished: bool,
    pub charged: bool,
    pub reason: Option<String>,
    pub next_action: &'static str,
}
pub(crate) fn open(config: &Config) -> Result<Store> {
    Store::open_existing_registered_readonly(
        config
            .trusted_registry
            .as_deref()
            .ok_or(StoreError::Invalid)?,
        config.store_dir.as_deref().ok_or(StoreError::Invalid)?,
        &config.roots,
    )
}
pub(crate) fn resolve(config: &Config, selector: &str) -> Result<Uuid> {
    let store = open(config)?;
    resolve_in_store(&store, selector)
}

pub(crate) fn resolve_finish(config: &Config, selector: &str) -> Result<Uuid> {
    // Finish already permits migration of validated established v8..=17
    // authority. Use that admission path before resolving either namespace;
    // status and removal previews keep their strictly read-only admission.
    let store = match open(config) {
        Ok(store) => store,
        Err(StoreError::UpgradeRequired) => Store::open_finish_authority(
            config
                .trusted_registry
                .as_deref()
                .ok_or(StoreError::Invalid)?,
            config.store_dir.as_deref().ok_or(StoreError::Invalid)?,
            &config.roots,
        )?,
        Err(error) => return Err(error),
    };
    resolve_in_store(&store, selector)
}

fn resolve_in_store(store: &Store, selector: &str) -> Result<Uuid> {
    let _phase = store.sql_phase();
    // A UUID-shaped task is legal. Match both namespaces against existing rows
    // and refuse a selector naming distinct checkouts instead of guessing.
    let id = Uuid::parse_str(selector).ok().map(|id| id.to_string());
    let mut query = store.conn.prepare("SELECT id FROM checkouts WHERE id=?2 OR (task=?1 AND (state!='retired' OR NOT EXISTS(SELECT 1 FROM checkouts WHERE task=?1 AND state!='retired'))) LIMIT 2")?;
    let mut rows = query.query(rusqlite::params![selector, id])?;
    let row = rows.next()?.ok_or(StoreError::Invalid)?;
    let id = match row.get_ref(0)? {
        rusqlite::types::ValueRef::Text(bytes) if bytes.len() == 36 => {
            Uuid::try_parse_ascii(bytes).map_err(|_| StoreError::Invalid)?
        }
        _ => return Err(StoreError::Invalid),
    };
    if id.get_version_num() != 7 || rows.next()?.is_some() {
        return Err(StoreError::Invalid);
    }
    Ok(id)
}

pub(crate) fn status(config: &Config) -> Result<Status> {
    let missing = |path: &std::path::Path| matches!(std::fs::symlink_metadata(path), Err(e) if e.kind()==std::io::ErrorKind::NotFound);
    if config.store_dir.as_deref().is_some_and(missing)
        && config.trusted_registry.as_deref().is_some_and(missing)
    {
        return Ok(Status {
            initialized: false,
            charged: 0,
            checkouts: vec![],
        });
    }
    let store = open(config)?;
    let _phase = store.sql_phase();
    let count: i64 = store
        .conn
        .query_row("SELECT count(*) FROM checkouts", [], |r| r.get(0))?;
    if count > 4096 {
        return Err(StoreError::Invalid);
    }
    let mut query = store.conn.prepare("SELECT c.id,c.task,c.owner,c.state,a.record FROM checkouts c LEFT JOIN allocations a ON a.checkout=c.id ORDER BY c.id")?;
    let mut rows = query.query([])?;
    let mut checkouts = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = rows.next()? {
        // Validate all borrowed columns before allocating any of this row.
        for column in 0..5 {
            match row.get_ref(column)? {
                rusqlite::types::ValueRef::Text(value) if value.len() <= 1024 * 1024 => {
                    bytes += value.len();
                }
                rusqlite::types::ValueRef::Null if column == 4 => {}
                _ => return Err(StoreError::Invalid),
            }
        }
        if bytes > 2 * 1024 * 1024 || checkouts.len() >= 4096 {
            return Err(StoreError::Invalid);
        }
        let (id, task, owner, state, record): (String, String, String, String, Option<String>) = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        );
        let checkout = Uuid::parse_str(&id).map_err(|_| StoreError::Invalid)?;
        let allocation: Option<crate::allocate::Allocation> = record
            .as_deref()
            .map(|body| {
                if body.len() > 1024 * 1024 {
                    return Err(StoreError::Invalid);
                }
                serde_json::from_str(body).map_err(|_| StoreError::Invalid)
            })
            .transpose()?;
        if allocation
            .as_ref()
            .is_some_and(|a| a.checkout != checkout || a.request.task != task)
        {
            return Err(StoreError::Invalid);
        }
        let task_finished = !crate::finish::task_open(&store.conn, checkout)?;
        let charged = state != "retired";
        let removal = crate::removal_journal::history(&store.conn, checkout)?;
        let mut reason = allocation.as_ref().and_then(|a| a.reason.clone());
        let next_action = match removal.as_ref().map(|h| h.phase.as_str()) {
            Some("intent") => {
                reason = Some("removal outcome unknown; charge retained".into());
                "manual investigation required; removal will not replay"
            }
            Some("native_succeeded") => {
                reason = Some("native removal recorded; charge reconciliation pending".into());
                "work remove TASK_OR_ID --confirm-stopped to reconcile capacity"
            }
            _ if !charged => "removed",
            _ if task_finished => {
                if crate::finish::interactive_completion(&store.conn, checkout).is_ok() {
                    "stop agents; preview work remove"
                } else {
                    reason = Some(
                        "historical run or capture state; interactive removal unavailable".into(),
                    );
                    "inspect historical state"
                }
            }
            _ if state == "active" => "work in checkout; then work finish",
            _ => "inspect held allocation",
        };
        checkouts.push(Checkout {
            checkout,
            task,
            owner,
            path: allocation.map(|a| a.destination).unwrap_or_default(),
            state,
            task_finished,
            charged,
            reason,
            next_action,
        });
    }
    Ok(Status {
        initialized: true,
        charged: checkouts.iter().filter(|r| r.charged).count(),
        checkouts,
    })
}
