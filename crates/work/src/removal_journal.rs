//! Append-only interactive removal history in the existing durable outbox.
//! Acknowledgment does not delete events. No history record authorizes a new
//! native dispatch: only this invocation's fresh retained inspection can do so.
use crate::{
    events::Event,
    store::{Result, StoreError},
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub version: u32,
    pub allocation: String,
    pub finish_operation: String,
    pub common: (u64, u64),
    pub parent: (u64, u64),
    pub private_parent: (u64, u64),
    pub roots: Vec<String>,
}
pub(crate) struct History {
    pub operation: Uuid,
    pub record: Record,
    pub phase: String,
}
pub(crate) fn history(conn: &Connection, checkout: Uuid) -> Result<Option<History>> {
    let mut query = conn.prepare("SELECT payload FROM outbox WHERE json_extract(payload,'$.type')='interactive_removal' AND json_extract(payload,'$.checkout')=?1 ORDER BY sequence LIMIT 4")?;
    let rows = query
        .query_map([checkout.to_string()], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() > 3 {
        return Err(StoreError::Invalid);
    }
    let mut result: Option<History> = None;
    for (index, body) in rows.iter().enumerate() {
        if body.len() > 256 * 1024 {
            return Err(StoreError::Invalid);
        }
        let event: Event = serde_json::from_str(body).map_err(|_| StoreError::Invalid)?;
        let Event::InteractiveRemoval {
            checkout: id,
            operation,
            phase,
            record,
        } = event
        else {
            return Err(StoreError::Invalid);
        };
        let record: Record = serde_json::from_str(&record).map_err(|_| StoreError::Invalid)?;
        if id != checkout
            || operation.get_version_num() != 7
            || record.version != 1
            || record.roots.is_empty()
            || record.roots.len() > 1024
            || record.roots.windows(2).any(|p| p[0] >= p[1])
            || record.roots.iter().any(|s| {
                !matches!(s.len(), 40 | 64)
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            || phase != ["intent", "native_succeeded", "removed"][index]
            || result
                .as_ref()
                .is_some_and(|h| h.operation != operation || h.record != record)
        {
            return Err(StoreError::Invalid);
        }
        result = Some(History {
            operation,
            record,
            phase,
        });
    }
    let h = result.as_ref().ok_or(StoreError::Invalid)?;
    let (allocation, finish, state, ready): (String,String,String,bool) = conn.query_row(
        "SELECT a.record,f.operation,c.state,c.ready FROM allocations a JOIN task_finishes f ON f.checkout=a.checkout JOIN checkouts c ON c.id=a.checkout WHERE a.checkout=?1", [checkout.to_string()], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if allocation != h.record.allocation
        || finish != h.record.finish_operation
        || ready
        || state
            != if h.phase == "removed" {
                "retired"
            } else {
                "held"
            }
    {
        return Err(StoreError::Invalid);
    }
    Ok(result)
}
pub(crate) fn completed(conn: &Connection, checkout: Uuid) -> Result<bool> {
    Ok(history(conn, checkout)?.is_some_and(|h| h.phase == "removed"))
}
pub(crate) fn emit(
    conn: &Connection,
    checkout: Uuid,
    operation: Uuid,
    phase: &str,
    record: &Record,
) -> Result<()> {
    crate::store::emit(
        conn,
        &Event::InteractiveRemoval {
            checkout,
            operation,
            phase: phase.into(),
            record: serde_json::to_string(record).map_err(|_| StoreError::Invalid)?,
        },
    )
}
