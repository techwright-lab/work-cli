//! Append-only interactive removal history in the existing durable outbox.
//! Acknowledgment does not delete events. No history record authorizes a new
//! native dispatch: only this invocation's fresh retained inspection can do so.
use crate::{
    events::Event,
    store::{Result, StoreError},
};
use rusqlite::{types::ValueRef, Connection};
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
    let mut query = conn.prepare("SELECT length(CAST(payload AS BLOB)),payload FROM outbox WHERE json_extract(payload,'$.type')='interactive_removal' AND json_extract(payload,'$.checkout')=?1 ORDER BY sequence LIMIT 4")?;
    let mut rows = query.query([checkout.to_string()])?;
    let mut result: Option<History> = None;
    let mut index = 0;
    while let Some(row) = rows.next()? {
        let length: i64 = row.get(0)?;
        if index >= 3 || !(0..=256 * 1024).contains(&length) {
            return Err(StoreError::Invalid);
        }
        let body = match row.get_ref(1)? {
            ValueRef::Text(bytes) if bytes.len() <= 256 * 1024 => bytes,
            _ => return Err(StoreError::Invalid),
        };
        let event: Event = serde_json::from_slice(body).map_err(|_| StoreError::Invalid)?;
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
        index += 1;
        result = Some(History {
            operation,
            record,
            phase,
        });
    }
    let Some(h) = result.as_ref() else {
        return Ok(None);
    };
    let mut query = conn.prepare("SELECT a.record,f.operation,c.state,c.ready FROM allocations a JOIN task_finishes f ON f.checkout=a.checkout JOIN checkouts c ON c.id=a.checkout WHERE a.checkout=?1")?;
    let mut bindings = query.query([checkout.to_string()])?;
    let row = bindings.next()?.ok_or(StoreError::Invalid)?;
    // Compare borrowed values; corrupt retained columns are never copied.
    for (column, expected) in [
        (0, h.record.allocation.as_str()),
        (1, h.record.finish_operation.as_str()),
        (
            2,
            if h.phase == "removed" {
                "retired"
            } else {
                "held"
            },
        ),
    ] {
        if !matches!(row.get_ref(column)?, ValueRef::Text(bytes) if bytes == expected.as_bytes()) {
            return Err(StoreError::Invalid);
        }
    }
    if !matches!(row.get_ref(3)?, ValueRef::Integer(0)) {
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
    let event = Event::InteractiveRemoval {
        checkout,
        operation,
        phase: phase.into(),
        record: serde_json::to_string(record).map_err(|_| StoreError::Invalid)?,
    };
    if serde_json::to_vec(&event)
        .map_err(|_| StoreError::Invalid)?
        .len()
        > 256 * 1024
    {
        return Err(StoreError::Invalid);
    }
    crate::store::emit(conn, &event)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_retained_event_refuses_before_decoding_or_binding() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE outbox(sequence INTEGER, payload TEXT)")
            .unwrap();
        let checkout = Uuid::now_v7();
        let body = serde_json::json!({"type":"interactive_removal", "checkout":checkout, "record":"x".repeat(256 * 1024)}).to_string();
        conn.execute("INSERT INTO outbox VALUES(1,?1)", [body])
            .unwrap();
        assert!(matches!(history(&conn, checkout), Err(StoreError::Invalid)));
    }
}
