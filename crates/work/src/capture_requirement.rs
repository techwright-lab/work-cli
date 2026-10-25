//! Independent, permanent allocation requirement. No settings or secret values.
use crate::store::{Result, StoreError};
use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

pub(crate) const SCHEMA: &str = "CREATE TABLE capture_requirements(
 checkout TEXT PRIMARY KEY REFERENCES checkouts(id),
 allocation_operation TEXT NOT NULL UNIQUE REFERENCES checkouts(operation),
 family TEXT NOT NULL CHECK(family='portable-capture'),
 version INTEGER NOT NULL CHECK(version=1),
 revision INTEGER NOT NULL CHECK(revision>=1));
 CREATE INDEX capture_requirement_operation ON capture_requirements(allocation_operation);
 PRAGMA user_version=11;";
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Requirement {
    pub(crate) operation: String,
    pub(crate) revision: u64,
}
pub(crate) fn present(conn: &Connection, checkout: Uuid) -> Result<bool> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 11 {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM capture_requirements WHERE checkout=?1)",
        [checkout.to_string()],
        |r| r.get(0),
    )?)
}
pub(crate) fn read(conn: &Connection, checkout: Uuid) -> Result<Option<Requirement>> {
    if !present(conn, checkout)? {
        return Ok(None);
    }
    let row: Option<(String, String, i64, i64)> = conn.query_row(
        "SELECT allocation_operation,family,version,revision FROM capture_requirements WHERE checkout=?1",
        [checkout.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let (operation, family, version, revision) = row.ok_or(StoreError::Invalid)?;
    let allocation_operation: String = conn.query_row(
        "SELECT operation FROM checkouts WHERE id=?1",
        [checkout.to_string()],
        |r| r.get(0),
    )?;
    let id = Uuid::parse_str(&operation).map_err(|_| StoreError::Invalid)?;
    if family != "portable-capture"
        || version != 1
        || revision < 1
        || operation != allocation_operation
        || id.get_version_num() != 7
        || id.get_variant() != uuid::Variant::RFC4122
    {
        return Err(StoreError::Invalid);
    }
    Ok(Some(Requirement {
        operation,
        revision: revision as u64,
    }))
}
pub(crate) fn insert(conn: &Connection, checkout: Uuid, operation: Uuid) -> Result<()> {
    crate::retirement_journal::require_unfenced(conn, checkout)?;
    conn.execute(
        "INSERT INTO capture_requirements VALUES(?1,?2,'portable-capture',1,1)",
        (checkout.to_string(), operation.to_string()),
    )?;
    Ok(())
}
pub(crate) fn validate_schema(conn: &Connection) -> Result<()> {
    let normalize = |s: &str| {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '"')
            .collect::<String>()
            .to_ascii_lowercase()
    };
    for (name, kind, expected) in [
        (
            "capture_requirements",
            "table",
            SCHEMA.split(';').next().ok_or(StoreError::Invalid)?,
        ),
        (
            "capture_requirement_operation",
            "index",
            SCHEMA.split(';').nth(1).ok_or(StoreError::Invalid)?,
        ),
    ] {
        let ddl: String = conn.query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1 AND type=?2",
            (name, kind),
            |r| r.get(0),
        )?;
        if normalize(&ddl) != normalize(expected) {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}
