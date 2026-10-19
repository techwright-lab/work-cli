//! Accountable owner transitions; no public state setter or charge release.
use crate::{
    admission::Limits,
    events::Event,
    store::{count, emit, identity, Result, Store, StoreError},
};
use rusqlite::TransactionBehavior;
use uuid::Uuid;
impl Store {
    pub fn transfer(&mut self, checkout: Uuid, recipient: &str, limits: Limits) -> Result<()> {
        identity(recipient)?;
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (repo, owner): (String, String) = tx.query_row(
            "SELECT repository,owner FROM checkouts WHERE id=?1 AND state!='retired'",
            [checkout.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if owner == recipient {
            return Ok(());
        }
        let retired: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM retired_owners WHERE owner=?1)",
            [recipient],
            |r| r.get(0),
        )?;
        if retired || count(&tx, &repo, Some(recipient))? >= limits.owner {
            return Err(StoreError::Capacity);
        }
        tx.execute(
            "UPDATE checkouts SET owner=?1 WHERE id=?2",
            (recipient, checkout.to_string()),
        )?;
        emit(
            &tx,
            &Event::OwnerTransferred {
                checkout,
                from: owner,
                to: recipient.into(),
            },
        )?;
        tx.commit()?;
        Ok(())
    }
    /// The caller passes the configured operator, never an inferred fallback.
    /// All existing responsibility moves atomically, even when already over quota.
    pub fn retire_owner(
        &mut self,
        owner: &str,
        operator: Option<&str>,
        limits: Limits,
    ) -> Result<usize> {
        identity(owner)?;
        let _phase = self.sql_phase();
        let operator = operator.ok_or(StoreError::Invalid)?;
        identity(operator)?;
        if owner == operator {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let retired: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM retired_owners WHERE owner=?1)",
            [operator],
            |r| r.get(0),
        )?;
        if retired {
            return Err(StoreError::Invalid);
        }
        let rows: Vec<(String, String)> = {
            let mut s = tx.prepare("SELECT id,repository FROM checkouts WHERE owner=?1 AND state!='retired' ORDER BY rowid")?;
            let rows = s
                .query_map([owner], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<_, _>>()?;
            rows
        };
        tx.execute("INSERT OR IGNORE INTO retired_owners VALUES(?1)", [owner])?;
        for (id, repo) in &rows {
            let checkout = Uuid::parse_str(id).map_err(|_| StoreError::Invalid)?;
            tx.execute("UPDATE checkouts SET owner=?1 WHERE id=?2", (operator, id))?;
            let over_quota = count(&tx, repo, Some(operator))? > limits.owner
                || count(&tx, repo, None)? > limits.repository;
            emit(
                &tx,
                &Event::OwnerEscalated {
                    checkout,
                    from: owner.into(),
                    to: operator.into(),
                    over_quota,
                },
            )?;
        }
        tx.commit()?;
        Ok(rows.len())
    }
}
