//! Cooperative declarations, not OS identity, process exit, or individual credit.
use crate::store::{Result, Store, StoreError};
use serde::{Deserialize, Serialize};
use work_contract::{ActorId, GroupId, RunId};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ref(String);
impl Ref {
    pub fn new(value: String) -> Result<Self> {
        if value.trim().is_empty()
            || value.chars().count() > 256
            || value.chars().any(char::is_control)
        {
            return Err(StoreError::Invalid);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for Ref {
    type Error = StoreError;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}
impl From<Ref> for String {
    fn from(r: Ref) -> String {
        r.0
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantKey {
    pub session: Ref,
    pub agent: Ref,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    Stop,
    SubagentStart,
    SubagentStop,
    SessionEnd,
    Reconcile,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    pub run: RunId,
    pub group: GroupId,
    pub source: Ref,
    pub participant: ParticipantKey,
    pub parent: Option<ParticipantKey>,
    pub actor: Option<ActorId>,
    pub prompt: Ref,
    pub tool: Ref,
    pub event_ref: Ref,
    pub kind: ActivityKind,
    pub observed_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantRecord {
    pub key: ParticipantKey,
    pub actor: Option<ActorId>,
    pub parent: Option<ParticipantKey>,
    pub declared_closed: bool,
    pub heartbeat: Option<u64>,
    pub depth: u8,
}
pub(crate) const MAX_PARTICIPANTS: usize = 256;
pub(crate) fn roster(
    conn: &rusqlite::Connection,
    request: &crate::adopted::AdoptedRequest,
) -> Result<Vec<ParticipantRecord>> {
    let mut stmt = conn.prepare("SELECT source,session,agent,actor,parent,closed,heartbeat,depth FROM adopted_sessions WHERE group_id=?1 ORDER BY source,session,agent LIMIT 257")?;
    let rows = stmt.query_map([request.identity.group.to_string()], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, bool>(5)?,
            r.get::<_, Option<i64>>(6)?,
            r.get::<_, u8>(7)?,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (source, session, agent, actor, parent, declared_closed, heartbeat, depth) = row?;
        if source != request.source.as_str() || depth > 16 {
            return Err(StoreError::Invalid);
        }
        let actor = actor
            .map(|a| {
                Ref::new(a.clone())?;
                ActorId::parse(&a).map_err(|_| StoreError::Invalid)
            })
            .transpose()?;
        let parent = parent
            .map(|p| serde_json::from_str::<ParticipantKey>(&p).map_err(|_| StoreError::Invalid))
            .transpose()?;
        let heartbeat = heartbeat
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StoreError::Invalid)?;
        records.push(ParticipantRecord {
            key: ParticipantKey {
                session: Ref::new(session)?,
                agent: Ref::new(agent)?,
            },
            actor,
            parent,
            declared_closed,
            heartbeat,
            depth,
        });
    }
    if records.len() > MAX_PARTICIPANTS {
        return Err(StoreError::Invalid);
    }
    let root = ParticipantKey {
        session: request.session.clone(),
        agent: request.agent.clone(),
    };
    for record in &records {
        if record.key == root {
            if record.parent.is_some()
                || record.depth != 0
                || record.actor.as_ref() != Some(&request.identity.actor)
            {
                return Err(StoreError::Invalid);
            }
        } else {
            let parent = record
                .parent
                .as_ref()
                .and_then(|p| records.iter().find(|r| &r.key == p))
                .ok_or(StoreError::Invalid)?;
            if record.depth != parent.depth + 1 {
                return Err(StoreError::Invalid);
            }
        }
    }
    if !records.iter().any(|r| r.key == root) {
        return Err(StoreError::Invalid);
    }
    Ok(records)
}
impl Store {
    /// Explicit root/group/source/parent context, never environment-based joining.
    /// No declaration here can release a writer or produce ScopeRoot evidence.
    pub fn record_activity(&mut self, event: &Activity) -> Result<crate::run_journal::Transition> {
        use crate::{
            adopted::{held, journal_event, json, read},
            run_journal::Transition,
        };
        use rusqlite::OptionalExtension;
        if event.observed_at > i64::MAX as u64 {
            return Err(StoreError::Invalid);
        }
        if let Some(actor) = &event.actor {
            Ref::new(actor.as_str().into())?;
        }
        let _phase = self.sql_phase();
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (request, revision, _) = read(&tx, &event.run)?.ok_or(StoreError::Invalid)?;
        if request.identity.group != event.group || request.source != event.source {
            return Err(StoreError::Conflict);
        }
        held(&tx, &request)?;
        let body = json(event)?;
        let kind = json(&event.kind)?;
        let key = (
            event.group.to_string(),
            event.source.as_str(),
            event.participant.session.as_str(),
            event.participant.agent.as_str(),
            event.prompt.as_str(),
            event.tool.as_str(),
            kind.as_str(),
            event.event_ref.as_str(),
        );
        let existing: Option<String> = tx.query_row("SELECT body FROM adopted_segments WHERE group_id=?1 AND source=?2 AND session=?3 AND agent=?4 AND prompt=?5 AND tool=?6 AND kind=?7 AND event_ref=?8", key, |r| r.get(0)).optional()?;
        if let Some(existing) = existing {
            return if existing == body {
                Ok(Transition::Existing)
            } else {
                Err(StoreError::Conflict)
            };
        }
        let records = roster(&tx, &request)?;
        let registered = records.iter().find(|r| r.key == event.participant);
        let child_event = matches!(
            event.kind,
            ActivityKind::SubagentStart | ActivityKind::SubagentStop
        );
        if child_event {
            let parent = event.parent.as_ref().ok_or(StoreError::Invalid)?;
            if parent == &event.participant {
                return Err(StoreError::Conflict);
            }
            let parent_record = records
                .iter()
                .find(|r| &r.key == parent)
                .ok_or(StoreError::Invalid)?;
            if parent_record.depth >= 16 {
                return Err(StoreError::Invalid);
            }
            if registered.is_none() {
                if records.len() >= MAX_PARTICIPANTS {
                    return Err(StoreError::Capacity);
                }
                tx.execute("INSERT INTO adopted_sessions(group_id,source,session,agent,actor,parent,closed,depth) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    (event.group.to_string(),event.source.as_str(),event.participant.session.as_str(),event.participant.agent.as_str(),event.actor.as_ref().map(ActorId::as_str),json(parent)?,event.kind==ActivityKind::SubagentStop,parent_record.depth+1))?;
            }
        } else if registered.is_none() {
            return Err(StoreError::Invalid);
        }
        if let Some(record) = registered {
            if record.parent != event.parent || record.actor != event.actor {
                return Err(StoreError::Conflict);
            }
        }
        // Late Start is recorded but never reopens a terminal tombstone.
        let close = matches!(
            event.kind,
            ActivityKind::SubagentStop | ActivityKind::SessionEnd
        );
        let heartbeat = if matches!(
            event.kind,
            ActivityKind::Reconcile | ActivityKind::SubagentStart
        ) {
            None
        } else {
            Some(event.observed_at as i64)
        };
        tx.execute("UPDATE adopted_sessions SET closed=MAX(closed,?5),heartbeat=CASE WHEN ?6 IS NULL THEN heartbeat ELSE MAX(COALESCE(heartbeat,0),?6) END WHERE group_id=?1 AND source=?2 AND session=?3 AND agent=?4",
            (event.group.to_string(),event.source.as_str(),event.participant.session.as_str(),event.participant.agent.as_str(),close,heartbeat))?;
        tx.execute("INSERT INTO adopted_segments(group_id,source,session,agent,prompt,tool,kind,event_ref,body) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            (event.group.to_string(),event.source.as_str(),event.participant.session.as_str(),event.participant.agent.as_str(),event.prompt.as_str(),event.tool.as_str(),&kind,event.event_ref.as_str(),body))?;
        let revision = revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StoreError::Invalid)?;
        tx.execute(
            "UPDATE adopted_groups SET revision=?2,reconcile=MAX(reconcile,?3) WHERE id=?1",
            (
                event.group.to_string(),
                revision as i64,
                matches!(
                    event.kind,
                    ActivityKind::SessionEnd | ActivityKind::Reconcile
                ),
            ),
        )?;
        journal_event(&tx, &request, revision)?;
        tx.commit()?;
        Ok(Transition::Changed)
    }
}
