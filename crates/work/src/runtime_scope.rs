//! Pure scope evidence guards. Observations must be supplied by a trusted future driver;
//! these types do not collect OS evidence or authenticate an environment lease ID.
use std::time::{Duration, Instant};
use work_contract::RunId;

#[derive(Debug)]
pub struct LaunchIntent {
    unit: String,
    boot: String,
}
impl LaunchIntent {
    pub fn new(run: RunId, boot: &str) -> Result<Self, HoldReason> {
        if !uuid_text(boot, true) {
            return Err(HoldReason::InvalidBoot);
        }
        Ok(Self {
            unit: format!("work-run-{run}.scope"),
            boot: boot.into(),
        })
    }
    pub fn unit_name(&self) -> &str {
        &self.unit
    }
    pub fn boot_id(&self) -> &str {
        &self.boot
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeIdentity {
    pub unit: String,
    pub invocation: String,
    pub cgroup: String,
}
/// Driver-observed /proc identity, not a caller-supplied PID or environment claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot: String,
    pub cgroup: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Complete,
    Incomplete,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStatus {
    Loaded,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveStatus {
    Active,
    Inactive,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitPresence {
    Present {
        identity: ScopeIdentity,
        load: LoadStatus,
        active: ActiveStatus,
    },
    /// Driver-confirmed unit absence linked to the previously bound identity,
    /// with no replacement/ambiguous lookup. Not merely a failed unit query.
    AutoReaped(ScopeIdentity),
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Membership {
    Present(Vec<ChildIdentity>),
    /// Confirmed absence of the exact bound cgroup, not an unreadable path.
    Absent,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantStatus {
    Open,
    Closed,
    ProvenAbsent,
    Unknown,
}
/// One coherent driver observation. `observed_at` is the earliest evidence
/// collection instant, never a refreshed timestamp on cached evidence. Coverage
/// means all recursive cgroup descendants and the entire known participant roster,
/// respectively; read errors, racing membership or missing registry data are Unknown.
/// Closed/ProvenAbsent are explicit participant evidence, never heartbeat silence.
#[derive(Debug, Clone)]
pub struct Observation {
    pub boot: String,
    pub observed_at: Instant,
    pub unit: UnitPresence,
    pub membership: Membership,
    pub recursive_coverage: Coverage,
    pub participant_coverage: Coverage,
    pub participants: Vec<ParticipantStatus>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldReason {
    InvalidBoot,
    BootMismatch,
    FutureObservation,
    StaleObservation,
    UnitUnknown,
    UnitMismatch,
    InvalidInvocation,
    InvalidCgroup,
    ChildIdentity,
    MembershipUnknown,
    IncompleteMembership,
    ParticipantUncertain,
    Populated,
    ReapedGroupNotAbsent,
}

/// Opaque result of matching pre-exec unit, trusted child and recursive snapshot.
/// Not serializable and not constructible from a caller's lease/environment ID.
#[derive(Debug)]
pub struct Binding {
    identity: ScopeIdentity,
    boot: String,
    child: ChildIdentity,
}

/// Authorizes only cancellation of this bound unit, never arbitrary PID signaling.
/// The driver must use promptly; this is not a persistent or retirement permission.
#[derive(Debug)]
pub struct Cancellation<'a> {
    binding: &'a Binding,
}
impl Cancellation<'_> {
    pub fn unit_name(&self) -> &str {
        &self.binding.identity.unit
    }
    pub fn identity(&self) -> &ScopeIdentity {
        &self.binding.identity
    }
}

/// A downstream quiescence input ONLY. Preservation, filesystem identity and
/// retirement authorization are separate; this cannot authorize retirement.
#[derive(Debug)]
pub struct VerifiedEmpty<'a> {
    _binding: &'a Binding,
}

pub fn bind(
    intent: &LaunchIntent,
    child: &ChildIdentity,
    obs: &Observation,
    now: Instant,
    max_age: Duration,
) -> Result<Binding, HoldReason> {
    fresh(obs, &intent.boot, now, max_age)?;
    let identity = present_identity(&obs.unit)?;
    validate_structure(intent, identity, child)?;
    if obs.recursive_coverage != Coverage::Complete {
        return Err(HoldReason::IncompleteMembership);
    }
    match &obs.membership {
        Membership::Present(members) if members.contains(child) => {}
        _ => return Err(HoldReason::ChildIdentity),
    }
    // Active is required at the pre-exec binding boundary, not inferred from PID existence.
    if !matches!(
        obs.unit,
        UnitPresence::Present {
            active: ActiveStatus::Active,
            ..
        }
    ) {
        return Err(HoldReason::UnitUnknown);
    }
    Ok(Binding {
        identity: identity.clone(),
        boot: intent.boot.clone(),
        child: child.clone(),
    })
}
/// Shared structural invariants for live binding and historical journal reads.
/// This checks metadata ONLY: no freshness, OS observation, or authority token.
pub(crate) fn validate_structure(
    intent: &LaunchIntent,
    identity: &ScopeIdentity,
    child: &ChildIdentity,
) -> Result<(), HoldReason> {
    if identity.unit != intent.unit {
        return Err(HoldReason::UnitMismatch);
    }
    if !uuid_text(&identity.invocation, false) {
        return Err(HoldReason::InvalidInvocation);
    }
    if !normalized(&identity.cgroup) || !identity.cgroup.ends_with(&format!("/{}", intent.unit)) {
        return Err(HoldReason::InvalidCgroup);
    }
    if child.pid == 0
        || child.pid > i32::MAX as u32
        || child.start_ticks == 0
        || child.boot != intent.boot
        || !within(&child.cgroup, &identity.cgroup)
    {
        return Err(HoldReason::ChildIdentity);
    }
    Ok(())
}
impl Binding {
    pub fn trusted_child(&self) -> &ChildIdentity {
        &self.child
    }
    pub fn identity(&self) -> &ScopeIdentity {
        &self.identity
    }
    pub fn boot_id(&self) -> &str {
        &self.boot
    }
    pub fn authorize_cancel(
        &self,
        obs: &Observation,
        now: Instant,
        max_age: Duration,
    ) -> Result<Cancellation<'_>, HoldReason> {
        fresh(obs, &self.boot, now, max_age)?;
        self.matches(present_identity(&obs.unit)?)?;
        Ok(Cancellation { binding: self })
    }
    pub fn verify_empty(
        &self,
        obs: &Observation,
        now: Instant,
        max_age: Duration,
    ) -> Result<VerifiedEmpty<'_>, HoldReason> {
        verify_empty_evidence(&self.identity, &self.boot, obs, now, max_age)?;
        Ok(VerifiedEmpty { _binding: self })
    }
    fn matches(&self, identity: &ScopeIdentity) -> Result<(), HoldReason> {
        if identity != &self.identity {
            return Err(HoldReason::UnitMismatch);
        }
        Ok(())
    }
}
/// Shared pure emptiness invariants; returns no execution or cancellation authority.
pub(crate) fn verify_empty_evidence(
    expected: &ScopeIdentity,
    boot: &str,
    obs: &Observation,
    now: Instant,
    max_age: Duration,
) -> Result<(), HoldReason> {
    let matches = |identity: &ScopeIdentity| {
        if identity == expected {
            Ok(())
        } else {
            Err(HoldReason::UnitMismatch)
        }
    };
    fresh(obs, boot, now, max_age)?;
    match &obs.unit {
        UnitPresence::AutoReaped(identity) => {
            matches(identity)?;
            if obs.membership != Membership::Absent {
                return Err(HoldReason::ReapedGroupNotAbsent);
            }
        }
        _ => matches(present_identity(&obs.unit)?)?,
    }
    if obs.recursive_coverage != Coverage::Complete {
        return Err(HoldReason::IncompleteMembership);
    }
    if obs.participant_coverage != Coverage::Complete
        || obs.participants.iter().any(|p| {
            !matches!(
                p,
                ParticipantStatus::Closed | ParticipantStatus::ProvenAbsent
            )
        })
    {
        return Err(HoldReason::ParticipantUncertain);
    }
    match &obs.membership {
        Membership::Absent => {}
        Membership::Present(members) if members.is_empty() => {}
        Membership::Present(_) => return Err(HoldReason::Populated),
        Membership::Unknown => return Err(HoldReason::MembershipUnknown),
    }
    Ok(())
}
/// Nonexecuting validated host evidence. Not a Binding or an emptiness token.
#[derive(Debug)]
pub struct ValidatedHost {
    pub(crate) host: ChildIdentity,
    pub(crate) observed_at: Instant,
}
/// The involved roster is only the target host and, without the original controller,
/// the actual registrar, deduplicated by physical identity. It is not the full child
/// ledger or a group-quiescence claim. Recursive membership still covers all OS members.
#[allow(clippy::too_many_arguments)]
pub fn validate_enrollment_host(
    intent: &LaunchIntent,
    scope: &ScopeIdentity,
    expected: &crate::run_participants::ExpectedHost,
    host: &ChildIdentity,
    participants: &[ChildIdentity],
    obs: &Observation,
    now: Instant,
    max_age: Duration,
) -> Result<ValidatedHost, HoldReason> {
    fresh(obs, intent.boot_id(), now, max_age)?;
    if present_identity(&obs.unit)? != scope {
        return Err(HoldReason::UnitMismatch);
    }
    if !matches!(
        obs.unit,
        UnitPresence::Present {
            active: ActiveStatus::Active,
            ..
        }
    ) {
        return Err(HoldReason::UnitUnknown);
    }
    validate_structure(intent, scope, host)?;
    if host.pid != expected.pid
        || host.start_ticks != expected.start_ticks
        || host.boot != expected.boot
    {
        return Err(HoldReason::ChildIdentity);
    }
    if obs.recursive_coverage != Coverage::Complete {
        return Err(HoldReason::IncompleteMembership);
    }
    if participants.is_empty()
        || obs.participant_coverage != Coverage::Complete
        || obs.participants.len() != participants.len()
        || obs
            .participants
            .iter()
            .any(|p| *p != ParticipantStatus::Open)
    {
        return Err(HoldReason::ParticipantUncertain);
    }
    let Membership::Present(members) = &obs.membership else {
        return Err(HoldReason::MembershipUnknown);
    };
    if !participants.contains(host) || !members.contains(host) {
        return Err(HoldReason::ChildIdentity);
    }
    for (index, participant) in participants.iter().enumerate() {
        validate_structure(intent, scope, participant)?;
        if participants[..index]
            .iter()
            .any(|p| p.pid == participant.pid)
            || !members.contains(participant)
        {
            return Err(HoldReason::ChildIdentity);
        }
    }
    for (index, member) in members.iter().enumerate() {
        validate_structure(intent, scope, member)?;
        if members[..index].iter().any(|p| p.pid == member.pid) {
            return Err(HoldReason::ChildIdentity);
        }
    }
    Ok(ValidatedHost {
        host: host.clone(),
        observed_at: obs.observed_at,
    })
}
fn fresh(obs: &Observation, boot: &str, now: Instant, max_age: Duration) -> Result<(), HoldReason> {
    if obs.boot != boot {
        return Err(HoldReason::BootMismatch);
    }
    let age = now
        .checked_duration_since(obs.observed_at)
        .ok_or(HoldReason::FutureObservation)?;
    if age > max_age {
        return Err(HoldReason::StaleObservation);
    }
    Ok(())
}
fn present_identity(unit: &UnitPresence) -> Result<&ScopeIdentity, HoldReason> {
    match unit {
        UnitPresence::Present {
            identity,
            load: LoadStatus::Loaded,
            active: ActiveStatus::Active | ActiveStatus::Inactive,
        } => Ok(identity),
        _ => Err(HoldReason::UnitUnknown),
    }
}
fn uuid_text(raw: &str, hyphenated: bool) -> bool {
    let Ok(id) = uuid::Uuid::parse_str(raw) else {
        return false;
    };
    !id.is_nil()
        && if hyphenated {
            raw == id.hyphenated().to_string()
        } else {
            raw == id.simple().to_string()
        }
}
fn normalized(path: &str) -> bool {
    path.starts_with('/')
        && path
            .split('/')
            .skip(1)
            .all(|p| !p.is_empty() && p != "." && p != ".." && !p.chars().any(char::is_control))
}
fn within(child: &str, group: &str) -> bool {
    normalized(child)
        && (child == group
            || child
                .strip_prefix(group)
                .is_some_and(|rest| rest.starts_with('/')))
}
