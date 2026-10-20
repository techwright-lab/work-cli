//! Test-only, thread-local observations. No output until the first-declared guard
//! drops during unwinding, after product frames/locks have unwound. Retains the
//! last 256 events; reports diagnostic-only truncation. No runtime strings.
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    Sql {
        file: &'static str,
        line: u32,
        ticks: u32,
        wall: bool,
        vm: bool,
        elapsed_ms: u128,
        depth: usize,
    },
    Process {
        operation: Operation,
        timeout_ms: u128,
        elapsed_ms: u128,
        input_bytes: usize,
        output_bytes: Option<usize>,
        outcome: ProcessOutcome,
    },
    Store {
        phase: &'static str,
        category: StoreCategory,
        primary: Option<i32>,
        extended: Option<i32>,
    },
    /// Inclusive wall time; nested regions overlap and totals are NONADDITIVE.
    SubphaseSummary {
        region: Subphase,
        count: u64,
        total_elapsed_us: u128,
        max_elapsed_us: u128,
    },
    FinishRefused,
    FinishCodec {
        accepted: bool,
    },
    Workload {
        roots: usize,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreCategory {
    Unsafe,
    Database,
    Io,
    Conflict,
    Capacity,
    Writer,
    Invalid,
    FinishUncertain,
    DeliveryUncertain,
    UpgradeRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Begin,
    Finish,
    Retry,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessOutcome {
    Timeout,
    Cap,
    Io,
    Nonzero,
    Success,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Subphase {
    BeginCaptureTotal,
    BeforeSqlJson,
    AdmissionAgrees,
    RelatedQualification,
    NamespaceExisting,
    CaptureProof,
    OperationCollision,
    BeginRunWriter,
    WriteFreshCommitTail,
    HistoryIds,
    HistoryTargetRosters,
    HistoryRootReadDecode,
    HistoryRoster,
    HistoryChildExact,
    HistoryTerminal,
    TerminalRowVersion,
    TerminalSpecDecode,
    TerminalAgrees,
    TerminalNamespaceHeaderDigest,
    TerminalPreparedEndChecks,
    TerminalFinalization,
}
const REGIONS: [Subphase; 21] = [
    Subphase::BeginCaptureTotal,
    Subphase::BeforeSqlJson,
    Subphase::AdmissionAgrees,
    Subphase::RelatedQualification,
    Subphase::NamespaceExisting,
    Subphase::CaptureProof,
    Subphase::OperationCollision,
    Subphase::BeginRunWriter,
    Subphase::WriteFreshCommitTail,
    Subphase::HistoryIds,
    Subphase::HistoryTargetRosters,
    Subphase::HistoryRootReadDecode,
    Subphase::HistoryRoster,
    Subphase::HistoryChildExact,
    Subphase::HistoryTerminal,
    Subphase::TerminalRowVersion,
    Subphase::TerminalSpecDecode,
    Subphase::TerminalAgrees,
    Subphase::TerminalNamespaceHeaderDigest,
    Subphase::TerminalPreparedEndChecks,
    Subphase::TerminalFinalization,
];
#[derive(Clone, Copy, Default)]
struct Stats {
    count: u64,
    total_elapsed_us: u128,
    max_elapsed_us: u128,
}
pub(crate) struct ProfileRoot(bool);
impl ProfileRoot {
    pub(crate) fn new() -> Self {
        Self(ACTIVE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(c) = slot.as_mut() else { return false };
            if c.profile.is_some() {
                return false;
            }
            c.profile = Some([Stats::default(); REGIONS.len()]);
            true
        }))
    }
}
impl Drop for ProfileRoot {
    fn drop(&mut self) {
        if !self.0 {
            return;
        }
        let stats = ACTIVE.with(|slot| slot.borrow_mut().as_mut().and_then(|c| c.profile.take()));
        if let Some(stats) = stats {
            for (region, s) in REGIONS.into_iter().zip(stats) {
                if s.count != 0 {
                    record(Event::SubphaseSummary {
                        region,
                        count: s.count,
                        total_elapsed_us: s.total_elapsed_us,
                        max_elapsed_us: s.max_elapsed_us,
                    });
                }
            }
        }
    }
}
pub(crate) struct Span(Subphase, Option<std::time::Instant>);
pub(crate) fn span(region: Subphase) -> Span {
    let active = ACTIVE.with(|slot| slot.borrow().as_ref().is_some_and(|c| c.profile.is_some()));
    Span(region, active.then(std::time::Instant::now))
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some(start) = self.1 else { return };
        let elapsed = start.elapsed().as_micros();
        ACTIVE.with(|slot| {
            if let Some(stats) = slot.borrow_mut().as_mut().and_then(|c| c.profile.as_mut()) {
                let s = &mut stats[self.0 as usize];
                s.count += 1;
                s.total_elapsed_us += elapsed;
                s.max_elapsed_us = s.max_elapsed_us.max(elapsed);
            }
        });
    }
}

struct Collector {
    events: [Option<Event>; 256],
    count: usize,
    profile: Option<[Stats; REGIONS.len()]>,
}
impl Collector {
    fn new() -> Self {
        Self {
            events: [None; 256],
            count: 0,
            profile: None,
        }
    }
}
thread_local! { static ACTIVE: RefCell<Option<Collector>> = const { RefCell::new(None) }; }
pub(crate) fn store_error(phase: &'static str, error: &crate::store::StoreError) {
    use crate::store::StoreError as E;
    let category = match error {
        E::Unsafe => StoreCategory::Unsafe,
        E::Database(_) => StoreCategory::Database,
        E::Io(_) => StoreCategory::Io,
        E::Conflict => StoreCategory::Conflict,
        E::Capacity => StoreCategory::Capacity,
        E::Writer => StoreCategory::Writer,
        E::Invalid => StoreCategory::Invalid,
        E::CaptureFinishUncertain => StoreCategory::FinishUncertain,
        E::CaptureDeliveryUncertain => StoreCategory::DeliveryUncertain,
        E::UpgradeRequired => StoreCategory::UpgradeRequired,
    };
    let extended = match error {
        E::Database(rusqlite::Error::SqliteFailure(e, _)) => Some(e.extended_code),
        _ => None,
    };
    record(Event::Store {
        phase,
        category,
        primary: extended.map(|code| code & 0xff),
        extended,
    });
}
pub(crate) fn enabled() -> bool {
    ACTIVE.with(|slot| slot.borrow().is_some())
}
pub(crate) fn process(
    operation: &str,
    timeout: std::time::Duration,
    start: Option<std::time::Instant>,
    input_bytes: usize,
    result: &Result<std::process::Output, &'static str>,
) {
    let Some(start) = start else { return };
    let operation = match operation {
        "begin" => Operation::Begin,
        "finish" => Operation::Finish,
        "retry" => Operation::Retry,
        _ => Operation::Other,
    };
    let (outcome, output_bytes) = match result {
        Ok(output) => (
            if output.status.success() {
                ProcessOutcome::Success
            } else {
                ProcessOutcome::Nonzero
            },
            Some(output.stdout.len() + output.stderr.len()),
        ),
        Err("Git runtime limit reached; inventory incomplete") => (ProcessOutcome::Timeout, None),
        Err("Git capture limit reached; inventory incomplete") => (ProcessOutcome::Cap, None),
        Err(_) => (ProcessOutcome::Io, None),
    };
    record(Event::Process {
        operation,
        timeout_ms: timeout.as_millis(),
        elapsed_ms: start.elapsed().as_millis(),
        input_bytes,
        output_bytes,
        outcome,
    });
}
pub(crate) fn record(event: Event) {
    ACTIVE.with(|slot| {
        if let Some(c) = slot.borrow_mut().as_mut() {
            c.events[c.count % 256] = Some(event);
            c.count += 1;
        }
    });
}
pub(crate) struct Guard(Option<Collector>);
impl Guard {
    pub(crate) fn new() -> Self {
        Self(ACTIVE.with(|slot| slot.replace(Some(Collector::new()))))
    }
    pub(crate) fn events(&self) -> Vec<Event> {
        ACTIVE.with(|slot| {
            let slot = slot.borrow();
            let c = slot.as_ref().unwrap();
            (c.count.saturating_sub(256)..c.count)
                .filter_map(|i| c.events[i % 256])
                .collect()
        })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let current = ACTIVE.with(|slot| slot.replace(self.0.take()));
        if std::thread::panicking() {
            if let Some(c) = current {
                eprintln!(
                    "capture diagnostics (inclusive wall subphases overlap; totals NONADDITIVE; last 256; discarded={}):",
                    c.count.saturating_sub(256)
                );
                for i in c.count.saturating_sub(256)..c.count {
                    eprintln!("{:?}", c.events[i % 256].unwrap());
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subphase_profiles_aggregate_scoped_wall_spans_on_early_return() {
        fn attempt() -> Result<(), ()> {
            let _root = ProfileRoot::new();
            let _outer = span(Subphase::BeginCaptureTotal);
            for _ in 0..2 {
                let _inner = span(Subphase::TerminalSpecDecode);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(())?
        }
        assert!(!enabled());
        assert_eq!(attempt(), Err(()));
        let guard = Guard::new();
        // A collector alone does not enable per-record spans.
        drop(span(Subphase::TerminalAgrees));
        assert!(guard.events().is_empty());
        for _ in 0..2 {
            assert_eq!(attempt(), Err(()));
        }
        let events = guard.events();
        assert_eq!(events.len(), 4, "missing aggregate events at profile exit");
        for pair in events.chunks_exact(2) {
            let Event::SubphaseSummary {
                region,
                count,
                total_elapsed_us,
                max_elapsed_us,
            } = pair[0]
            else {
                panic!("summary required")
            };
            assert_eq!(region, Subphase::BeginCaptureTotal);
            assert_eq!(count, 1);
            assert_eq!(total_elapsed_us, max_elapsed_us);
            let Event::SubphaseSummary {
                region,
                count,
                total_elapsed_us,
                max_elapsed_us,
            } = pair[1]
            else {
                panic!("summary required")
            };
            assert_eq!(region, Subphase::TerminalSpecDecode);
            assert_eq!(count, 2);
            assert!(total_elapsed_us >= max_elapsed_us);
        }
        {
            let inner = Guard::new();
            assert_eq!(attempt(), Err(()));
            assert_eq!(inner.events().len(), 2);
        }
        assert_eq!(guard.events(), events);
        drop(guard);
        assert_eq!(attempt(), Err(()));
        assert!(!enabled());
    }

    #[test]
    fn collector_is_scoped_bounded_and_classifies_without_error_text() {
        assert!(!enabled());
        record(Event::Workload { roots: 2 });
        let guard = Guard::new();
        record(Event::Workload { roots: 2 });
        {
            let inner = Guard::new();
            for _ in 0..300 {
                record(Event::Workload { roots: 48 });
            }
            assert_eq!(inner.events().len(), 256);
            assert!(inner
                .events()
                .iter()
                .all(|e| *e == Event::Workload { roots: 48 }));
        }
        assert_eq!(guard.events(), vec![Event::Workload { roots: 2 }]);
        store_error(
            "test",
            &crate::store::StoreError::Database(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(9),
                Some("must not escape".into()),
            )),
        );
        assert_eq!(
            guard.events()[1],
            Event::Store {
                phase: "test",
                category: StoreCategory::Database,
                primary: Some(9),
                extended: Some(9)
            }
        );
        drop(guard);
        assert!(!enabled());
    }
}
