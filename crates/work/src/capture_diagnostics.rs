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
struct Collector {
    events: [Option<Event>; 256],
    count: usize,
}
impl Collector {
    fn new() -> Self {
        Self {
            events: [None; 256],
            count: 0,
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
                    "capture diagnostics (last 256; discarded={}):",
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
