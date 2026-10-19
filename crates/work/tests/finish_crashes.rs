mod support;
use support::Fixture;
use uuid::Uuid;
use work_cli::finish::{self, CaptureContext, CaptureResult, Delivery, LocalSink};
struct DiskSink(std::path::PathBuf);
impl LocalSink for DiskSink {
    fn freeze(&self, context: &CaptureContext) -> CaptureResult {
        // Fake local durable idempotency receipt; no receiver or network authority.
        let key = context.operation.to_string();
        if self.0.exists() {
            assert_eq!(std::fs::read_to_string(&self.0).unwrap(), key);
        } else {
            std::fs::write(&self.0, key).unwrap();
        }
        CaptureResult::Frozen {
            delivery: Some(Delivery::Pending),
        }
    }
}
#[test]
fn finish_worker() {
    let Ok(base) = std::env::var("WORK_FINISH_BASE") else {
        return;
    };
    let config = work_cli::config::Config::load().unwrap();
    let id = Uuid::parse_str(&std::env::var("WORK_FINISH_CHECKOUT").unwrap()).unwrap();
    let sink = DiskSink(std::path::Path::new(&base).join("frozen-key"));
    finish::finish_with_sink_observed(&config, id, Some(&sink), |boundary| {
        if std::env::var("WORK_FINISH_BOUNDARY").as_deref() == Ok(boundary) {
            use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
            setrlimit(
                Resource::Core,
                Rlimit {
                    current: Some(0),
                    ..getrlimit(Resource::Core)
                },
            )
            .unwrap();
            assert_eq!(getrlimit(Resource::Core).current, Some(0));
            std::process::abort();
        }
    })
    .unwrap();
}
#[test]
fn aborts_preserve_atomic_completion_and_idempotent_local_capture() {
    for boundary in [
        "before_commit",
        "completion_committed",
        "before_freeze",
        "external_frozen",
        "outcome_committed",
        "before_ack",
    ] {
        let f = Fixture::new();
        let out = f.start(&Uuid::now_v7().to_string(), "task", "topic", &[]);
        assert!(out.status.success());
        let a: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let id = Uuid::parse_str(a["checkout"].as_str().unwrap()).unwrap();
        let mut cfg = work_cli::config::Config::from_text(
            &std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap(),
        )
        .unwrap();
        cfg.allocation.as_mut().unwrap().capture_sink = Some("local-fixture".into());
        // Only fixture config is written, not production host config.
        let mut text = std::fs::read_to_string(f.temp.path().join("config.toml")).unwrap();
        text.push_str("capture_sink='local-fixture'\n");
        std::fs::write(f.temp.path().join("config.toml"), text).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "finish_worker"])
            .env("WORK_FINISH_BASE", f.temp.path())
            .env("WORK_FINISH_CHECKOUT", id.to_string())
            .env("WORK_FINISH_BOUNDARY", boundary)
            .env("WORK_CONFIG", f.temp.path().join("config.toml"))
            .status()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6), "{boundary}");
        let sql = rusqlite::Connection::open(f.temp.path().join("private/store.sqlite")).unwrap();
        let n: i64 = sql
            .query_row("SELECT count(*) FROM task_finishes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, if boundary == "before_commit" { 0 } else { 1 });
        let (state, ready): (String, bool) = sql
            .query_row("SELECT state,ready FROM checkouts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(
            (state.as_str(), ready),
            if boundary == "before_commit" {
                ("active", true)
            } else {
                ("held", false)
            }
        );
        let key = f.temp.path().join("frozen-key");
        let prior = std::fs::read_to_string(&key).ok();
        let report =
            finish::finish_with_sink_observed(&cfg, id, Some(&DiskSink(key.clone())), |_| {})
                .unwrap();
        assert!(report.task_finished);
        assert_eq!(report.local_freeze, finish::Freeze::Frozen);
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            report.operation.to_string()
        );
        if let Some(prior) = prior {
            assert_eq!(prior, report.operation.to_string());
        }
        let repeated =
            finish::finish_with_sink_observed(&cfg, id, Some(&DiskSink(key)), |_| {}).unwrap();
        assert_eq!(report, repeated);
        assert_eq!(f.store().charged(&f.repo, None).unwrap(), 1);
        let n: i64 = sql
            .query_row(
                "SELECT count(*) FROM outbox WHERE json_extract(payload,'$.type')='task_finished'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        assert!(std::path::Path::new(a["destination"].as_str().unwrap()).is_dir());
        assert_eq!(std::fs::read_dir(&f.root).unwrap().count(), 1);
    }
}
