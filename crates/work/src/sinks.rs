//! Library-only process transport. No CLI/env selection or persistence callbacks.
//! The trusted host supplies settings. Operator receiver environment is inherited
//! for capture; stripping credentials before writer launch belongs to integration.
use crate::{bounded_process, capture_bridge::*};
use std::{fmt, path::PathBuf, process::Command, time::Duration};

pub struct ProcessSinkSettings {
    executable: PathBuf,
    registry: PathBuf,
    state: PathBuf,
    timeout: Duration,
    response_cap: usize,
}
impl ProcessSinkSettings {
    pub fn new(
        executable: PathBuf,
        registry: PathBuf,
        state: PathBuf,
        timeout: Duration,
        response_cap: usize,
    ) -> Result<Self, Refused> {
        if [&executable, &registry, &state]
            .iter()
            .any(|p| !p.is_absolute())
            || timeout < Duration::from_millis(1)
            || timeout > Duration::from_millis(30000)
            || !(1..=MAX_WIRE_BYTES).contains(&response_cap)
        {
            return Err(Refused);
        }
        Ok(Self {
            executable,
            registry,
            state,
            timeout,
            response_cap,
        })
    }
}
pub struct ProcessSink {
    settings: ProcessSinkSettings,
}
impl ProcessSink {
    pub fn new(settings: ProcessSinkSettings) -> Self {
        Self { settings }
    }
    fn invoke(&self, operation: &str, input: &[u8]) -> Result<Vec<u8>, Refused> {
        if input.len() > MAX_WIRE_BYTES {
            return Err(Refused);
        }
        let s = &self.settings;
        let mut command = Command::new(&s.executable);
        command
            .arg("--config")
            .arg(&s.registry)
            .arg("capture")
            .arg(operation)
            .arg("--state-dir")
            .arg(&s.state)
            .arg("--json");
        #[cfg(test)]
        let mut transport = crate::capture_diagnostics::TransportGuard::new(operation);
        #[cfg(test)]
        let started = transport.is_some().then(std::time::Instant::now);
        #[cfg(test)]
        let output = match transport.as_mut() {
            Some(guard) => bounded_process::output_with_input_aggregate_observed(
                &mut command,
                s.timeout,
                s.response_cap,
                input,
                guard.progress(),
            ),
            None => bounded_process::output_with_input_aggregate(
                &mut command,
                s.timeout,
                s.response_cap,
                input,
            ),
        };
        #[cfg(not(test))]
        let output = bounded_process::output_with_input_aggregate(
            &mut command,
            s.timeout,
            s.response_cap,
            input,
        );
        // Elapsed includes the existing process cleanup, not just its deadline.
        #[cfg(test)]
        crate::capture_diagnostics::process(operation, s.timeout, started, input.len(), &output);
        #[cfg(test)]
        drop(transport);
        let output = output.map_err(|_| Refused)?;
        if !output.status.success() {
            return Err(Refused);
        }
        Ok(output.stdout)
    }
    /// The host must supply its trusted profile, not one inferred from the response.
    /// An explicitly empty profile requires all Git fields to be absent:
    /// ```no_run
    /// use work_cli::{capture_bridge::*, sinks::ProcessSink};
    /// fn prepare_without_git(sink: &ProcessSink, request: &BeginRequest) -> Result<Prepared, Refused> {
    ///     sink.begin(request, &GitProfile::default())
    /// }
    /// ```
    /// ```compile_fail
    /// use work_cli::{capture_bridge::BeginRequest, sinks::ProcessSink};
    /// fn unchecked(sink: &ProcessSink, request: &BeginRequest) {
    ///     let _ = sink.begin(request); // trusted profile is mandatory
    /// }
    /// ```
    pub fn begin(
        &self,
        request: &BeginRequest,
        expected_git: &GitProfile,
    ) -> Result<Prepared, Refused> {
        expected_git.validate()?;
        let input = request.encode()?;
        decode_begin(&self.invoke("begin", &input)?, request, expected_git)
    }
    pub fn finish(
        &self,
        binding: &CaptureBinding,
        request: &FinishRequest,
    ) -> Result<LocalFrozen, Refused> {
        if &request.capture_id != binding.capture_id() {
            return Err(Refused);
        }
        let input = request.encode()?;
        let decoded = decode_terminal(&self.invoke("finish", &input)?, binding);
        #[cfg(test)]
        crate::capture_diagnostics::record(crate::capture_diagnostics::Event::FinishCodec {
            accepted: decoded.is_ok(),
        });
        decoded
    }
    pub fn retry(&self, binding: &CaptureBinding) -> Result<LocalFrozen, Refused> {
        let input = RetryRequest {
            capture_id: binding.capture_id().clone(),
        }
        .encode()?;
        decode_terminal(&self.invoke("retry", &input)?, binding)
    }
}
impl fmt::Debug for ProcessSinkSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessSinkSettings([REDACTED])")
    }
}
impl fmt::Debug for ProcessSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessSink([REDACTED])")
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn transport_progress_emits_only_for_enabled_capture() {
        use crate::capture_diagnostics::{
            self, Event, Guard, Operation, ProcessOutcome, TransportPhase, TransportProgress,
        };
        use std::{os::unix::fs::PermissionsExt, process::Command, time::Duration};
        fn progress(events: &[Event]) -> TransportProgress {
            let records: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    Event::TransportProgress {
                        operation: Operation::Begin,
                        progress,
                    } => Some(*progress),
                    _ => None,
                })
                .collect();
            assert_eq!(
                records.len(),
                1,
                "missing single transport progress event: {events:?}"
            );
            records[0]
        }
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("producer");
        std::fs::write(&executable, "#!/bin/sh\n/usr/bin/cat; printf err >&2\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let make_sink = |executable| {
            super::ProcessSink::new(
                super::ProcessSinkSettings::new(
                    executable,
                    dir.path().join("registry"),
                    dir.path().join("state"),
                    Duration::from_secs(2),
                    1024,
                )
                .unwrap(),
            )
        };
        let sink = make_sink(executable);
        assert!(!capture_diagnostics::enabled());
        assert_eq!(sink.invoke("begin", b"input").unwrap(), b"input");
        let diagnostics = Guard::new();
        assert!(diagnostics.events().is_empty());
        let ordinary = crate::bounded_process::output(
            Command::new("/usr/bin/printf").arg("ordinary"),
            Duration::from_secs(2),
            1024,
        )
        .unwrap();
        assert_eq!(ordinary.stdout, b"ordinary");
        assert!(
            diagnostics.events().is_empty(),
            "ordinary helper must not emit"
        );
        assert_eq!(sink.invoke("begin", b"input").unwrap(), b"input");
        let events = diagnostics.events();
        let p = progress(&events);
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            Event::Process {
                operation: Operation::Begin,
                input_bytes: 5,
                output_bytes: Some(8),
                outcome: ProcessOutcome::Success,
                ..
            }
        ));
        assert_eq!(p.phase, TransportPhase::IoLoop);
        assert_eq!(p.timeout_site, None);
        assert_eq!(p.timeout_observed_us, None);
        assert_eq!(p.spawn_attempts, 1);
        assert_eq!(p.etxtbsy_failures, 0);
        assert!(p.spawned && p.input_complete_closed && p.stdout_eof && p.stderr_eof);
        assert!(p.exit_observed && p.helper_returned);
        assert_eq!(
            (
                p.stdin_bytes_written,
                p.stdout_bytes_read,
                p.stderr_bytes_read
            ),
            (5, 5, 3)
        );
        assert!(p.spawn_return_us.is_some());
        assert!(p.spawn_return_us <= p.cleanup_start_us);
        assert!(p.cleanup_start_us.is_some() && p.cleanup_start_us <= p.cleanup_end_us);
        assert!(p.group_kill_ok.is_some());
        assert_eq!(p.child_kill_ok, None);
        assert_eq!(p.leader_wait_ok, Some(true));
        {
            let failed = Guard::new();
            let missing = dir.path().join("known-missing-producer");
            assert!(!missing.exists());
            assert!(make_sink(missing).invoke("begin", b"input").is_err());
            let events = failed.events();
            let p = progress(&events);
            assert_eq!(events.len(), 2);
            assert!(matches!(
                events[0],
                Event::Process {
                    output_bytes: None,
                    outcome: ProcessOutcome::Io,
                    ..
                }
            ));
            assert_eq!(p.phase, TransportPhase::Spawn);
            assert_eq!(p.spawn_attempts, 1);
            assert_eq!(p.etxtbsy_failures, 0);
            assert!(!p.spawned && !p.input_complete_closed && !p.exit_observed);
            assert!(!p.stdout_eof && !p.stderr_eof);
            assert!(p.helper_returned);
            assert_eq!(
                (
                    p.stdin_bytes_written,
                    p.stdout_bytes_read,
                    p.stderr_bytes_read
                ),
                (0, 0, 0)
            );
            assert_eq!(p.spawn_return_us, None);
            assert_eq!(p.timeout_site, None);
            assert_eq!(p.timeout_observed_us, None);
            assert_eq!(p.cleanup_start_us, None);
            assert_eq!(p.cleanup_end_us, None);
            assert_eq!(p.group_kill_ok, None);
            assert_eq!(p.child_kill_ok, None);
            assert_eq!(p.leader_wait_ok, None);
        }
        assert_eq!(diagnostics.events(), events);
        drop(diagnostics);
        assert!(!capture_diagnostics::enabled());
    }

    #[test]
    fn diagnostics_classify_real_process_outcomes() {
        use crate::capture_diagnostics::{Event, Guard, Operation, ProcessOutcome};
        use std::os::unix::fs::PermissionsExt;
        let diagnostics = Guard::new();
        let dir = tempfile::tempdir().unwrap();
        let mut observed = Vec::new();
        for (index, body, expected) in [
            (0, "sleep 1", ProcessOutcome::Timeout),
            (1, "exit 3", ProcessOutcome::Nonzero),
            (2, "printf ok", ProcessOutcome::Success),
        ] {
            let executable = dir.path().join(index.to_string());
            std::fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let sink = super::ProcessSink::new(
                super::ProcessSinkSettings::new(
                    executable,
                    dir.path().join("registry"),
                    dir.path().join("state"),
                    std::time::Duration::from_millis(50),
                    1024,
                )
                .unwrap(),
            );
            let result = sink.invoke("finish", b"");
            observed.push((expected, result.is_ok(), diagnostics.events()));
        }
        for (expected, success, events) in observed {
            assert_eq!(success, expected == ProcessOutcome::Success);
            assert!(events.iter().any(|e| matches!(e,
                Event::Process { operation: Operation::Finish, timeout_ms: 50, outcome, .. } if *outcome == expected)), "missing process classification {expected:?}: {events:?}");
        }
    }
}
