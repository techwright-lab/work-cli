//! Bounded process I/O with owned process-group cleanup (not malicious setsid containment).
//! Kernel uninterruptible I/O can delay kill/reap; deadlines are not a hard D-state bound.
use std::{
    io::{self, Read, Write},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

#[cfg(test)]
use crate::capture_diagnostics::{TransportPhase, TransportProgress, TransportTimeoutSite};

pub(crate) fn output_aggregate(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> Result<Output, &'static str> {
    output_mode(
        command,
        timeout,
        limit,
        true,
        None,
        #[cfg(test)]
        None,
    )
}

pub(crate) fn output_with_input_aggregate(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
    input: &[u8],
) -> Result<Output, &'static str> {
    output_mode(
        command,
        timeout,
        limit,
        true,
        Some(input),
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
pub(crate) fn output_with_input_aggregate_observed(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
    input: &[u8],
    progress: &mut TransportProgress,
) -> Result<Output, &'static str> {
    let result = output_mode(command, timeout, limit, true, Some(input), Some(progress));
    progress.helper_returned = true;
    result
}

// Aggregate capture cannot probe EOF at an exhausted boundary: even a one-byte
// lookahead violates the caller's OS-read budget. Exact-cap output is held.
fn capture_read(pipe: &mut dyn Read, buffer: &mut [u8], remaining: usize) -> io::Result<usize> {
    if remaining == 0 {
        return Err(io::Error::other("capture capacity exhausted"));
    }
    let length = buffer.len().min(remaining).min(8192);
    pipe.read(&mut buffer[..length])
}

pub(crate) fn output(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> Result<Output, &'static str> {
    output_mode(
        command,
        timeout,
        limit,
        false,
        None,
        #[cfg(test)]
        None,
    )
}

fn output_mode(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
    aggregate: bool,
    input: Option<&[u8]>,
    #[cfg(test)] mut progress: Option<&mut TransportProgress>,
) -> Result<Output, &'static str> {
    use std::os::unix::process::CommandExt;
    const IO_ERROR: &str = "Git process I/O unavailable; inventory incomplete";
    let start = Instant::now();
    command
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            #[cfg(test)]
            if let Some(p) = progress.as_deref_mut() {
                p.timeout_site = Some(TransportTimeoutSite::PreSpawn);
                p.timeout_observed_us = Some(elapsed.as_micros());
            }
            return Err("Git runtime limit reached; inventory incomplete");
        }
        #[cfg(test)]
        if let Some(p) = progress.as_deref_mut() {
            p.phase = TransportPhase::Spawn;
            p.spawn_attempts = p.spawn_attempts.saturating_add(1);
        }
        match command.spawn() {
            Ok(child) => {
                #[cfg(test)]
                if let Some(p) = progress.as_deref_mut() {
                    p.spawned = true;
                    p.spawn_return_us = Some(start.elapsed().as_micros());
                }
                break child;
            }
            // Internal callers use fixed programs without pre_exec callbacks.
            // ETXTBSY is a failed exec: no helper code or stdin protocol ran.
            // Reuse Command; std closes each failed attempt's capture pipes.
            Err(error)
                if error.raw_os_error() == Some(rustix::io::Errno::TXTBSY.raw_os_error()) =>
            {
                #[cfg(test)]
                if let Some(p) = progress.as_deref_mut() {
                    p.etxtbsy_failures = p.etxtbsy_failures.saturating_add(1);
                }
                std::thread::sleep(
                    Duration::from_millis(2).min(timeout.saturating_sub(start.elapsed())),
                );
            }
            Err(_) => return Err(IO_ERROR),
        }
    };
    let group = rustix::process::Pid::from_raw(child.id() as i32).ok_or(IO_ERROR)?;
    #[cfg(test)]
    if let Some(p) = progress.as_deref_mut() {
        p.phase = TransportPhase::PipeSetup;
    }
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or(IO_ERROR)?;
        let mut stderr = child.stderr.take().ok_or(IO_ERROR)?;
        for fd in [
            &stdout as &dyn std::os::fd::AsFd,
            &stderr as &dyn std::os::fd::AsFd,
        ] {
            rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::NONBLOCK).map_err(|_| IO_ERROR)?;
        }
        let mut stdin = child.stdin.take();
        if let Some(pipe) = &stdin {
            rustix::fs::fcntl_setfl(pipe, rustix::fs::OFlags::NONBLOCK).map_err(|_| IO_ERROR)?;
        }
        let input = input.unwrap_or_default();
        let mut written: usize = 0;
        if input.is_empty() {
            drop(stdin.take());
            #[cfg(test)]
            if let Some(p) = progress.as_deref_mut() {
                p.input_complete_closed = true;
            }
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut eof = [false; 2];
        let mut remaining = limit;
        #[cfg(test)]
        if let Some(p) = progress.as_deref_mut() {
            p.phase = TransportPhase::IoLoop;
        }
        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                #[cfg(test)]
                if let Some(p) = progress.as_deref_mut() {
                    p.timeout_site = Some(TransportTimeoutSite::IoLoop);
                    p.timeout_observed_us = Some(elapsed.as_micros());
                }
                return Err("Git runtime limit reached; inventory incomplete");
            }
            let mut progressed = false;
            for (index, (pipe, bytes)) in [
                (&mut stdout as &mut dyn Read, &mut out),
                (&mut stderr as &mut dyn Read, &mut err),
            ]
            .into_iter()
            .enumerate()
            {
                if eof[index] {
                    continue;
                }
                let mut buffer = [0; 8192];
                if aggregate && remaining == 0 {
                    return Err("Git capture limit reached; inventory incomplete");
                }
                let read = if aggregate {
                    capture_read(pipe, &mut buffer, remaining)
                } else {
                    pipe.read(&mut buffer)
                };
                match read {
                    Ok(0) => {
                        eof[index] = true;
                        #[cfg(test)]
                        if let Some(p) = progress.as_deref_mut() {
                            if index == 0 {
                                p.stdout_eof = true;
                            } else {
                                p.stderr_eof = true;
                            }
                        }
                    }
                    Ok(n) => {
                        #[cfg(test)]
                        if let Some(p) = progress.as_deref_mut() {
                            let count = if index == 0 {
                                &mut p.stdout_bytes_read
                            } else {
                                &mut p.stderr_bytes_read
                            };
                            *count = count.saturating_add(n as u64);
                        }
                        if n > limit.saturating_sub(bytes.len()) {
                            return Err("Git capture limit reached; inventory incomplete");
                        }
                        bytes.extend_from_slice(&buffer[..n]);
                        if aggregate {
                            remaining -= n;
                            if remaining == 0 {
                                return Err("Git capture limit reached; inventory incomplete");
                            }
                        }
                        progressed = true;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(IO_ERROR),
                }
            }
            if let Some(pipe) = &mut stdin {
                let end = input.len().min(written.saturating_add(8192));
                match pipe.write(&input[written..end]) {
                    Ok(0) => return Err(IO_ERROR),
                    Ok(n) => {
                        written += n;
                        #[cfg(test)]
                        if let Some(p) = progress.as_deref_mut() {
                            p.stdin_bytes_written = p.stdin_bytes_written.saturating_add(n as u64);
                        }
                        progressed = true;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(IO_ERROR),
                }
                if written == input.len() {
                    drop(stdin.take());
                    #[cfg(test)]
                    if let Some(p) = progress.as_deref_mut() {
                        p.input_complete_closed = true;
                    }
                }
            }
            // Observe exit without reaping: keep the leader PID/group owned until
            // cleanup, avoiding a recycled process-group ID after try_wait/reap.
            use rustix::process::{waitid, WaitId, WaitIdOptions};
            if eof == [true; 2]
                && waitid(
                    WaitId::Pid(group),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                )
                .map_err(|_| IO_ERROR)?
                .is_some()
            {
                #[cfg(test)]
                if let Some(p) = progress.as_deref_mut() {
                    p.exit_observed = true;
                }
                if written != input.len() {
                    return Err(IO_ERROR);
                }
                return Ok((out, err));
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    })();
    // Every failure path, including setup/read failures, kills and reaps. No
    // reader threads survive a deadline and neither pipe grows without bound.
    // Kill the owned group even when the leader exited successfully: descendants
    // must not escape through closed capture pipes. Never target the caller's group.
    #[cfg(test)]
    if let Some(p) = progress.as_deref_mut() {
        p.cleanup_start_us = Some(start.elapsed().as_micros());
    }
    #[cfg(not(test))]
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    #[cfg(test)]
    {
        let killed = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        if let Some(p) = progress.as_deref_mut() {
            p.group_kill_ok = Some(killed.is_ok());
        }
    }
    if result.is_err() {
        #[cfg(not(test))]
        let _ = child.kill();
        #[cfg(test)]
        {
            let killed = child.kill();
            if let Some(p) = progress.as_deref_mut() {
                p.child_kill_ok = Some(killed.is_ok());
            }
        }
    }
    let status = child.wait().map_err(|_| IO_ERROR);
    #[cfg(test)]
    if let Some(p) = progress {
        p.leader_wait_ok = Some(status.is_ok());
        p.cleanup_end_us = Some(start.elapsed().as_micros());
    }
    let (stdout, stderr) = result?;
    Ok(Output {
        status: status?,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_progress_preserves_partial_reads_at_cap() {
        use crate::capture_diagnostics::{Event, Guard, Operation, TransportGuard};
        let diagnostics = Guard::new();
        let mut transport = TransportGuard::new("finish").unwrap();
        let result = output_with_input_aggregate_observed(
            Command::new("/usr/bin/printf").arg("12345678"),
            Duration::from_secs(2),
            8,
            b"",
            transport.progress(),
        );
        assert_eq!(
            result.unwrap_err(),
            "Git capture limit reached; inventory incomplete"
        );
        drop(transport);
        let events = diagnostics.events();
        assert_eq!(events.len(), 1);
        let Event::TransportProgress {
            operation: Operation::Finish,
            progress: p,
        } = events[0]
        else {
            panic!("missing cap progress: {events:?}");
        };
        assert_eq!((p.stdout_bytes_read, p.stderr_bytes_read), (8, 0));
        assert_eq!(p.stdin_bytes_written, 0);
        assert!(p.input_complete_closed);
        assert!(!p.stdout_eof, "exact-cap refusal must not infer EOF");
        assert!(!p.exit_observed, "cap refusal precedes waitid observation");
        assert!(p.spawned && p.helper_returned);
        assert_eq!(p.phase, TransportPhase::IoLoop);
        assert_eq!(p.timeout_site, None);
        assert_eq!(p.timeout_observed_us, None);
        assert!(p.spawn_return_us.is_some() && p.spawn_return_us <= p.cleanup_start_us);
        assert!(p.cleanup_start_us.is_some() && p.cleanup_start_us <= p.cleanup_end_us);
        assert!(p.group_kill_ok.is_some() && p.child_kill_ok.is_some());
        assert_eq!(p.leader_wait_ok, Some(true));
    }

    #[test]
    fn transport_progress_distinguishes_deadline_sites() {
        use crate::capture_diagnostics::TransportTimeoutSite;
        const TIMEOUT: &str = "Git runtime limit reached; inventory incomplete";
        fn no_child(p: &TransportProgress) {
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
            assert_eq!(p.cleanup_start_us, None);
            assert_eq!(p.cleanup_end_us, None);
            assert_eq!(p.group_kill_ok, None);
            assert_eq!(p.child_kill_ok, None);
            assert_eq!(p.leader_wait_ok, None);
        }
        let mut zero = TransportProgress::default();
        assert_eq!(
            output_with_input_aggregate_observed(
                &mut Command::new("/usr/bin/true"),
                Duration::ZERO,
                1024,
                b"",
                &mut zero,
            )
            .unwrap_err(),
            TIMEOUT
        );
        assert_eq!(
            zero.timeout_site,
            Some(TransportTimeoutSite::PreSpawn),
            "missing pre-spawn deadline observation"
        );
        assert_eq!(zero.phase, TransportPhase::PreSpawn);
        assert_eq!(zero.spawn_attempts, 0);
        assert_eq!(zero.etxtbsy_failures, 0);
        assert!(zero.timeout_observed_us.is_some());
        no_child(&zero);

        let temp = tempfile::tempdir().unwrap();
        let (mut command, _writer) = writable_script(&temp, "printf called > \"$1\"");
        let mut busy = TransportProgress::default();
        assert_eq!(
            output_with_input_aggregate_observed(
                &mut command,
                Duration::from_millis(40),
                1024,
                b"input",
                &mut busy,
            )
            .unwrap_err(),
            TIMEOUT
        );
        assert!(!temp.path().join("called").exists());
        assert_eq!(busy.timeout_site, Some(TransportTimeoutSite::PreSpawn));
        assert!(busy.timeout_observed_us.unwrap() >= 40_000);
        assert_eq!(busy.spawn_attempts, busy.etxtbsy_failures);
        assert_eq!(
            busy.phase,
            if busy.spawn_attempts == 0 {
                TransportPhase::PreSpawn
            } else {
                TransportPhase::Spawn
            }
        );
        no_child(&busy);

        // Natural scheduling qualification, not a deterministic timeout seam.
        // The owned shell publishes its PID/output then execs a native sleeper.
        let pid = temp.path().join("leader");
        let mut io = TransportProgress::default();
        let result = output_with_input_aggregate_observed(
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "printf '%s' $$ > \"$1\"; printf partial; exec /usr/bin/sleep 30",
                    "transport-fixture",
                ])
                .arg(&pid),
            Duration::from_millis(100),
            1024,
            b"",
            &mut io,
        );
        assert_eq!(result.unwrap_err(), TIMEOUT);
        let leader = std::fs::read_to_string(pid).unwrap();
        assert!(
            !std::path::Path::new(&format!("/proc/{leader}")).exists(),
            "leader not reaped"
        );
        assert_eq!(io.timeout_site, Some(TransportTimeoutSite::IoLoop));
        assert_eq!(io.phase, TransportPhase::IoLoop);
        assert_eq!(io.spawn_attempts, 1);
        assert_eq!(io.etxtbsy_failures, 0);
        assert!(io.spawned && io.input_complete_closed && io.helper_returned);
        assert_eq!(
            (
                io.stdin_bytes_written,
                io.stdout_bytes_read,
                io.stderr_bytes_read
            ),
            (0, 7, 0)
        );
        assert!(!io.stdout_eof && !io.stderr_eof && !io.exit_observed);
        assert!(io.timeout_observed_us.unwrap() >= 100_000);
        assert!(io.spawn_return_us.is_some() && io.spawn_return_us <= io.timeout_observed_us);
        assert!(io.timeout_observed_us <= io.cleanup_start_us);
        assert!(io.cleanup_start_us <= io.cleanup_end_us);
        assert!(io.cleanup_end_us.is_some());
        assert_eq!(io.group_kill_ok, Some(true));
        assert!(io.child_kill_ok.is_some());
        assert_eq!(io.leader_wait_ok, Some(true));
    }

    fn writable_script(temp: &tempfile::TempDir, body: &str) -> (Command, std::fs::File) {
        use std::{io::Write, os::unix::fs::PermissionsExt};
        let path = temp.path().join("helper");
        let mut writer = std::fs::File::create(&path).unwrap();
        write!(writer, "#!/bin/sh\n{body}\n").unwrap();
        writer
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let mut command = Command::new(path);
        command.arg(temp.path().join("called"));
        (command, writer)
    }

    #[test]
    fn input_interleaves_with_large_output_and_closes_at_eof() {
        let input = vec![b'x'; 256 * 1024];
        let result = output_with_input_aggregate(
            Command::new("/bin/sh").args(["-c", "head -c 131072 /dev/zero; wc -c"]),
            Duration::from_secs(2),
            200000,
            &input,
        )
        .unwrap();
        assert!(result.status.success());
        assert_eq!(&result.stdout[131072..], b"262144\n");
        let empty = output_with_input_aggregate(
            Command::new("/bin/sh").args(["-c", "wc -c"]),
            Duration::from_secs(2),
            32,
            b"",
        )
        .unwrap();
        assert_eq!(empty.stdout, b"0\n");
    }

    #[test]
    fn incomplete_input_is_refused_and_blocked_input_is_bounded() {
        let input = vec![b'x'; 1024 * 1024];
        for body in ["exit 0", "exec sleep 30"] {
            let start = Instant::now();
            assert!(output_with_input_aggregate(
                Command::new("/bin/sh").args(["-c", body]),
                Duration::from_millis(50),
                32,
                &input,
            )
            .is_err());
            assert!(start.elapsed() < Duration::from_secs(2));
        }
    }

    #[test]
    fn input_busy_exec_retry_delivers_once_and_shares_the_original_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let (mut command, writer) =
            writable_script(&temp, "printf 'called\\n' >> \"$1\"; /usr/bin/cat; exit 9");
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(writer);
        });
        let output = output_with_input_aggregate(
            &mut command,
            Duration::from_secs(2),
            100,
            b"literal input",
        )
        .unwrap();
        release.join().unwrap();
        assert_eq!(output.status.code(), Some(9));
        assert_eq!(output.stdout, b"literal input");
        assert_eq!(
            std::fs::read(temp.path().join("called")).unwrap(),
            b"called\n"
        );

        let temp = tempfile::tempdir().unwrap();
        let (mut command, writer) = writable_script(
            &temp,
            "printf called > \"$1\"; /usr/bin/sleep 0.2; /usr/bin/cat",
        );
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            drop(writer);
        });
        assert!(output_with_input_aggregate(
            &mut command,
            Duration::from_millis(350),
            100,
            b"literal"
        )
        .is_err());
        release.join().unwrap();
        assert!(temp.path().join("called").exists());
        let temp = tempfile::tempdir().unwrap();
        let (mut command, _writer) = writable_script(&temp, "printf called > \"$1\"");
        assert!(output_with_input_aggregate(
            &mut command,
            Duration::from_millis(40),
            100,
            b"literal"
        )
        .is_err());
        assert!(!temp.path().join("called").exists());
    }

    #[test]
    fn blocked_input_cleanup_reaps_leader_and_aggregate_exhaustion_is_shared() {
        let temp = tempfile::tempdir().unwrap();
        let pid = temp.path().join("pid");
        let body = format!("printf '%s' $$ > '{}'; exec sleep 30", pid.display());
        assert!(output_with_input_aggregate(
            Command::new("/bin/sh").args(["-c", &body]),
            Duration::from_millis(100),
            100,
            &vec![b'x'; 1024 * 1024],
        )
        .is_err());
        let leader = std::fs::read_to_string(pid).unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists());
        let body = format!(
            "printf '{}'; printf '{}' >&2; /usr/bin/cat",
            "o".repeat(80),
            "e".repeat(80)
        );
        assert_eq!(
            output_with_input_aggregate(
                Command::new("/bin/sh").args(["-c", &body]),
                Duration::from_secs(2),
                160,
                b"input"
            )
            .unwrap_err(),
            "Git capture limit reached; inventory incomplete"
        );
    }

    #[test]
    fn aggregate_capture_shares_capacity_but_per_stream_capture_does_not() {
        let body = format!(
            "printf '{}'; printf '{}' >&2",
            "o".repeat(80),
            "e".repeat(80)
        );
        let per_stream = output(
            Command::new("/bin/sh").args(["-c", &body]),
            Duration::from_secs(2),
            100,
        )
        .unwrap();
        assert_eq!(per_stream.stdout.len() + per_stream.stderr.len(), 160);
        assert_eq!(
            output_aggregate(
                Command::new("/bin/sh").args(["-c", &body]),
                Duration::from_secs(2),
                100
            )
            .unwrap_err(),
            "Git capture limit reached; inventory incomplete"
        );
    }

    #[test]
    fn aggregate_boundary_is_conservative_without_eof_lookahead() {
        for (stdout, stderr, limit, success) in [
            (80, 80, 161, true),
            (80, 80, 160, false),
            (0, 0, 0, false),
            (0, 0, 1, true),
        ] {
            let body = format!(
                "printf '{}'; printf '{}' >&2",
                "o".repeat(stdout),
                "e".repeat(stderr)
            );
            let result = output_aggregate(
                Command::new("/bin/sh").args(["-c", &body]),
                Duration::from_secs(2),
                limit,
            );
            if success {
                let output = result.unwrap();
                assert!(output.status.success());
                assert_eq!(output.stdout.len(), stdout);
                assert_eq!(output.stderr.len(), stderr);
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    "Git capture limit reached; inventory incomplete"
                );
            }
        }
    }

    #[test]
    fn aggregate_exhaustion_kills_owned_descendants_and_reaps_leader() {
        for _ in 0..3 {
            let temp = tempfile::tempdir().unwrap();
            let pids = temp.path().join("pids");
            let body = format!(
                "sleep 30 & child=$!; printf '%s %s' $$ $child > '{}'; printf '{}'; wait",
                pids.display(),
                "x".repeat(160)
            );
            assert_eq!(
                output_aggregate(
                    Command::new("/bin/sh").args(["-c", &body]),
                    Duration::from_secs(2),
                    100
                )
                .unwrap_err(),
                "Git capture limit reached; inventory incomplete"
            );
            let pids = std::fs::read_to_string(pids).unwrap();
            let mut pids = pids.split_whitespace();
            let leader = pids.next().unwrap();
            assert!(
                !std::path::Path::new(&format!("/proc/{leader}")).exists(),
                "leader not reaped"
            );
            let child = pids.next().unwrap();
            // A killed orphan may remain a zombie until init reaps it. Wait for
            // the delivered SIGKILL, not an outer elapsed-time success oracle.
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match std::fs::read_to_string(format!("/proc/{child}/stat")) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                    Ok(stat)
                        if stat.rsplit_once(')').unwrap().1.split_whitespace().next()
                            == Some("Z") =>
                    {
                        break
                    }
                    state => {
                        assert!(Instant::now() < deadline, "descendant survived: {state:?}");
                        std::thread::yield_now();
                    }
                }
            }
        }
    }

    #[test]
    fn capture_read_never_requests_or_consumes_beyond_remaining() {
        struct CountRead {
            requests: Vec<usize>,
            consumed: usize,
        }
        impl Read for CountRead {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.requests.push(buf.len());
                buf.fill(b'x');
                self.consumed += buf.len();
                Ok(buf.len())
            }
        }
        let mut reader = CountRead {
            requests: vec![],
            consumed: 0,
        };
        let mut buffer = [0; 16384];
        assert_eq!(capture_read(&mut reader, &mut buffer, 100).unwrap(), 100);
        assert_eq!(reader.requests, [100]);
        assert_eq!(reader.consumed, 100);
        assert!(capture_read(&mut reader, &mut buffer, 0).is_err());
        assert_eq!(
            reader.requests,
            [100],
            "zero capacity must not read or infer EOF"
        );
    }

    #[test]
    fn retries_busy_executable_until_writer_closes_then_executes_once() {
        let temp = tempfile::tempdir().unwrap();
        let (mut command, writer) = writable_script(
            &temp,
            "printf 'called\\n' >> \"$1\"; printf captured; printf diagnostic >&2",
        );
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            drop(writer);
        });
        let result = output(&mut command, Duration::from_secs(2), 32);
        release.join().unwrap();
        let result = result.unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"captured");
        assert_eq!(result.stderr, b"diagnostic");
        assert_eq!(
            std::fs::read(temp.path().join("called")).unwrap(),
            b"called\n"
        );
    }

    #[test]
    fn busy_executable_held_through_deadline_never_starts() {
        let temp = tempfile::tempdir().unwrap();
        let (mut command, _writer) = writable_script(&temp, "printf called > \"$1\"");
        let start = Instant::now();
        assert_eq!(
            output(&mut command, Duration::from_millis(40), 32).unwrap_err(),
            "Git runtime limit reached; inventory incomplete"
        );
        assert!(start.elapsed() >= Duration::from_millis(40));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!temp.path().join("called").exists());
    }

    #[test]
    fn busy_spawn_and_capture_share_one_runtime_budget() {
        let temp = tempfile::tempdir().unwrap();
        let (mut command, writer) = writable_script(
            &temp,
            "printf called > \"$1\"; /usr/bin/sleep 0.2; printf finished",
        );
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            drop(writer);
        });
        let result = output(&mut command, Duration::from_millis(350), 32);
        release.join().unwrap();
        assert_eq!(
            result.unwrap_err(),
            "Git runtime limit reached; inventory incomplete"
        );
        assert!(temp.path().join("called").exists());
    }

    #[test]
    fn other_spawn_errors_return_io_error_without_waiting_for_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("helper");
        for exists in [false, true] {
            if exists {
                std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
            }
            let start = Instant::now();
            assert_eq!(
                output(&mut Command::new(&path), Duration::from_secs(2), 32).unwrap_err(),
                "Git process I/O unavailable; inventory incomplete"
            );
            assert!(start.elapsed() < Duration::from_secs(1));
        }
    }

    #[test]
    fn timeout_kills_descendants_holding_capture_pipes() {
        let temp = tempfile::tempdir().unwrap();
        let sentinel = temp.path().join("survived");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!("(sleep 0.2; touch {}) & wait", sentinel.display()));
        assert!(output(&mut command, Duration::from_millis(30), 1024).is_err());
        std::thread::sleep(Duration::from_millis(300));
        assert!(!sentinel.exists(), "descendant survived timeout");
    }
    #[test]
    fn captures_normal_output() {
        let result = output(
            Command::new("/usr/bin/printf").arg("hello"),
            Duration::from_secs(1),
            16,
        )
        .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"hello");
    }
    #[test]
    fn kills_and_reaps_on_runtime_or_capture_exhaustion() {
        for _ in 0..3 {
            let start = std::time::Instant::now();
            assert_eq!(
                output(
                    Command::new("/usr/bin/sleep").arg("10"),
                    Duration::from_millis(30),
                    32
                )
                .unwrap_err(),
                "Git runtime limit reached; inventory incomplete"
            );
            assert!(start.elapsed() < Duration::from_secs(2));
            assert_eq!(
                output(
                    &mut Command::new("/usr/bin/yes"),
                    Duration::from_secs(1),
                    32
                )
                .unwrap_err(),
                "Git capture limit reached; inventory incomplete"
            );
            let mut stderr = Command::new("/usr/bin/yes");
            // Invalid option produces stderr larger than this one-byte budget.
            stderr.arg("--invalid-option");
            assert_eq!(
                output(&mut stderr, Duration::from_secs(1), 1).unwrap_err(),
                "Git capture limit reached; inventory incomplete"
            );
        }
    }
}
