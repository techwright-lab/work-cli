//! Bounded process I/O with owned process-group cleanup (not malicious setsid containment).
//! Kernel uninterruptible I/O can delay kill/reap; deadlines are not a hard D-state bound.
use std::{
    io::{self, Read, Write},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

pub(crate) fn output_aggregate(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> Result<Output, &'static str> {
    output_mode(command, timeout, limit, true, None)
}

pub(crate) fn output_with_input_aggregate(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
    input: &[u8],
) -> Result<Output, &'static str> {
    output_mode(command, timeout, limit, true, Some(input))
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
    output_mode(command, timeout, limit, false, None)
}

fn output_mode(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
    aggregate: bool,
    input: Option<&[u8]>,
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
        if start.elapsed() >= timeout {
            return Err("Git runtime limit reached; inventory incomplete");
        }
        match command.spawn() {
            Ok(child) => break child,
            // Internal callers use fixed programs without pre_exec callbacks.
            // ETXTBSY is a failed exec: no helper code or stdin protocol ran.
            // Reuse Command; std closes each failed attempt's capture pipes.
            Err(error)
                if error.raw_os_error() == Some(rustix::io::Errno::TXTBSY.raw_os_error()) =>
            {
                std::thread::sleep(
                    Duration::from_millis(2).min(timeout.saturating_sub(start.elapsed())),
                );
            }
            Err(_) => return Err(IO_ERROR),
        }
    };
    let group = rustix::process::Pid::from_raw(child.id() as i32).ok_or(IO_ERROR)?;
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
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut eof = [false; 2];
        let mut remaining = limit;
        loop {
            if start.elapsed() >= timeout {
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
                    Ok(0) => eof[index] = true,
                    Ok(n) => {
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
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| IO_ERROR);
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
