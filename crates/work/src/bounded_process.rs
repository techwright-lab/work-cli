//! Bounded Git capture with owned process-group cleanup (not malicious setsid containment).
use std::{
    io::{self, Read},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

pub(crate) fn output(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> Result<Output, &'static str> {
    use std::os::unix::process::CommandExt;
    const IO_ERROR: &str = "Git process I/O unavailable; inventory incomplete";
    let start = Instant::now();
    command
        .process_group(0)
        .stdin(Stdio::null())
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
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut eof = [false; 2];
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
                match pipe.read(&mut buffer) {
                    Ok(0) => eof[index] = true,
                    Ok(n) => {
                        if n > limit.saturating_sub(bytes.len()) {
                            return Err("Git capture limit reached; inventory incomplete");
                        }
                        bytes.extend_from_slice(&buffer[..n]);
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
