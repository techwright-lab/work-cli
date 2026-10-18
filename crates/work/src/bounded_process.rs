//! Bounded capture for read-only Git inventory subprocesses.
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
    const IO_ERROR: &str = "Git process I/O unavailable; inventory incomplete";
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| IO_ERROR)?;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or(IO_ERROR)?;
        let mut stderr = child.stderr.take().ok_or(IO_ERROR)?;
        for fd in [
            &stdout as &dyn std::os::fd::AsFd,
            &stderr as &dyn std::os::fd::AsFd,
        ] {
            rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::NONBLOCK).map_err(|_| IO_ERROR)?;
        }
        let start = Instant::now();
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
            if let Some(status) = child.try_wait().map_err(|_| IO_ERROR)? {
                if eof == [true; 2] {
                    return Ok(Output {
                        status,
                        stdout: out,
                        stderr: err,
                    });
                }
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    })();
    // Every failure path, including setup/read failures, kills and reaps. No
    // reader threads survive a deadline and neither pipe grows without bound.
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
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
