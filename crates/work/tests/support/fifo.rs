//! Owned FIFO fixtures only; never a readable-open fallback for production code.
use std::path::Path;

pub fn create_fifo(path: &Path, mode: rustix::fs::Mode) {
    assert!(path.is_absolute(), "FIFO fixture path must be absolute");
    #[cfg(not(target_os = "macos"))]
    rustix::fs::mkfifoat(rustix::fs::CWD, path, mode).unwrap();

    // rustix does not expose mkfifoat on Darwin. This child only constructs an
    // owned test fixture, and must be reaped even if the utility stalls.
    #[cfg(target_os = "macos")]
    {
        use std::{
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let mut child = Command::new("/usr/bin/mkfifo")
            .arg("-m")
            .arg(format!("{:o}", mode.bits()))
            .arg(path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success(), "mkfifo fixture failed: {status}");
                    break;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                outcome => {
                    let killed = child.kill();
                    let reaped = child.wait();
                    panic!(
                        "mkfifo fixture unavailable: {outcome:?}; kill={killed:?}; wait={reaped:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn fifo_fixture_preserves_opaque_path_type_and_zero_mode() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fifo ; $opaque path");
    create_fifo(&path, rustix::fs::Mode::empty());
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_fifo());
    // Zero mode is independent of the process umask; never change global umask.
    assert_eq!(metadata.permissions().mode() & 0o777, 0);
}

#[test]
fn fifo_fixture_preserves_non_utf8_path_where_supported() {
    use std::os::unix::{ffi::OsStrExt, fs::FileTypeExt};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join(std::ffi::OsStr::from_bytes(b"fifo-\xff"));
    // APFS can refuse the name before the FIFO utility is involved. Distinguish
    // this filesystem limitation from exercising the helper's opaque argument.
    match std::fs::write(&path, b"name probe") {
        Ok(()) => std::fs::remove_file(&path).unwrap(),
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::ILSEQ.raw_os_error()) => {
            eprintln!("NOT_EXERCISED: filesystem refused non-UTF8 fixture name: {error}");
            return;
        }
        Err(error) => panic!("non-UTF8 fixture name probe failed: {error}"),
    }
    create_fifo(&path, rustix::fs::Mode::RUSR);
    assert!(std::fs::symlink_metadata(path)
        .unwrap()
        .file_type()
        .is_fifo());
}
