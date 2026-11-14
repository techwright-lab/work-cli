//! Test-only characterization: a completed experiment is not payload-read admission.
use work_darwin::Attributes;

#[derive(Debug, Eq, PartialEq)]
enum WriteObservation {
    Unavailable,
    IdentityChanged,
    RepeatedToken,
    ChangedToken,
}

fn observe_write(before: Option<Attributes>, after: Option<Attributes>) -> WriteObservation {
    match (before, after) {
        (Some(before), Some(after)) if before.file_id != after.file_id => {
            WriteObservation::IdentityChanged
        }
        (Some(before), Some(after)) if before.generation == after.generation => {
            WriteObservation::RepeatedToken
        }
        (Some(_), Some(_)) => WriteObservation::ChangedToken,
        _ => WriteObservation::Unavailable,
    }
}

#[cfg(test)]
mod reporting_tests {
    use super::*;
    use work_darwin::{decode_attributes, AttributeSet};

    fn token(file_id: u64, generation: u32) -> Attributes {
        Attributes {
            returned: AttributeSet {
                common: 0x8208_0000,
                volume: 0,
                directory: 0,
                file: 0,
                fork: 0,
            },
            file_id,
            generation,
        }
    }

    #[test]
    fn native_generation_reporting_nonzero_repeated_token_does_not_detect_write() {
        let valid = Some(token(7, 42));
        assert_eq!(observe_write(valid, valid), WriteObservation::RepeatedToken);
    }

    #[test]
    fn native_generation_reporting_distinguishes_change_from_object_replacement() {
        assert_eq!(
            observe_write(Some(token(7, 42)), Some(token(7, 43))),
            WriteObservation::ChangedToken
        );
        assert_eq!(
            observe_write(Some(token(7, 42)), Some(token(8, 43))),
            WriteObservation::IdentityChanged
        );
    }

    #[test]
    fn native_generation_reporting_missing_zero_or_failed_observations_remain_unavailable() {
        // Exercise the existing strict decoder, not a permissive diagnostics parser.
        let mut wire = [0u8; 36];
        wire[..4].copy_from_slice(&36u32.to_ne_bytes());
        wire[4..8].copy_from_slice(&0x8208_0000u32.to_ne_bytes());
        wire[28..36].copy_from_slice(&7u64.to_ne_bytes());
        let zero = decode_attributes(&wire).ok();
        assert!(zero.is_none());
        wire[4..8].copy_from_slice(&0x8200_0000u32.to_ne_bytes());
        let missing = decode_attributes(&wire).ok();
        assert!(missing.is_none());
        for unavailable in [zero, missing, None] {
            assert_eq!(
                observe_write(Some(token(7, 42)), unavailable),
                WriteObservation::Unavailable
            );
            assert_eq!(
                observe_write(unavailable, Some(token(7, 43))),
                WriteObservation::Unavailable
            );
        }
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions, Permissions};
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::time::{Duration, SystemTime};
    use work_darwin::{attributes_at, AttributeError, ATTRIBUTE_BUFFER_SIZE};

    #[derive(Debug, Eq, PartialEq)]
    struct Metadata {
        dev: u64,
        ino: u64,
        mode: u32,
        nlink: u64,
        uid: u32,
        gid: u32,
        size: u64,
        mtime: (i64, i64),
        ctime: (i64, i64),
    }

    fn metadata(path: &Path) -> Metadata {
        let m = fs::symlink_metadata(path).unwrap();
        assert!(m.is_file(), "fixture must remain a regular file");
        Metadata {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            nlink: m.nlink(),
            uid: m.uid(),
            gid: m.gid(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }

    struct Sample {
        token: Option<Attributes>,
        metadata: Metadata,
    }

    fn sample(parent: &File, root: &Path, name: &str, label: &str) -> Sample {
        let before = metadata(&root.join(name));
        let mut wire = [0xff; ATTRIBUTE_BUFFER_SIZE];
        let result = attributes_at(parent.as_fd(), &CString::new(name).unwrap(), &mut wire);
        // Only a successful syscall (including a strict decoder refusal) permits
        // interpreting the returned header. Never parse errno/preflight bytes.
        let syscall_succeeded = matches!(&result, Ok(_) | Err(AttributeError::Decode(_)));
        let errno = match &result {
            Err(AttributeError::Os(error)) => error.raw_os_error(),
            _ => None,
        };
        let declared = syscall_succeeded.then(|| u32::from_ne_bytes(wire[..4].try_into().unwrap()));
        let masks = declared
            .filter(|length| (24..=36).contains(length) && length % 4 == 0)
            .map(|_| {
                std::array::from_fn::<_, 5, _>(|index| {
                    u32::from_ne_bytes(wire[4 + index * 4..8 + index * 4].try_into().unwrap())
                })
            });
        // Raw generation is diagnostic only; zero MUST still fail strict decoding.
        let raw_generation = match (declared, masks) {
            (Some(length), Some(masks)) if length >= 28 && masks[0] & 0x0008_0000 != 0 => {
                Some(u32::from_ne_bytes(wire[24..28].try_into().unwrap()))
            }
            _ => None,
        };
        let after = metadata(&root.join(name));
        eprintln!(
            "A3b SAMPLE {label}: name={name:?} syscall_succeeded={syscall_succeeded} errno={errno:?} declared_length={declared:?} returned_masks={masks:#x?} raw_generation={raw_generation:?} strict_result={result:?} initialized_raw_window={wire:02x?} metadata_before={before:?} metadata_after={after:?}"
        );
        assert_eq!(before, after, "fixture metadata changed during observation");
        let token = result.ok();
        if let Some(token) = token {
            assert_eq!(token.file_id, after.ino);
        }
        Sample {
            token,
            metadata: after,
        }
    }

    struct Fixture {
        root: PathBuf,
        parent: File,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "work-darwin-generation-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&root).unwrap(); // Never reuse/adopt an existing path.
            fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
            eprintln!("A3b retained owned fixture: {}", root.display());
            let parent = File::open(&root).unwrap();
            Self { root, parent }
        }

        fn create(&self, name: &str) -> File {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(self.root.join(name))
                .unwrap();
            file.write_all(b"abcdefgh").unwrap();
            file.sync_all().unwrap();
            file
        }

        fn sample(&self, name: &str, label: &str) -> Sample {
            sample(&self.parent, &self.root, name, label)
        }
    }

    // Python's standard mmap supplies the fixture only, not native observation.
    // An absolute interpreter, isolated mode, fixed script, one owned path arg,
    // fixed-size pipe messages and 15s command waits avoid shell/unsafe test FFI.
    const MMAP_SCRIPT: &str = r#"
import mmap, os, select, signal, sys
signal.alarm(20)

def command(expected):
    if not select.select([sys.stdin.buffer], [], [], 15)[0]:
        raise RuntimeError('owned mmap command timeout')
    if sys.stdin.buffer.readline(16) != expected:
        raise RuntimeError('unexpected owned mmap command')

with open(sys.argv[1], 'r+b', buffering=0) as f:
    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as m:
        sys.stdout.buffer.write(b'READY\n'); sys.stdout.buffer.flush()
        command(b'WRITE\n')
        m[0:8] = b'MAPPED!!'
        m.flush()
        os.fsync(f.fileno())
        sys.stdout.buffer.write(b'SYNCED\n'); sys.stdout.buffer.flush()
        command(b'CLOSE\n')
"#;

    struct Mapping {
        child: Child,
        input: ChildStdin,
        output: ChildStdout,
    }

    impl Mapping {
        fn new(path: &Path) -> Self {
            let mut child = Command::new("/usr/bin/python3")
                .args(["-I", "-c", MMAP_SCRIPT])
                .arg(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let input = child.stdin.take().unwrap();
            let output = child.stdout.take().unwrap();
            let mut mapping = Self {
                child,
                input,
                output,
            };
            let mut ready = [0; 6];
            mapping.output.read_exact(&mut ready).unwrap();
            assert_eq!(&ready, b"READY\n");
            mapping
        }

        fn write_and_sync(&mut self) {
            self.input.write_all(b"WRITE\n").unwrap();
            self.input.flush().unwrap();
            let mut synced = [0; 7];
            self.output.read_exact(&mut synced).unwrap();
            assert_eq!(&synced, b"SYNCED\n");
        }

        fn close(&mut self) {
            self.input.write_all(b"CLOSE\n").unwrap();
            self.input.flush().unwrap();
            assert!(self.child.wait().unwrap().success());
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // Only our own helper process; retain every fixture/evidence byte.
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    fn record_write(label: &str, before: &Sample, after: &Sample, blocked: &mut Vec<String>) {
        let observation = observe_write(before.token, after.token);
        eprintln!("A3b WRITE {label}: {observation:?}");
        if observation != WriteObservation::ChangedToken {
            blocked.push(format!("{label}: {observation:?}"));
        }
    }

    #[test]
    fn attributes_at_characterizes_owned_payload_generation_without_admission() {
        let f = Fixture::new();
        let mut blocked = Vec::new();

        drop(f.create("unchanged"));
        let initial = f.sample("unchanged", "initial");
        let unchanged = f.sample("unchanged", "unchanged");
        assert_eq!(initial.metadata, unchanged.metadata);
        eprintln!(
            "A3b CONTROL unchanged: {:?}",
            observe_write(initial.token, unchanged.token)
        );
        if initial.token.is_none() || unchanged.token.is_none() {
            blocked.push("initial/unchanged: mandatory token unavailable".into());
        }

        drop(f.create("open-only"));
        let before = f.sample("open-only", "open-only/pre");
        let opened = OpenOptions::new()
            .write(true)
            .open(f.root.join("open-only"))
            .unwrap();
        let after = f.sample("open-only", "open-only/open");
        drop(opened);
        let closed = f.sample("open-only", "open-only/closed");
        assert_eq!(before.metadata.size, after.metadata.size);
        eprintln!(
            "A3b CONTROL open-only: open={:?} closed={:?}",
            observe_write(before.token, after.token),
            observe_write(after.token, closed.token)
        );

        for (name, bytes) in [
            ("ordinary-write", b"ordinary longer write".as_slice()),
            ("same-length-write", b"ABCDEFGH"),
        ] {
            drop(f.create(name));
            let before = f.sample(name, &format!("{name}/pre"));
            let mut writer = OpenOptions::new()
                .write(true)
                .open(f.root.join(name))
                .unwrap();
            writer.write_all(bytes).unwrap();
            writer.sync_all().unwrap();
            let after = f.sample(name, &format!("{name}/post"));
            assert_eq!(after.metadata.size, bytes.len() as u64);
            record_write(name, &before, &after, &mut blocked);
        }

        let truncator = f.create("truncate");
        let before = f.sample("truncate", "truncate/pre");
        truncator.set_len(3).unwrap();
        truncator.sync_all().unwrap();
        let after = f.sample("truncate", "truncate/post");
        assert_eq!(after.metadata.size, 3);
        record_write("truncate", &before, &after, &mut blocked);

        let mut retained = f.create("retained-writable-fd");
        // Creation leaves the writable FD open BEFORE the pre-observation.
        // Rewind before observing, then same-length overwrite without reopening.
        retained.rewind().unwrap();
        let before = f.sample("retained-writable-fd", "retained-fd/pre");
        retained.write_all(b"RETAINED").unwrap();
        retained.sync_all().unwrap();
        let after = f.sample("retained-writable-fd", "retained-fd/post");
        assert_eq!(after.metadata.size, 8);
        record_write("retained-writable-fd", &before, &after, &mut blocked);

        drop(f.create("mmap"));
        let unmapped = f.sample("mmap", "mmap/before-map");
        let mut mapping = Mapping::new(&f.root.join("mmap"));
        let before = f.sample("mmap", "mmap/mapped-pre");
        mapping.write_and_sync();
        let after = f.sample("mmap", "mmap/mapped-synchronized-post");
        assert_eq!(before.metadata.size, after.metadata.size);
        record_write("mmap-live-synchronized", &before, &after, &mut blocked);
        mapping.close();
        let closed = f.sample("mmap", "mmap/unmapped-post");
        record_write(
            "mmap-before-map-to-unmapped",
            &unmapped,
            &closed,
            &mut blocked,
        );

        drop(f.create("chmod"));
        let before = f.sample("chmod", "chmod/pre");
        fs::set_permissions(f.root.join("chmod"), Permissions::from_mode(0o400)).unwrap();
        let after = f.sample("chmod", "chmod/post");
        assert_eq!(after.metadata.mode & 0o777, 0o400);
        assert_eq!(before.metadata.size, after.metadata.size);
        eprintln!(
            "A3b METADATA chmod: {:?}",
            observe_write(before.token, after.token)
        );

        let file = f.create("mtime");
        let before = f.sample("mtime", "mtime/pre");
        file.set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567)),
        )
        .unwrap();
        let after = f.sample("mtime", "mtime/post");
        assert_eq!(after.metadata.mtime, (1_234_567, 0));
        assert_eq!(before.metadata.size, after.metadata.size);
        eprintln!(
            "A3b METADATA mtime: {:?}",
            observe_write(before.token, after.token)
        );

        drop(f.create("hardlink"));
        let before = f.sample("hardlink", "hardlink/pre");
        fs::hard_link(f.root.join("hardlink"), f.root.join("owned-link")).unwrap();
        let linked = f.sample("hardlink", "hardlink/created");
        let alias = f.sample("owned-link", "hardlink/alias");
        assert_eq!(linked.metadata.ino, before.metadata.ino);
        assert_eq!(linked.metadata.nlink, before.metadata.nlink + 1);
        assert_eq!(alias.metadata, linked.metadata);
        // Remove only the exact link just created by this test, never user data.
        fs::remove_file(f.root.join("owned-link")).unwrap();
        let removed = f.sample("hardlink", "hardlink/removed");
        assert_eq!(removed.metadata.nlink, before.metadata.nlink);
        eprintln!("A3b LINK transitions: create={:?} remove={:?}; ctime before={:?} linked={:?} removed={:?}", observe_write(before.token, linked.token), observe_write(linked.token, removed.token), before.metadata.ctime, linked.metadata.ctime, removed.metadata.ctime);

        drop(f.create("rename"));
        let before = f.sample("rename", "rename/pre");
        fs::rename(f.root.join("rename"), f.root.join("renamed")).unwrap();
        let after = f.sample("renamed", "rename/post");
        assert_eq!(before.metadata.ino, after.metadata.ino);
        assert_eq!(before.metadata.size, after.metadata.size);
        eprintln!("A3b RENAME: {:?}", observe_write(before.token, after.token));

        // A successful characterization test means only that all experiments
        // completed and were recorded. It NEVER means admission/qualification.
        if blocked.is_empty() {
            eprintln!("A3b OBSERVED changes in tested writes only; NOT qualified or payload-read admission");
        } else {
            eprintln!(
                "A3b BLOCKED payload-read advancement: {}",
                blocked.join("; ")
            );
        }
    }
}
