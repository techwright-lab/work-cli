#![cfg(target_os = "macos")]
//! SDK27 ABI development checks, only new owned fixtures; never lifecycle proof.
use std::fs::{self, DirBuilder, File};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use work_darwin::{
    access_at, access_fd, principal, AccessError, GrantExposure, Principal, ACCESS_BUFFER_SIZE,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn fixture() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "work-darwin-access-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    DirBuilder::new().mode(0o700).create(&p).unwrap();
    p
}
fn grant(path: &Path, acl: &str) {
    // Test-only mutation of an exclusively created fixture via trusted utility.
    assert!(Command::new("/bin/chmod")
        .arg("+a")
        .arg(acl)
        .arg(path)
        .env_clear()
        .status()
        .unwrap()
        .success());
}
#[test]
fn native_access_harmless_dangerous_and_unavailable_acl_evidence() {
    let root = fixture();
    let held = File::open(&root).unwrap();
    let mut b = [0xff; ACCESS_BUFFER_SIZE];
    if let Err(error) = access_fd(held.as_fd(), &mut b) {
        eprintln!(
            "initial ACL unavailable (held fail closed): {error}; header={:02x?}",
            &b[..64]
        );
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let returned = u32::from_ne_bytes(b[4..8].try_into().unwrap());
        assert_eq!(
            returned & 0x0040_0000,
            0,
            "only missing mandatory ACL is an allowed hold in this control"
        );
    }
    grant(&root, "everyone allow readattr,readsecurity");
    // First call carries bounded diagnostic bytes only if it refuses.
    if let Err(error) = access_fd(held.as_fd(), &mut b) {
        panic!(
            "ACL-present observation failed: {error}; packet={:02x?}",
            &b[..128]
        );
    }
    let harmless = access_fd(held.as_fd(), &mut b).unwrap();
    assert_eq!(harmless.file_id, held.metadata().unwrap().ino());
    assert_eq!(harmless.owner, held.metadata().unwrap().uid());
    assert_eq!(harmless.effective_access & 7, 7);
    assert!(!harmless.acl.is_empty());
    for entry in harmless.acl.entries() {
        assert_eq!(
            entry.exposure(Principal::Unknown, harmless.owner),
            Ok(GrantExposure::default())
        );
    }
    grant(&root, "everyone allow delete,delete_child,write,append");
    let dangerous = access_fd(held.as_fd(), &mut b).unwrap();
    assert!(dangerous.acl.entries().any(|e| matches!(
        e.exposure(Principal::Unknown, dangerous.owner),
        Err(AccessError::UnknownPrincipal)
    )));
}
#[test]
fn native_access_current_user_uuid_and_effective_search_denial() {
    // chmod's user qualifier accepts a NAME, not a numeric UID. Resolve the
    // effective user through the existing trusted utility; mutate only our new
    // fixture. The production adapter never changes ACLs or account state.
    let user = Command::new("/usr/bin/id")
        .arg("-un")
        .env_clear()
        .output()
        .unwrap();
    assert!(user.status.success());
    assert!(
        user.stdout.len() <= 256,
        "unexpected account-name output size"
    );
    let user = std::str::from_utf8(&user.stdout)
        .unwrap()
        .strip_suffix('\n')
        .expect("id must emit one terminated account name");
    assert!(!user.is_empty() && !user.contains(['\n', '\r']));
    let own = fixture();
    let mut b = [0xff; ACCESS_BUFFER_SIZE];
    grant(&own, &format!("user:{user} allow write"));
    let f = File::open(&own).unwrap();
    let own_access = access_fd(f.as_fd(), &mut b).unwrap();
    for e in own_access.acl.entries() {
        let resolved = principal(&e.principal).unwrap();
        assert_eq!(resolved, Principal::User(own_access.owner));
        assert_eq!(
            e.exposure(resolved, own_access.owner),
            Ok(GrantExposure::default())
        );
    }
    // Ordinary mode bits alone would incorrectly claim effective execute access.
    grant(&own, "everyone deny execute");
    let denied = access_fd(f.as_fd(), &mut b).unwrap();
    assert_ne!(denied.mode & 0o100, 0);
    assert_eq!(denied.effective_access & 1, 0);
}
#[test]
fn native_access_inherited_harmless_acl_is_not_a_blanket_ban() {
    let inherited = fixture();
    let mut b = [0xff; ACCESS_BUFFER_SIZE];
    grant(
        &inherited,
        "everyone allow readattr,readsecurity,directory_inherit",
    );
    fs::create_dir(inherited.join("child")).unwrap();
    let child = File::open(inherited.join("child")).unwrap();
    let child_access = access_fd(child.as_fd(), &mut b).unwrap();
    assert!(child_access.acl.entries().any(|e| e.flags & 16 != 0));
    for e in child_access.acl.entries() {
        assert_eq!(
            e.exposure(Principal::Unknown, child_access.owner),
            Ok(GrantExposure::default())
        );
    }
}
#[test]
fn native_access_caller_budget_and_changed_identity_are_not_hidden() {
    let root = fixture();
    fs::create_dir(root.join("entry")).unwrap();
    grant(&root.join("entry"), "everyone allow readattr,readsecurity");
    let old = File::open(root.join("entry")).unwrap();
    for capacity in 0..ACCESS_BUFFER_SIZE {
        let mut insufficient = [0xff; ACCESS_BUFFER_SIZE];
        assert_eq!(
            access_fd(old.as_fd(), &mut insufficient[..capacity])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(insufficient.iter().all(|b| *b == 0xff));
    }
    let mut b = [0; ACCESS_BUFFER_SIZE];
    let id = access_fd(old.as_fd(), &mut b).unwrap().file_id;
    fs::rename(root.join("entry"), root.join("retained")).unwrap();
    fs::create_dir(root.join("entry")).unwrap();
    grant(&root.join("entry"), "everyone allow readattr,readsecurity");
    let new = File::open(root.join("entry")).unwrap();
    assert_ne!(access_fd(new.as_fd(), &mut b).unwrap().file_id, id);
    let parent = File::open(&root).unwrap();
    let at = access_at(parent.as_fd(), c"entry", &mut b).unwrap();
    assert_eq!(at.file_id, new.metadata().unwrap().ino());
    assert!(access_at(parent.as_fd(), c"../entry", &mut b).is_err());
    std::os::unix::fs::symlink("entry", root.join("link")).unwrap();
    if let Ok(link) = access_at(parent.as_fd(), c"link", &mut b) {
        assert_ne!(
            link.file_id,
            new.metadata().unwrap().ino(),
            "component ACL observation must not follow its final symlink"
        );
    }
    assert_eq!(
        access_at(parent.as_fd(), c"missing", &mut b)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(access_fd(old.as_fd(), &mut b).unwrap().file_id, id);
}
