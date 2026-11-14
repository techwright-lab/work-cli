//! Compile-time selection contract only; this does not test SQLite runtime behavior.
#![cfg(target_os = "macos")]

#[test]
fn rusqlite_ffi_requires_verified_darwin_bundled_build() {
    let _: () = rusqlite::ffi::WORK_DARWIN_REQUIRED_ACK_V1;
}
