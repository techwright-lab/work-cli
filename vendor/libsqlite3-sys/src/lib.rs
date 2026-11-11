#![expect(non_snake_case, non_camel_case_types)]
#![cfg_attr(not(test), no_std)]

#[cfg(all(
    target_os = "macos",
    any(
        not(feature = "bundled"),
        feature = "sqlcipher",
        feature = "bundled-sqlcipher",
        feature = "in_gecko",
        feature = "loadable_extension"
    )
))]
compile_error!(
    "Work requires exact patched bundled SQLite; system/alternate SQLite is not permitted"
);

// Generated only after target source verification and successful bundled C compilation.
// Retained OUT_DIR output is historical, not proof of a fresh build-script run.
#[cfg(target_os = "macos")]
include!(concat!(env!("OUT_DIR"), "/work_darwin_verified.rs"));

// force linking to openssl
#[cfg(feature = "bundled-sqlcipher-vendored-openssl")]
extern crate openssl_sys;

pub use self::error::*;

use core::mem;

mod error;

#[must_use]
pub fn SQLITE_STATIC() -> sqlite3_destructor_type {
    None
}

#[must_use]
pub fn SQLITE_TRANSIENT() -> sqlite3_destructor_type {
    Some(unsafe { mem::transmute::<isize, unsafe extern "C" fn(*mut core::ffi::c_void)>(-1_isize) })
}

#[allow(dead_code, clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindgen.rs"));
}
pub use bindings::*;

impl Default for sqlite3_vtab {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

impl Default for sqlite3_vtab_cursor {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}
