//! Internal safe interface for bounded Darwin observations.
//!
//! Portable decoding and native observation APIs are implemented in reviewed
//! slices. This crate is not evidence that the core macOS workflow is qualified.

#![deny(unsafe_code)]

mod attributes;
#[cfg(target_os = "macos")]
pub use attributes::attributes_at;
pub use attributes::AttributeError;

// Operator-authorized ABI exception; all decoding and application code remain safe.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod ffi;

mod decode;
pub use decode::{
    decode_attributes, decode_bulk, decode_census, AttributeSet, Attributes, BulkEntry,
    CensusEntry, Component, DecodeError, ATTRIBUTE_BUFFER_SIZE,
};

#[cfg(target_os = "macos")]
mod census;
#[cfg(target_os = "macos")]
pub use census::DirectoryCursor;

mod boot;
#[cfg(target_os = "macos")]
pub use boot::boot_session_uuid;
pub use boot::{parse_boot_session_uuid, BootSessionError, BootSessionUuid};
