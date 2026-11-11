//! Internal safe interface for bounded Darwin observations.
//!
//! Portable decoding and native observation APIs are implemented in reviewed
//! slices. This crate is not evidence that the core macOS workflow is qualified.

#![deny(unsafe_code)]

mod topology;
pub use topology::{decode_topology, DirectoryTopology, MountedVolume, TOPOLOGY_BUFFER_SIZE};

mod access;
pub use access::{
    decode_access, decode_filesec, decode_git_access, AccessError, AccessObservation, Ace, Acl,
    GitAccessDomain, GitAccessObservation, GitAcl, GrantExposure, Principal, ACCESS_BUFFER_SIZE,
    GIT_ACCESS_BUFFER_SIZE,
};

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

#[cfg(target_os = "macos")]
pub use access::{access_at, access_fd, git_access_at, git_access_fd, principal};

#[cfg(target_os = "macos")]
pub use topology::{
    directory_topology_at, directory_topology_fd, mounted_volume_fd, open_directory_at,
};
