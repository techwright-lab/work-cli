//! Preflight and errors shared with the small native attribute boundary.

#[cfg(any(target_os = "macos", test))]
use std::ffi::CStr;

use crate::DecodeError;
#[cfg(any(target_os = "macos", test))]
use crate::{Component, ATTRIBUTE_BUFFER_SIZE};

#[derive(Debug)]
pub enum AttributeError {
    Decode(DecodeError),
    BufferTooSmall { required: usize, available: usize },
    Os(std::io::Error),
}

impl std::fmt::Display for AttributeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(f),
            Self::BufferTooSmall {
                required,
                available,
            } => {
                write!(
                    f,
                    "Darwin attribute buffer needs {required} bytes, got {available}"
                )
            }
            Self::Os(error) => write!(f, "Darwin anchored attributes: {error}"),
        }
    }
}

impl std::error::Error for AttributeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Os(error) => Some(error),
            Self::BufferTooSmall { .. } => None,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn prepare_buffer<'a>(name: &CStr, buffer: &'a mut [u8]) -> Result<&'a mut [u8], AttributeError> {
    Component::new(name.to_bytes()).map_err(AttributeError::Decode)?;
    let available = buffer.len();
    let buffer = buffer
        .get_mut(..ATTRIBUTE_BUFFER_SIZE)
        .ok_or(AttributeError::BufferTooSmall {
            required: ATTRIBUTE_BUFFER_SIZE,
            available,
        })?;
    buffer.fill(0);
    Ok(buffer)
}

/// Observe returned masks, file ID and nonzero data generation via one held parent.
///
/// Borrows (never closes or duplicates) parent for the call; name must be one
/// component. The final symlink is not followed. Uses exactly ATTRIBUTE_BUFFER_SIZE
/// caller bytes, initialized before one syscall, with no retries (including EINTR).
/// Does not open readable payload, validate parent routes, prove mount identity,
/// inspect ACLs, or establish a complete removal/capture observation.
#[cfg(target_os = "macos")]
pub fn attributes_at(
    parent: std::os::fd::BorrowedFd<'_>,
    name: &CStr,
    buffer: &mut [u8],
) -> Result<crate::Attributes, AttributeError> {
    let buffer = prepare_buffer(name, buffer)?;
    crate::ffi::attributes_at(parent, name, buffer).map_err(AttributeError::Os)?;
    crate::decode_attributes(buffer).map_err(AttributeError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchored_preflight_rejects_invalid_components() {
        for name in [c"", c".", c"..", c"a/b", c"/absolute"] {
            let mut buffer = [0xff; ATTRIBUTE_BUFFER_SIZE];
            assert!(matches!(
                prepare_buffer(name, &mut buffer),
                Err(AttributeError::Decode(DecodeError::InvalidName))
            ));
            assert_eq!(buffer, [0xff; ATTRIBUTE_BUFFER_SIZE]);
        }
        // CStr itself prevents interior NUL from reaching the syscall boundary.
        let invalid = [b'a', 0, b'b', 0];
        assert!(CStr::from_bytes_with_nul(&invalid).is_err());
    }

    #[test]
    fn anchored_preflight_refuses_every_insufficient_capacity_without_mutation() {
        for capacity in 0..ATTRIBUTE_BUFFER_SIZE {
            let mut buffer = [0xff; ATTRIBUTE_BUFFER_SIZE];
            assert!(matches!(prepare_buffer(c"name", &mut buffer[..capacity]),
                Err(AttributeError::BufferTooSmall { required: ATTRIBUTE_BUFFER_SIZE, available }) if available == capacity));
            assert_eq!(buffer, [0xff; ATTRIBUTE_BUFFER_SIZE]);
        }
    }

    #[test]
    fn anchored_preflight_initializes_only_the_fixed_caller_owned_window() {
        let mut buffer = [0xff; ATTRIBUTE_BUFFER_SIZE + 8];
        let prepared = prepare_buffer(c"name", &mut buffer).unwrap();
        assert_eq!(prepared.len(), ATTRIBUTE_BUFFER_SIZE);
        assert_eq!(prepared, [0; ATTRIBUTE_BUFFER_SIZE]);
        assert_eq!(buffer[ATTRIBUTE_BUFFER_SIZE..], [0xff; 8]);
    }

    #[test]
    fn anchored_preflight_preserves_non_utf8_components() {
        let name = c"\xff";
        let mut buffer = [0; ATTRIBUTE_BUFFER_SIZE];
        assert!(prepare_buffer(name, &mut buffer).is_ok());
    }
}
