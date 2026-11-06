//! Strict bounded boot-session framing. No fallback or lifecycle inference.

/// Canonical lower-case UUID bytes. Debug intentionally redacts host identity.
/// This is native observation only, not a durable/provider-tagged application ID.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BootSessionUuid([u8; 36]);

impl BootSessionUuid {
    pub fn as_bytes(&self) -> &[u8; 36] {
        &self.0
    }
}

impl std::fmt::Debug for BootSessionUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootSessionUuid([redacted])")
    }
}

#[derive(Debug)]
pub enum BootSessionError {
    InvalidFrame,
    InvalidUuid,
    NilUuid,
    Os(std::io::Error),
}

impl std::fmt::Display for BootSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Os(error) => write!(f, "Darwin boot-session observation: {error}"),
            _ => write!(f, "Darwin boot-session observation: {self:?}"),
        }
    }
}

impl std::error::Error for BootSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Os(error) => Some(error),
            _ => None,
        }
    }
}

/// Require exactly 36 ASCII UUID bytes and ONE final NUL, with standard hyphen
/// positions. Reject nil, bad hex, embedded NUL, trailing bytes and short frames.
/// Upper/lower-case native hex canonicalizes to lower case before comparison.
pub fn parse_boot_session_uuid(frame: &[u8]) -> Result<BootSessionUuid, BootSessionError> {
    if frame.len() != 37 || frame[36] != 0 {
        return Err(BootSessionError::InvalidFrame);
    }
    let mut canonical = [0; 36];
    let mut nonzero = false;
    for (at, &byte) in frame[..36].iter().enumerate() {
        if matches!(at, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return Err(BootSessionError::InvalidUuid);
            }
        } else {
            if !byte.is_ascii_hexdigit() {
                return Err(BootSessionError::InvalidUuid);
            }
            nonzero |= byte != b'0';
        }
        canonical[at] = byte.to_ascii_lowercase();
    }
    if !nonzero {
        return Err(BootSessionError::NilUuid);
    }
    Ok(BootSessionUuid(canonical))
}

/// One read-only kern.bootsessionuuid sysctl into a fixed initialized 37-byte
/// stack buffer. No size probe, retry, growth, UUID synthesis or fallback IDs.
/// Missing/malformed/changing mandatory evidence must hold the caller's work;
/// repeat comparison and provider-aware durable binding remain caller duties.
#[cfg(target_os = "macos")]
pub fn boot_session_uuid() -> Result<BootSessionUuid, BootSessionError> {
    let mut buffer = [0; 37];
    let length = crate::ffi::boot_session_uuid(&mut buffer).map_err(BootSessionError::Os)?;
    let frame = buffer.get(..length).ok_or(BootSessionError::InvalidFrame)?;
    parse_boot_session_uuid(frame)
}
