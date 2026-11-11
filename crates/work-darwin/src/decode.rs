//! Safe decoding of the fixed minimal Darwin attribute schemas.
//!
//! These schemas do not use FSOPT_PACK_INVAL_ATTRS: absent fields take no space.
//! Values use native byte order and four-byte field alignment, even for u64.

pub(crate) const RETURNED: u32 = 0x8000_0000;
pub(crate) const NAME: u32 = 1;
// ATTR_CMN_ERROR is documented by Darwin but absent from pinned libc's constants.
pub(crate) const ERROR: u32 = 0x2000_0000;
pub(crate) const GENERATION: u32 = 0x0008_0000;
pub(crate) const FILE_ID: u32 = 0x0200_0000;
pub(crate) const IDENTITY: u32 = RETURNED | GENERATION | FILE_ID;
pub(crate) const BULK: u32 = IDENTITY | NAME | ERROR;
// Enumeration is not payload-generation evidence. Keep the A1 schema unchanged.
pub(crate) const CENSUS: u32 = RETURNED | NAME | ERROR | FILE_ID;

/// Space for length, returned attribute_set_t, generation and file ID.
pub const ATTRIBUTE_BUFFER_SIZE: usize = 36;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    EntryBudget,
    Truncated,
    InvalidLength,
    Misaligned,
    MissingAttributes,
    UnexpectedAttributes,
    EntryError(u32),
    InvalidReference,
    InvalidName,
    UnavailableIdentity,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Darwin attribute decoding: {self:?}")
    }
}

impl std::error::Error for DecodeError {}

/// A borrowed single path component, preserved as bytes (not lossy text).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Component<'a>(&'a [u8]);

impl<'a> Component<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty()
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&0)
            || bytes.contains(&b'/')
        {
            return Err(DecodeError::InvalidName);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributeSet {
    pub common: u32,
    pub volume: u32,
    pub directory: u32,
    pub file: u32,
    pub fork: u32,
}

/// Minimal observations only: not a complete identity, route or access proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attributes {
    pub returned: AttributeSet,
    pub file_id: u64,
    /// Nonzero data generation; not an inode-reuse or topology guarantee.
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BulkEntry<'a> {
    pub name: Component<'a>,
    pub attributes: Attributes,
}

/// Decode one returned-mask/generation/file-ID group, ignoring unused storage.
/// Missing mandatory fields and zero identities are errors, not default evidence.
pub fn decode_attributes(buffer: &[u8]) -> Result<Attributes, DecodeError> {
    let record = group(buffer, 4)?;
    let mut reader = Reader {
        bytes: record,
        at: 4,
    };
    let returned = reader.attribute_set(IDENTITY)?;
    require(returned.common, IDENTITY)?;
    let attributes = reader.identity(returned)?;
    if reader.at != record.len() {
        return Err(DecodeError::InvalidLength);
    }
    Ok(attributes)
}

/// Decode exactly the syscall's returned count, never the stale buffer tail.
///
/// The caller supplies both byte storage and entry capacity. No allocation,
/// refill, retry or resizing occurs. All output slots are cleared on error;
/// on success only the first returned_count slots contain accepted entries.
/// Names borrow buffer, so it cannot be reused while these entries are held.
/// This parses the minimal BULK schema only, without PACK_INVAL_ATTRS.
pub fn decode_bulk<'a>(
    buffer: &'a [u8],
    returned_count: usize,
    output: &mut [Option<BulkEntry<'a>>],
) -> Result<usize, DecodeError> {
    output.fill(None);
    if returned_count > output.len() {
        return Err(DecodeError::EntryBudget);
    }
    let result = (|| {
        let mut remaining = buffer;
        for slot in &mut output[..returned_count] {
            let record = group(remaining, 8)?;
            *slot = Some(bulk_entry(record)?);
            remaining = &remaining[record.len()..];
        }
        Ok(returned_count)
    })();
    if result.is_err() {
        output.fill(None);
    }
    result
}

/// A name/file-ID observation, NOT proof of payload generation or safe access.
/// Deliberately distinct from BulkEntry: census cannot satisfy mandatory
/// generation checks before an accepted payload read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CensusEntry<'a> {
    pub name: Component<'a>,
    pub returned: AttributeSet,
    pub file_id: u64,
}

/// Decode exactly one native census batch (NAME, FILEID, RETURNED_ATTRS, ERROR).
/// Generation is neither requested nor fabricated. As with decode_bulk, all
/// slots clear on error; count zero alone is EOF, and stale bytes are ignored.
/// Missing identities, per-entry errors and budget exhaustion are NOT clean EOF.
pub fn decode_census<'a>(
    buffer: &'a [u8],
    returned_count: usize,
    output: &mut [Option<CensusEntry<'a>>],
) -> Result<usize, DecodeError> {
    output.fill(None);
    if returned_count > output.len() {
        return Err(DecodeError::EntryBudget);
    }
    let result = (|| {
        let mut remaining = buffer;
        for slot in &mut output[..returned_count] {
            let record = group(remaining, 8)?;
            let mut reader = Reader {
                bytes: record,
                at: 4,
            };
            let returned = reader.attribute_set(CENSUS)?;
            if returned.common & ERROR != 0 {
                let errno = reader.u32()?;
                if errno != 0 {
                    return Err(DecodeError::EntryError(errno));
                }
            }
            require(returned.common, RETURNED | NAME | FILE_ID)?;
            let reference = reader.name_reference()?;
            let file_id = u64::from_ne_bytes(reader.array()?);
            if file_id == 0 {
                return Err(DecodeError::UnavailableIdentity);
            }
            *slot = Some(CensusEntry {
                name: reference.decode(record, reader.at)?,
                returned,
                file_id,
            });
            remaining = &remaining[record.len()..];
        }
        Ok(returned_count)
    })();
    if result.is_err() {
        output.fill(None);
    }
    result
}

fn group(buffer: &[u8], alignment: usize) -> Result<&[u8], DecodeError> {
    let mut reader = Reader {
        bytes: buffer,
        at: 0,
    };
    let length = usize::try_from(reader.u32()?).map_err(|_| DecodeError::InvalidLength)?;
    if length < 24 {
        return Err(DecodeError::InvalidLength);
    }
    if length % alignment != 0 {
        return Err(DecodeError::Misaligned);
    }
    buffer.get(..length).ok_or(DecodeError::Truncated)
}

fn bulk_entry(record: &[u8]) -> Result<BulkEntry<'_>, DecodeError> {
    let mut reader = Reader {
        bytes: record,
        at: 4,
    };
    let returned = reader.attribute_set(BULK)?;
    if returned.common & ERROR != 0 {
        let errno = reader.u32()?;
        if errno != 0 {
            return Err(DecodeError::EntryError(errno));
        }
    }
    require(returned.common, IDENTITY | NAME)?;
    let reference = reader.name_reference()?;
    let attributes = reader.identity(returned)?;
    Ok(BulkEntry {
        name: reference.decode(record, reader.at)?,
        attributes,
    })
}

struct NameReference {
    at: usize,
    offset: i32,
    length: usize,
}

impl NameReference {
    fn decode(self, record: &[u8], fixed_end: usize) -> Result<Component<'_>, DecodeError> {
        if self.offset % 4 != 0 {
            return Err(DecodeError::Misaligned);
        }
        let offset = isize::try_from(self.offset).map_err(|_| DecodeError::InvalidReference)?;
        let start = self
            .at
            .checked_add_signed(offset)
            .ok_or(DecodeError::InvalidReference)?;
        let end = start
            .checked_add(self.length)
            .ok_or(DecodeError::InvalidReference)?;
        // No alias of fixed fields, another record, or stale batch storage.
        if start < fixed_end || self.length == 0 {
            return Err(DecodeError::InvalidReference);
        }
        let name = record
            .get(start..end)
            .ok_or(DecodeError::InvalidReference)?;
        let name = name.strip_suffix(&[0]).ok_or(DecodeError::InvalidName)?;
        Component::new(name)
    }
}

fn require(actual: u32, required: u32) -> Result<(), DecodeError> {
    if actual & required != required {
        return Err(DecodeError::MissingAttributes);
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let end = self.at.checked_add(N).ok_or(DecodeError::Truncated)?;
        let array = self
            .bytes
            .get(self.at..end)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        self.at = end;
        Ok(array)
    }

    fn name_reference(&mut self) -> Result<NameReference, DecodeError> {
        Ok(NameReference {
            at: self.at,
            offset: i32::from_ne_bytes(self.array()?),
            length: usize::try_from(self.u32()?).map_err(|_| DecodeError::InvalidReference)?,
        })
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_ne_bytes(self.array()?))
    }

    fn attribute_set(&mut self, allowed: u32) -> Result<AttributeSet, DecodeError> {
        let returned = AttributeSet {
            common: self.u32()?,
            volume: self.u32()?,
            directory: self.u32()?,
            file: self.u32()?,
            fork: self.u32()?,
        };
        require(returned.common, RETURNED)?;
        if returned.common & !allowed != 0
            || returned.volume != 0
            || returned.directory != 0
            || returned.file != 0
            || returned.fork != 0
        {
            return Err(DecodeError::UnexpectedAttributes);
        }
        Ok(returned)
    }

    fn identity(&mut self, returned: AttributeSet) -> Result<Attributes, DecodeError> {
        let generation = self.u32()?;
        let file_id = u64::from_ne_bytes(self.array()?);
        if generation == 0 || file_id == 0 {
            return Err(DecodeError::UnavailableIdentity);
        }
        Ok(Attributes {
            returned,
            file_id,
            generation,
        })
    }
}
