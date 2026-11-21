use crate::{
    canonical::{self, Value},
    envelope::{MAX_WIRE_LEN, PADDING_BLOCK_LEN},
    types::{AppendUpdate, Creation, CreationResult, Entry, Id32, Page},
    WireError, WireResult,
};

pub const MAX_METADATA_LEN: usize = 128 * 1024;
pub const MAX_PERSISTED_COUNTER: u64 = i64::MAX as u64;
pub const DEFAULT_LIMIT: u64 = 100;
pub const MAX_LIMIT: u64 = 100;

pub(crate) fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}
pub(crate) fn bytes(id: &Id32) -> Value {
    Value::Bytes(id.to_vec())
}
pub(crate) fn array(value: &Value, count: usize) -> WireResult<&[Value]> {
    match value {
        Value::Array(fields) if fields.len() == count => Ok(fields),
        _ => Err(WireError::Schema),
    }
}
pub(crate) fn number(value: &Value) -> WireResult<u64> {
    match value {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| WireError::Schema),
        _ => Err(WireError::Schema),
    }
}
pub(crate) fn id32(value: &Value) -> WireResult<Id32> {
    match value {
        Value::Bytes(data) => data.as_slice().try_into().map_err(|_| WireError::Schema),
        _ => Err(WireError::Schema),
    }
}
pub(crate) fn version(value: &Value) -> WireResult<()> {
    if number(value)? != 1 {
        return Err(WireError::Version);
    }
    Ok(())
}
fn bounded_counter(n: u64) -> WireResult<u64> {
    if n > MAX_PERSISTED_COUNTER {
        return Err(WireError::Bounds);
    }
    Ok(n)
}
pub(crate) fn counter(value: &Value) -> WireResult<u64> {
    bounded_counter(number(value)?)
}
pub(crate) fn positive_counter(n: u64) -> WireResult<u64> {
    bounded_counter(n)?;
    if n == 0 {
        return Err(WireError::Schema);
    }
    Ok(n)
}
pub(crate) fn wire_length(n: u64) -> WireResult<()> {
    if !(PADDING_BLOCK_LEN as u64..=MAX_WIRE_LEN as u64).contains(&n)
        || n % PADDING_BLOCK_LEN as u64 != 0
    {
        return Err(WireError::Bounds);
    }
    Ok(())
}
fn encode_metadata(fields: Vec<Value>) -> WireResult<Vec<u8>> {
    let encoded = canonical::encode(&Value::Array(fields))?;
    if encoded.len() > MAX_METADATA_LEN {
        return Err(WireError::Bounds);
    }
    Ok(encoded)
}
fn decode_metadata(encoded: &[u8]) -> WireResult<Value> {
    canonical::decode(encoded, MAX_METADATA_LEN)
}
pub fn validate_limit(limit: Option<u64>) -> WireResult<u64> {
    let n = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&n) {
        return Err(WireError::Bounds);
    }
    Ok(n)
}

pub fn encode_creation(creation: &Creation) -> WireResult<Vec<u8>> {
    bounded_counter(creation.quota)?;
    encode_metadata(vec![
        uint(1),
        bytes(&creation.read_verifier),
        bytes(&creation.append_verifier),
        bytes(&creation.admin_verifier),
        uint(creation.quota),
    ])
}
pub fn decode_creation(encoded: &[u8]) -> WireResult<Creation> {
    let value = decode_metadata(encoded)?;
    let f = array(&value, 5)?;
    version(&f[0])?;
    Ok(Creation {
        read_verifier: id32(&f[1])?,
        append_verifier: id32(&f[2])?,
        admin_verifier: id32(&f[3])?,
        quota: counter(&f[4])?,
    })
}
pub fn encode_append_update(update: &AppendUpdate) -> WireResult<Vec<u8>> {
    positive_counter(update.revision)?;
    encode_metadata(vec![
        uint(1),
        uint(update.revision),
        bytes(&update.verifier),
    ])
}
pub fn decode_append_update(encoded: &[u8]) -> WireResult<AppendUpdate> {
    let value = decode_metadata(encoded)?;
    let f = array(&value, 3)?;
    version(&f[0])?;
    Ok(AppendUpdate {
        revision: positive_counter(number(&f[1])?)?,
        verifier: id32(&f[2])?,
    })
}
pub fn encode_creation_result(mailbox: &Id32, result: &CreationResult) -> WireResult<Vec<u8>> {
    bounded_counter(result.quota)?;
    positive_counter(result.append_revision)?;
    encode_metadata(vec![
        uint(1),
        bytes(mailbox),
        bytes(&result.run),
        uint(result.quota),
        uint(result.append_revision),
    ])
}
pub fn decode_creation_result(encoded: &[u8], created: bool) -> WireResult<(Id32, CreationResult)> {
    let value = decode_metadata(encoded)?;
    let f = array(&value, 5)?;
    version(&f[0])?;
    // The HTTP status supplies creation versus retry; the CBOR array has no boolean.
    Ok((
        id32(&f[1])?,
        CreationResult {
            created,
            run: id32(&f[2])?,
            quota: counter(&f[3])?,
            append_revision: positive_counter(number(&f[4])?)?,
        },
    ))
}
pub fn encode_append_result(mailbox: &Id32, revision: u64) -> WireResult<Vec<u8>> {
    positive_counter(revision)?;
    encode_metadata(vec![uint(1), bytes(mailbox), uint(revision)])
}
pub fn decode_append_result(encoded: &[u8]) -> WireResult<(Id32, u64)> {
    let value = decode_metadata(encoded)?;
    let f = array(&value, 3)?;
    version(&f[0])?;
    Ok((id32(&f[1])?, positive_counter(number(&f[2])?)?))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorCode {
    MalformedRequest = 1,
    InvalidCapability = 2,
    ObjectNotFound = 3,
    Conflict = 4,
    CursorAhead = 5,
    ObjectTooLarge = 6,
    UnsupportedMediaType = 7,
    AdmissionLimit = 8,
    StorageUnavailable = 9,
    QuotaExhausted = 10,
}
impl TryFrom<u64> for ErrorCode {
    type Error = WireError;
    fn try_from(code: u64) -> WireResult<Self> {
        Ok(match code {
            1 => Self::MalformedRequest,
            2 => Self::InvalidCapability,
            3 => Self::ObjectNotFound,
            4 => Self::Conflict,
            5 => Self::CursorAhead,
            6 => Self::ObjectTooLarge,
            7 => Self::UnsupportedMediaType,
            8 => Self::AdmissionLimit,
            9 => Self::StorageUnavailable,
            10 => Self::QuotaExhausted,
            _ => return Err(WireError::Schema),
        })
    }
}
impl ErrorCode {
    pub const fn status(self) -> u16 {
        match self {
            Self::MalformedRequest => 400,
            Self::InvalidCapability => 401,
            Self::ObjectNotFound => 404,
            Self::Conflict | Self::CursorAhead => 409,
            Self::ObjectTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::AdmissionLimit => 429,
            Self::StorageUnavailable => 503,
            Self::QuotaExhausted => 507,
        }
    }
}
pub fn encode_error(error: ErrorCode) -> WireResult<Vec<u8>> {
    encode_metadata(vec![uint(1), uint(error as u64)])
}
pub fn decode_error(encoded: &[u8]) -> WireResult<ErrorCode> {
    let value = decode_metadata(encoded)?;
    let f = array(&value, 2)?;
    version(&f[0])?;
    ErrorCode::try_from(number(&f[1])?)
}

fn validate_page_structure(page: &Page) -> WireResult<()> {
    bounded_counter(page.after)?;
    bounded_counter(page.next)?;
    bounded_counter(page.high_water)?;
    if page.entries.len() > MAX_LIMIT as usize {
        return Err(WireError::Bounds);
    }
    if page.after > page.high_water {
        return Err(WireError::Schema);
    }
    let mut previous = page.after;
    for entry in &page.entries {
        positive_counter(entry.sequence)?;
        bounded_counter(entry.wire_length)?;
        if previous.checked_add(1) != Some(entry.sequence) || entry.sequence > page.high_water {
            return Err(WireError::Schema);
        }
        previous = entry.sequence;
    }
    if page.next != previous {
        return Err(WireError::Schema);
    }
    Ok(())
}
pub fn encode_page(page: &Page) -> WireResult<Vec<u8>> {
    validate_page_structure(page)?;
    for entry in &page.entries {
        wire_length(entry.wire_length)?;
    }
    encode_metadata(vec![
        uint(1),
        bytes(&page.mailbox),
        uint(page.after),
        uint(page.next),
        uint(page.high_water),
        Value::Array(
            page.entries
                .iter()
                .map(|entry| {
                    Value::Array(vec![
                        uint(entry.sequence),
                        bytes(&entry.hash),
                        uint(entry.wire_length),
                        Value::Bytes(entry.receipt.clone()),
                    ])
                })
                .collect(),
        ),
    ])
}
pub fn decode_page(encoded: &[u8]) -> WireResult<Page> {
    let value = decode_metadata(encoded)?;
    let f = array(&value, 6)?;
    version(&f[0])?;
    let entries = match &f[5] {
        Value::Array(entries) if entries.len() <= MAX_LIMIT as usize => entries,
        Value::Array(_) => return Err(WireError::Bounds),
        _ => return Err(WireError::Schema),
    };
    let entries = entries
        .iter()
        .map(|entry| {
            let e = array(entry, 4)?;
            let receipt = match &e[3] {
                Value::Bytes(data) => data.clone(),
                _ => return Err(WireError::Schema),
            };
            Ok(Entry {
                sequence: counter(&e[0])?,
                hash: id32(&e[1])?,
                wire_length: number(&e[2])?,
                receipt,
            })
        })
        .collect::<WireResult<Vec<_>>>()?;
    let page = Page {
        mailbox: id32(&f[1])?,
        after: counter(&f[2])?,
        next: counter(&f[3])?,
        high_water: counter(&f[4])?,
        entries,
    };
    validate_page_structure(&page)?;
    Ok(page)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceAction {
    ReserveSetup = 0,
    RetireSetup = 1,
    ReservePayment = 2,
    PromotePayment = 3,
    RetirePayment = 4,
}

pub fn encode_setup_control(creation: &[u8], expires: u64, retire: bool) -> WireResult<Vec<u8>> {
    let action = if retire {
        NamespaceAction::RetireSetup
    } else {
        NamespaceAction::ReserveSetup
    };
    encode_namespace_control(creation, expires, action)
}
pub fn encode_namespace_control(
    creation: &[u8],
    expires: u64,
    action: NamespaceAction,
) -> WireResult<Vec<u8>> {
    decode_creation(creation)?;
    positive_counter(expires)?;
    encode_metadata(vec![
        uint(1),
        Value::Bytes(creation.to_vec()),
        uint(expires),
        uint(action as u64),
    ])
}
pub fn decode_setup_control(encoded: &[u8]) -> WireResult<(Vec<u8>, u64, bool)> {
    let (creation, expires, action) = decode_namespace_control(encoded)?;
    match action {
        NamespaceAction::ReserveSetup => Ok((creation, expires, false)),
        NamespaceAction::RetireSetup => Ok((creation, expires, true)),
        _ => Err(WireError::Schema),
    }
}
pub fn decode_namespace_control(encoded: &[u8]) -> WireResult<(Vec<u8>, u64, NamespaceAction)> {
    let value = decode_metadata(encoded)?;
    let f = array(&value, 4)?;
    version(&f[0])?;
    let Value::Bytes(creation) = &f[1] else {
        return Err(WireError::Schema);
    };
    decode_creation(creation)?;
    let expires = positive_counter(number(&f[2])?)?;
    let action = match number(&f[3])? {
        0 => NamespaceAction::ReserveSetup,
        1 => NamespaceAction::RetireSetup,
        2 => NamespaceAction::ReservePayment,
        3 => NamespaceAction::PromotePayment,
        4 => NamespaceAction::RetirePayment,
        _ => return Err(WireError::Schema),
    };
    Ok((creation.clone(), expires, action))
}
