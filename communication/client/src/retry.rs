use crate::{ClientError, ClientResult};

const FLOOR_MS: u64 = 250;
const CEILING_MS: u64 = 30_000;

pub(crate) fn now_ms() -> ClientResult<u64> {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ClientError::Storage)?
        .as_millis();
    u64::try_from(ms).map_err(|_| ClientError::Capacity)
}

fn ceiling(attempts: u64) -> ClientResult<u64> {
    let shift = u32::try_from(attempts.min(7)).map_err(|_| ClientError::Capacity)?;
    let scaled = FLOOR_MS.checked_shl(shift).ok_or(ClientError::Capacity)?;
    Ok(scaled.min(CEILING_MS))
}

/// Rejects a draw outside the inclusive delay for this attempt count.
pub(crate) fn delay_from_draw(attempts: u64, draw: u64) -> ClientResult<u64> {
    let ceiling = ceiling(attempts)?;
    if (FLOOR_MS..=ceiling).contains(&draw) {
        Ok(draw)
    } else {
        Err(ClientError::Config)
    }
}

/// One unbiased OS draw on `250..=min(30000, 250 * 2^min(attempts, 7))`.
pub(crate) fn sample_delay(attempts: u64) -> ClientResult<u64> {
    let ceiling = ceiling(attempts)?;
    let width = ceiling - FLOOR_MS + 1;
    let limit = u64::MAX - (u64::MAX % width);
    for _ in 0..16 {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| ClientError::Crypto)?;
        let sample = u64::from_le_bytes(bytes);
        if sample < limit {
            return delay_from_draw(attempts, FLOOR_MS + (sample % width));
        }
    }
    Err(ClientError::Crypto)
}
