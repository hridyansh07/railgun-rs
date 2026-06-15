//! The windowed block pump shared by the commitment syncer and the POI txid
//! indexer: walk `[resume_from, target]` in `block_window`-sized inclusive
//! chunks, handing each `[from, end]` window to the caller to fetch and
//! commit. One window = one durability checkpoint, so a crash re-fetches at
//! most one window.

use types::BlockNumber;

/// Drives `window(from, end)` over every `block_window`-sized inclusive chunk
/// of `[resume_from, target]`, in order. The closure owns fetching and
/// committing one window (and any summary bookkeeping); an error stops the
/// pump at the last committed window.
///
/// # Errors
/// Propagates the first error `window` returns.
pub async fn pump_windows<E>(
    resume_from: BlockNumber,
    target: BlockNumber,
    block_window: u64,
    mut window: impl AsyncFnMut(BlockNumber, BlockNumber) -> Result<(), E>,
) -> Result<(), E> {
    let mut from = resume_from;
    while from <= target {
        let end = from.saturating_add(block_window - 1).min(target);
        window(from, end).await?;
        from = end.saturating_add(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn windows_cover_the_range_inclusively_without_overlap() {
        let mut seen = Vec::new();
        pump_windows(
            BlockNumber::new(10),
            BlockNumber::new(35),
            10,
            async |from, end| {
                seen.push((from.get(), end.get()));
                Ok::<_, ()>(())
            },
        )
        .await
        .unwrap();
        assert_eq!(seen, vec![(10, 19), (20, 29), (30, 35)]);
    }

    #[tokio::test]
    async fn empty_range_runs_no_windows() {
        let mut calls = 0;
        pump_windows(
            BlockNumber::new(5),
            BlockNumber::new(4),
            10,
            async |_, _| {
                calls += 1;
                Ok::<_, ()>(())
            },
        )
        .await
        .unwrap();
        assert_eq!(calls, 0);
    }
}
