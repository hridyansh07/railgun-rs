//! [`Scanner`] — the incremental, multi-wallet, multi-threaded decode pass.
//!
//! One scan walks every leaf the wallets haven't attempted yet and tries each
//! active wallet's decryptor per leaf: leaf I/O is shared, the per-wallet cost
//! is one cheap decrypt attempt. Progress is a per-(wallet, tree) watermark —
//! in an append-only tree "attempted" is a contiguous prefix, so the watermark
//! *is* the skip-set. Backfills (nodes landing below a tree's length) are the
//! one exception; sync queues those positions and the scan drains the queue.
//!
//! Work is split into leaf-range chunks on a shared queue drained by worker
//! threads, each holding its own MVCC read view — parallel even when all new
//! leaves sit in one hot head tree. Trees are swept in *segments* between
//! distinct watermarks so a backfilling (newly added) wallet shares every
//! leaf read with the caught-up wallets where their ranges overlap.
//!
//! Found notes persist **sealed only** ([`crypto::Sealer`]): the database
//! holds ciphertext, never plaintext notes. The memory-only variant
//! ([`Scanner::scan_in_memory`]) persists nothing and leaves cursor-keeping
//! to the caller — the locked/degraded mode.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

use crypto::{
    CryptoError, DerivedRailgunKeys, NodeDecrypt, NoteDecryptor, Sealer, ViewingKeyPublicKey,
};
use database::{Commitments, Database, Decoded, Reader};
use sha2::{Digest, Sha256};
use types::DecryptedNote;

use crate::DecodeError;
use crate::decode::per_second;

/// A stable, non-secret wallet identifier: SHA-256 of the viewing public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WalletId([u8; 32]);

impl WalletId {
    /// Derives the id from an account's keys (touches only the *public*
    /// viewing key).
    #[must_use]
    pub fn from_keys(keys: &DerivedRailgunKeys) -> Self {
        WalletId(Sha256::digest(keys.viewing_key.public_key().as_bytes()).into())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One active wallet in a scan: its id and in-memory decryptor (keys never
/// touch storage).
pub struct ScanWallet {
    pub id: WalletId,
    decryptor: NoteDecryptor,
}

impl ScanWallet {
    #[must_use]
    pub fn from_keys(keys: &DerivedRailgunKeys) -> Self {
        ScanWallet {
            id: WalletId::from_keys(keys),
            decryptor: NoteDecryptor::from_keys(keys),
        }
    }
}

/// In-memory scan cursors for the locked (nothing-persisted) mode:
/// `(wallet, tree) -> scanned length`.
pub type ScanCursors = HashMap<(WalletId, u32), u32>;

/// What a memory-only pass hands back: per-wallet notes found this pass, the
/// advanced cursors, and the summary.
pub type MemoryScan = (
    Vec<(WalletId, Vec<DecryptedNote>)>,
    ScanCursors,
    ScanSummary,
);

/// Outcome of one scan pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanSummary {
    /// Stored leaves visited (each read once per segment it belongs to).
    pub leaves_scanned: u64,
    /// Decrypt attempts across all wallets.
    pub attempts: u64,
    /// Notes recovered across all wallets this pass.
    pub notes_found: u64,
    /// Backfilled positions drained from the rescan queue.
    pub rescans: u64,
}

/// One unit of worker work: scan `tree` positions `first..=last`, trying the
/// wallets at `wallet_indices`.
struct Chunk {
    tree: u32,
    first: u32,
    last: u32,
    // alloc-ok: a few indices per chunk, built once at planning time.
    wallet_indices: Vec<usize>,
}

/// The incremental multi-wallet decode pass. Construct once per set of active
/// wallets; each [`scan`](Self::scan) call decodes everything new since the
/// previous one.
pub struct Scanner {
    wallets: Vec<ScanWallet>,
    threads: usize,
    chunk_size: u32,
}

impl Scanner {
    /// A scanner over `wallets`, defaulting to one worker per available core
    /// and 4096-leaf chunks.
    #[must_use]
    pub fn new(wallets: Vec<ScanWallet>) -> Self {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        Scanner {
            wallets,
            threads,
            chunk_size: 4096,
        }
    }

    /// Overrides the worker thread count.
    ///
    /// # Panics
    /// Panics if `threads` is zero.
    pub fn set_threads(&mut self, threads: usize) {
        assert!(threads > 0, "threads must be non-zero");
        self.threads = threads;
    }

    /// Adds a wallet to subsequent scans (it backfills from leaf 0 via its
    /// own watermark, then converges with the rest).
    pub fn add_wallet(&mut self, wallet: ScanWallet) {
        self.wallets.push(wallet);
    }

    /// The ids of every wallet this scanner decodes for.
    pub fn wallet_ids(&self) -> impl Iterator<Item = WalletId> {
        self.wallets.iter().map(|wallet| wallet.id)
    }

    /// Scans everything new since the persisted watermarks and persists the
    /// results: per-wallet **sealed** note records, advanced watermarks, and
    /// the drained rescan queue — one write transaction.
    ///
    /// # Errors
    /// Propagates [`DecodeError`].
    pub fn scan(&self, db: &Database, sealer: &dyn Sealer) -> Result<ScanSummary, DecodeError> {
        let view = db.read()?;

        // Existing notes come out of their sealed records first, so the merge
        // below can dedup against them.
        // alloc-ok: per-wallet note sets, bounded by the wallets' note counts.
        let mut notes_by_wallet: Vec<Vec<DecryptedNote>> = Vec::with_capacity(self.wallets.len()); // We can make this a ListOfLists type with wallet id based search built into it? 
        for wallet in &self.wallets {
            let decoded = Decoded::new(&view);
            let notes = match decoded.sealed_notes(wallet.id.as_bytes())? {
                Some(ciphertext) => {
                    let plain = sealer.unseal(&ciphertext).map_err(DecodeError::Seal)?;
                    serde_json::from_slice(&plain)
                        .map_err(|error| database::DatabaseError::Serde(error.to_string()))?
                }
                None => Vec::new(),
            };
            notes_by_wallet.push(notes);
        }

        let watermarks = |wallet: usize, tree: u32| {
            Decoded::new(&view).watermark(self.wallets[wallet].id.as_bytes(), tree)
        };
        let (found, lengths, rescanned, summary) = self.run(db, &view, &watermarks)?;

        // Merge: dedup against existing notes by (tree, position), keep
        // position order (stable records, idempotent rescans).
        for (wallet, new_notes) in found.into_iter().enumerate() {
            let existing = &mut notes_by_wallet[wallet];
            for note in new_notes {
                if !existing.iter().any(|n| n.position == note.position) {
                    existing.push(note);
                }
            }
            existing.sort_by_key(|note| (note.position.tree_number(), note.position.leaf_index()));
        }

        db.write(|txn| {
            for (wallet, notes) in self.wallets.iter().zip(&notes_by_wallet) {
                let plain = serde_json::to_vec(notes)
                    .map_err(|error| database::DatabaseError::Serde(error.to_string()))?;
                let ciphertext = sealer.seal(&plain).map_err(DecodeError::Seal)?;
                let mut decoded = txn.decoded();
                decoded.save_sealed_notes(wallet.id.as_bytes(), &ciphertext)?;
                for (tree, length) in lengths.iter().enumerate() {
                    #[allow(clippy::cast_possible_truncation)]
                    decoded.set_watermark(wallet.id.as_bytes(), tree as u32, *length)?;
                }
            }
            for &(tree, position) in &rescanned {
                txn.commitments().clear_rescan(tree, position)?;
            }
            Ok::<_, DecodeError>(())
        })?;

        Ok(summary)
    }

    /// The locked-mode scan: nothing persists. Cursors live with the caller;
    /// returns only the notes found *this pass*, and the advanced cursors.
    /// (The rescan queue is attempted but left queued for a future sealed
    /// scan, which is the durability point.)
    ///
    /// # Errors
    /// Propagates [`DecodeError`].
    pub fn scan_in_memory(
        &self,
        db: &Database,
        cursors: &ScanCursors,
    ) -> Result<MemoryScan, DecodeError> {
        let view = db.read()?;
        let watermarks = |wallet: usize, tree: u32| {
            Ok(*cursors.get(&(self.wallets[wallet].id, tree)).unwrap_or(&0))
        };
        let (found, lengths, _, summary) = self.run(db, &view, &watermarks)?;

        let mut advanced = ScanCursors::new();
        for wallet in &self.wallets {
            for (tree, length) in lengths.iter().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                advanced.insert((wallet.id, tree as u32), *length);
            }
        }
        let notes = self
            .wallets
            .iter()
            .map(|wallet| wallet.id)
            .zip(found)
            .collect();
        Ok((notes, advanced, summary))
    }

    /// The shared engine: plan segments from watermarks, fan chunks across
    /// workers, return per-wallet found notes + the tree lengths the
    /// watermarks should advance to + the drained rescan entries.
    #[allow(clippy::type_complexity)]
    fn run<R: Reader>(
        &self,
        db: &Database,
        view: &R,
        watermark: &dyn Fn(usize, u32) -> Result<u32, database::DatabaseError>,
    ) -> Result<
        (
            Vec<Vec<DecryptedNote>>,
            Vec<u32>,
            Vec<(u32, u32)>,
            ScanSummary,
        ),
        DecodeError,
    > {
        let span = tracing::info_span!("decode.scan", wallets = self.wallets.len());
        let _guard = span.enter();
        let started = Instant::now();

        let commitments = Commitments::new(view);
        let tree_count = commitments.tree_count()?;

        // Plan: per tree, sweep segments between distinct watermarks so every
        // overlapping range is read once with the maximal wallet group.
        // alloc-ok: planning state, bounded by trees × wallets.
        let mut lengths = Vec::with_capacity(tree_count as usize);
        let mut queue = VecDeque::new();
        let mut pending_leaves: u64 = 0;
        for tree in 0..tree_count {
            let length = commitments.tree_length(tree)?;
            lengths.push(length);

            let mut marks = Vec::with_capacity(self.wallets.len());
            for wallet in 0..self.wallets.len() {
                marks.push(watermark(wallet, tree)?.min(length));
            }
            let mut boundaries: Vec<u32> = marks.iter().copied().filter(|&m| m < length).collect();
            boundaries.sort_unstable();
            boundaries.dedup();

            for (index, &start) in boundaries.iter().enumerate() {
                let end = boundaries.get(index + 1).copied().unwrap_or(length);
                let group: Vec<usize> = (0..self.wallets.len())
                    .filter(|&w| marks[w] <= start)
                    .collect();
                pending_leaves += u64::from(end - start) * group.len() as u64;
                let mut first = start;
                while first < end {
                    let last = first.saturating_add(self.chunk_size - 1).min(end - 1);
                    queue.push_back(Chunk {
                        tree,
                        first,
                        last,
                        wallet_indices: group.clone(),
                    });
                    first = last.saturating_add(1);
                }
            }
        }

        // Backfilled positions: every wallet attempts them.
        let rescans = commitments.rescan_queue()?;
        for &(tree, position) in &rescans {
            queue.push_back(Chunk {
                tree,
                first: position,
                last: position,
                wallet_indices: (0..self.wallets.len()).collect(),
            });
        }

        let chunks = queue.len();
        let workers = self.threads.min(chunks.max(1));
        tracing::debug!(chunks, workers, pending_leaves, "scan planned");

        // Fan out: workers drain the shared queue, each over its own view.
        let queue = Mutex::new(queue);
        let mut found: Vec<Vec<DecryptedNote>> = vec![Vec::new(); self.wallets.len()];
        let mut summary = ScanSummary {
            rescans: rescans.len() as u64,
            ..ScanSummary::default()
        };

        std::thread::scope(|scope| -> Result<(), DecodeError> {
            // alloc-ok: one handle per worker.
            let mut handles = Vec::with_capacity(workers);
            for _ in 0..workers {
                handles.push(scope.spawn(|| self.worker(db, &queue)));
            }
            for handle in handles {
                let (notes, leaves, attempts) = handle.join().expect("scan worker panicked")?;
                summary.leaves_scanned += leaves;
                summary.attempts += attempts;
                for (wallet, note) in notes {
                    summary.notes_found += 1;
                    found[wallet].push(note);
                }
            }
            Ok(())
        })?;

        tracing::info!(
            wallets = self.wallets.len(),
            chunks,
            workers,
            leaves_scanned = summary.leaves_scanned,
            attempts = summary.attempts,
            notes_found = summary.notes_found,
            rescans = summary.rescans,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            attempts_per_sec = per_second(summary.attempts, started.elapsed()),
            "scan complete"
        );

        Ok((found, lengths, rescans, summary))
    }

    /// One worker: drain chunks, scan each with an own read view.
    #[allow(clippy::type_complexity)]
    fn worker(
        &self,
        db: &Database,
        queue: &Mutex<VecDeque<Chunk>>,
    ) -> Result<(Vec<(usize, DecryptedNote)>, u64, u64), DecodeError> {
        let view = db.read()?;
        // alloc-ok: this worker's findings (a handful of notes at most).
        let mut found = Vec::new();
        let mut leaves: u64 = 0;
        let mut attempts: u64 = 0;

        loop {
            let Some(chunk) = queue.lock().expect("scan queue poisoned").pop_front() else {
                return Ok((found, leaves, attempts));
            };
            for stored in
                Commitments::new(&view).nodes_range(chunk.tree, chunk.first, chunk.last)?
            {
                let stored = stored?;
                leaves += 1;
                for &wallet in &chunk.wallet_indices {
                    attempts += 1;
                    match stored.decrypt_with(&self.wallets[wallet].decryptor) {
                        Ok(note) => found.push((wallet, note)),
                        // The common case: this leaf is not addressed to us.
                        Err(CryptoError::Aes) => {}
                        Err(error) => tracing::debug!(
                            tree = chunk.tree,
                            position = stored.position.leaf_index(),
                            %error,
                            "skipped commitment that decrypted but did not validate"
                        ),
                    }
                }
            }
        }
    }
}
