//! The user-facing facade: one place that owns session state (active wallets,
//! the unlock/seal lifecycle) and the single-lifecycle pipeline — **sync the
//! tree once, scan once for every wallet, and every later read is implicitly
//! fresh** (reads come off MVCC snapshots; buckets/balances are computed per
//! query, never cached stale).
//!
//! Key handling: registered wallets hold in-memory [`decoder::ScanWallet`]s
//! (derived decryptors) — secrets never reach storage. Decoded notes persist
//! only **sealed** ([`crypto::Sealer`]) while a data-encryption key is
//! unlocked; with no DEK the pipeline runs memory-only (notes and cursors
//! live in this struct, nothing on disk, full rescan next launch — the
//! degraded-but-private mode). The DEK itself comes from the platform layer:
//! today a caller-provided 32-byte key, later a hardware/biometric-gated
//! keystore unwrap behind the same `unlock` call.

use std::collections::HashMap;

use crypto::{AesGcmSealer, DerivedRailgunKeys, Sealer};
use database::Database;
use decoder::{DecodeError, ScanCursors, ScanSummary, ScanWallet, Scanner, WalletId};
use sync::{EventSource, SyncError, SyncSummary, Syncer};
use types::DecryptedNote;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Database(#[from] database::DatabaseError),
    #[error("wallet {0:?} is not registered")]
    UnknownWallet(WalletId),
}

/// Outcome of one [`Wallets::sync_and_scan`] pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PipelineSummary {
    pub sync: SyncSummary,
    pub scan: ScanSummary,
}

/// The active-wallet session: registry, unlock state, and the pipeline.
pub struct Wallets {
    scanner: Scanner,
    sealer: Option<AesGcmSealer>,
    /// Memory-only state while locked: scan cursors + found notes.
    cursors: ScanCursors,
    cache: HashMap<WalletId, Vec<DecryptedNote>>
}

impl Wallets {
    #[must_use]
    pub fn new() -> Self {
        Wallets {
            scanner: Scanner::new(Vec::new()),
            sealer: None,
            cursors: ScanCursors::new(),
            cache: HashMap::new(),
        }
    }

    /// Registers an account's derived keys as an active wallet. The keys stay
    /// in memory only; the returned id is the wallet's stable, non-secret
    /// handle. A wallet registered after others backfills from leaf 0 on the
    /// next scan, then converges.
    pub fn register(&mut self, keys: &DerivedRailgunKeys) -> WalletId {
        let wallet = ScanWallet::from_keys(keys);
        let id = wallet.id;
        self.scanner.add_wallet(wallet);
        id
    }

    /// Unlocks sealed persistence with a 32-byte data-encryption key.
    /// (Platform follow-up: this is where a hardware/biometric-gated keystore
    /// hands over the unwrapped DEK.)
    pub fn unlock(&mut self, dek: [u8; 32]) {
        self.sealer = Some(AesGcmSealer::new(dek));
    }

    /// Drops the session key: subsequent scans run memory-only.
    pub fn lock(&mut self) {
        self.sealer = None;
    }

    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.sealer.is_some()
    }

    /// The single-lifecycle pass: sync the tree to the source's head, then
    /// one multi-wallet scan over everything new — sealed-persisted when
    /// unlocked, memory-only when locked.
    ///
    /// # Errors
    /// Propagates [`WalletError`] from the failing stage; a sync that
    /// succeeded stays committed even if the scan then fails (the scan just
    /// reruns next pass).
    pub async fn sync_and_scan<S: EventSource>(
        &mut self,
        db: &Database,
        syncer: &Syncer<S>,
    ) -> Result<PipelineSummary, WalletError> {
        let sync = syncer.run_to_head(db).await?;
        let scan = self.scan(db)?;
        Ok(PipelineSummary { sync, scan })
    }

    /// Runs just the scan stage (e.g. after registering a wallet, without
    /// touching the network).
    ///
    /// # Errors
    /// Propagates [`WalletError`].
    pub fn scan(&mut self, db: &Database) -> Result<ScanSummary, WalletError> {
        if let Some(sealer) = &self.sealer {
            Ok(self.scanner.scan(db, sealer)?)
        } else {
            let (found, cursors, summary) = self.scanner.scan_in_memory(db, &self.cursors)?;
            self.cursors = cursors;
            for (id, notes) in found {
                let cached = self.cache.entry(id).or_default();
                for note in notes {
                    if !cached.iter().any(|n| n.position == note.position) {
                        cached.push(note);
                    }
                }
            }
            Ok(summary)
        }
    }

    /// The wallet's decoded notes: unsealed from the database when unlocked,
    /// from the in-memory cache when locked.
    ///
    /// # Errors
    /// Propagates [`WalletError`]; [`WalletError::UnknownWallet`] if `id` was
    /// never registered.
    pub fn notes(&self, db: &Database, id: WalletId) -> Result<decoder::DecodedNotes, WalletError> {
        if !self.scanner.wallet_ids().any(|registered| registered == id) {
            return Err(WalletError::UnknownWallet(id));
        }
        let notes = if let Some(sealer) = &self.sealer {
            match db.read()?.decoded().sealed_notes(id.as_bytes())? {
                Some(sealed) => {
                    let plain = sealer.unseal(&sealed).map_err(DecodeError::Seal)?;
                    serde_json::from_slice(&plain)
                        .map_err(|error| database::DatabaseError::Serde(error.to_string()))?
                }
                None => Vec::new(),
            }
        } else {
            self.cache.get(&id).cloned().unwrap_or_default()
        };
        Ok(decoder::DecodedNotes::from_notes(notes))
    }
}

impl Default for Wallets {
    fn default() -> Self {
        Wallets::new()
    }
}
