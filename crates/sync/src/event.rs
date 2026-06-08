use commitments::CommitmentNode;
use types::Nullified;

/// One unit of synced chain state: a commitment leaf or a spend (nullifier).
#[derive(Debug)]
pub enum SyncEvent {
    Commitment(CommitmentNode),
    Nullified(Nullified),
}
