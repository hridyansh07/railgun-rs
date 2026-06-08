use types::{Node, Nullified};

/// One unit of synced chain state: a commitment leaf or a spend (nullifier).
#[derive(Debug)]
pub enum SyncEvent {
    Commitment(Node),
    Nullified(Nullified),
}
