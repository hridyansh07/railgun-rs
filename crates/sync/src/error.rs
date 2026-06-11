#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("graphql error: {0}")]
    GraphQl(String),
    #[error("request failed ({status}): {body}")]
    Request {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error(transparent)]
    Database(#[from] database::DatabaseError),
    #[error(transparent)]
    Merkle(#[from] crypto::MerkleError),
}
