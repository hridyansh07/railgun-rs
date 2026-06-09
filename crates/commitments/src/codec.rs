//! Byte-exact encoding for stored [`Node`]s.
//!
//! Layout is canonical and inspectable: fixed-width big-endian scalars, raw 32-byte
//! hashes/keys, and length-prefixed blobs for variable data. Ciphertext and the shield
//! bundle are stored verbatim so nothing ever transforms them between persistence and
//! decryption.
//!
//! Record layout: `position | hash | block | body_tag | body`.

use types::{
    AssetId, BlindedKey, BlockNumber, Bytes, Ciphertext, CommitmentHash, EvmAddress, Node,
    NodeBody, NodePosition, ShieldBody, TransactBody, TypeError, U256, ViewingPublicKey,
};

// This should be an enum
const TAG_SHIELD: u8 = 0;
const TAG_TRANSACT: u8 = 1;
const TAG_ERC20: u8 = 0;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("unexpected end of stored bytes")]
    UnexpectedEof,
    #[error("trailing bytes after decoding a record")]
    TrailingBytes,
    #[error("invalid commitment tag {0}")]
    InvalidCommitmentTag(u8),
    #[error("invalid asset tag {0}")]
    InvalidAssetTag(u8),
    #[error(transparent)]
    Type(#[from] TypeError),
}

// ---- encoding ----------------------------------------------------------------

/// Encodes a [`Node`] into its canonical byte layout.
#[must_use]
pub fn encode_node(node: &Node) -> Vec<u8> {
    // alloc-ok: owned record buffer at the persistence boundary.
    let mut buf = Vec::new();
    put_position(&mut buf, node.position);
    put_u256(&mut buf, node.hash.as_u256());
    put_u64(&mut buf, node.block.get());

    // Note: Is there a way to make the buf API idiomatic instead of multiple calls passing the buf around ?
    // Seemes like it would be cleaner
    match &node.body {
        NodeBody::Shield(body) => {
            buf.push(TAG_SHIELD);
            put_u256(&mut buf, body.npk);
            put_asset(&mut buf, body.token);
            put_u256(&mut buf, body.value);
            put_bundle(&mut buf, &body.encrypted_bundle);
            buf.extend_from_slice(body.shield_key.as_bytes());
        }
        NodeBody::Transact(body) => {
            buf.push(TAG_TRANSACT);
            put_ciphertext(&mut buf, &body.ciphertext);
            put_blob(&mut buf, body.memo.as_ref());
            buf.extend_from_slice(body.blinded_sender_key.as_bytes());
            buf.extend_from_slice(body.blinded_receiver_key.as_bytes());
            put_blob(&mut buf, body.annotation.as_ref());
        }
    }
    buf
}

fn put_position(buf: &mut Vec<u8>, position: NodePosition) {
    put_u32(buf, position.tree_number());
    put_u32(buf, position.leaf_index());
}

fn put_asset(buf: &mut Vec<u8>, asset: AssetId) {
    match asset {
        AssetId::Erc20(address) => {
            buf.push(TAG_ERC20);
            buf.extend_from_slice(address.as_slice());
        }
    }
}

fn put_ciphertext(buf: &mut Vec<u8>, ciphertext: &Ciphertext) {
    buf.extend_from_slice(&ciphertext.iv);
    buf.extend_from_slice(&ciphertext.tag);
    put_u32(buf, blob_len(ciphertext.data.len()));
    for block in &ciphertext.data {
        put_blob(buf, block.as_ref());
    }
}

fn put_bundle(buf: &mut Vec<u8>, bundle: &[[u8; 32]]) {
    put_u32(buf, blob_len(bundle.len()));
    for word in bundle {
        buf.extend_from_slice(word);
    }
}

fn put_u256(buf: &mut Vec<u8>, value: U256) {
    buf.extend_from_slice(&value.to_be_bytes::<32>());
}

fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_blob(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(buf, blob_len(bytes.len()));
    buf.extend_from_slice(bytes);
}

fn blob_len(len: usize) -> u32 {
    u32::try_from(len).expect("stored blob length fits in u32")
}

// ---- decoding ----------------------------------------------------------------

/// Decodes a [`Node`] from its canonical byte layout.
///
/// # Errors
/// Returns [`CodecError`] on truncated input, an unknown tag, an out-of-range
/// node position, or trailing bytes.
pub fn decode_node(bytes: &[u8]) -> Result<Node, CodecError> {
    // Might be cleaner to write the decode as a impl on the Reader function?
    // This is ideally the same bytes being repeated again and again a single function should also do the job
    let mut reader = Reader::new(bytes);
    let position = reader.take_position()?;
    let hash = CommitmentHash::new(reader.take_u256()?);
    let block = BlockNumber::new(reader.take_u64()?);

    let body = match reader.take_u8()? {
        TAG_SHIELD => NodeBody::Shield(ShieldBody {
            npk: reader.take_u256()?,
            token: reader.take_asset()?,
            value: reader.take_u256()?,
            encrypted_bundle: reader.take_bundle()?,
            shield_key: ViewingPublicKey::from_bytes(reader.take_array32()?),
        }),
        TAG_TRANSACT => NodeBody::Transact(TransactBody {
            ciphertext: reader.take_ciphertext()?,
            memo: Bytes::copy_from_slice(reader.take_blob()?),
            blinded_sender_key: BlindedKey::from_bytes(reader.take_array32()?),
            blinded_receiver_key: BlindedKey::from_bytes(reader.take_array32()?),
            annotation: Bytes::copy_from_slice(reader.take_blob()?),
        }),
        other => return Err(CodecError::InvalidCommitmentTag(other)),
    };
    reader.finish()?;

    Ok(Node {
        position,
        hash,
        block,
        body,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

// Many functions seem redundant clean and minimize
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(len).ok_or(CodecError::UnexpectedEof)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32, CodecError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("took exactly 4 bytes");
        Ok(u32::from_be_bytes(bytes))
    }

    fn take_u64(&mut self) -> Result<u64, CodecError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("took exactly 8 bytes");
        Ok(u64::from_be_bytes(bytes))
    }

    fn take_array32(&mut self) -> Result<[u8; 32], CodecError> {
        let bytes: [u8; 32] = self.take(32)?.try_into().expect("took exactly 32 bytes");
        Ok(bytes)
    }

    fn take_u256(&mut self) -> Result<U256, CodecError> {
        Ok(U256::from_be_bytes(self.take_array32()?))
    }

    fn take_blob(&mut self) -> Result<&'a [u8], CodecError> {
        let len = self.take_u32()? as usize;
        self.take(len)
    }

    fn take_bundle(&mut self) -> Result<Vec<[u8; 32]>, CodecError> {
        let count = self.take_u32()? as usize;
        // alloc-ok: word list bounded by the stored count we wrote ourselves.
        let mut bundle = Vec::with_capacity(count);
        for _ in 0..count {
            bundle.push(self.take_array32()?);
        }
        Ok(bundle)
    }

    fn take_position(&mut self) -> Result<NodePosition, CodecError> {
        let tree_number = self.take_u32()?;
        let leaf_index = self.take_u32()?;
        Ok(NodePosition::try_new(tree_number, leaf_index)?)
    }

    fn take_asset(&mut self) -> Result<AssetId, CodecError> {
        match self.take_u8()? {
            TAG_ERC20 => Ok(AssetId::erc20(EvmAddress::from_slice(self.take(20)?))),
            other => Err(CodecError::InvalidAssetTag(other)),
        }
    }

    fn take_ciphertext(&mut self) -> Result<Ciphertext, CodecError> {
        let iv: [u8; 16] = self.take(16)?.try_into().expect("took exactly 16 bytes");
        let tag: [u8; 16] = self.take(16)?.try_into().expect("took exactly 16 bytes");
        let block_count = self.take_u32()? as usize;
        // alloc-ok: block list bounded by the stored block count we wrote ourselves.
        let mut data = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            data.push(Bytes::copy_from_slice(self.take_blob()?));
        }
        Ok(Ciphertext { iv, tag, data })
    }

    fn finish(self) -> Result<(), CodecError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}
