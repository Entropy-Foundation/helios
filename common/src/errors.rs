use ethers::abi::Log as DecodedLog;
use ethers::types::H256;
use thiserror::Error;

use crate::types::BlockTag;

#[derive(Debug, Error)]
#[error("block not available: {block}")]
pub struct BlockNotFoundError {
    block: BlockTag,
}

impl BlockNotFoundError {
    pub fn new(block: BlockTag) -> Self {
        Self { block }
    }
}

#[derive(Debug, Error)]
#[error("slot not found: {slot:?}")]
pub struct SlotNotFoundError {
    slot: H256,
}

impl SlotNotFoundError {
    pub fn new(slot: H256) -> Self {
        Self { slot }
    }
}

#[derive(Debug, Error)]
#[error("rpc error on method: {method}, message: {error}")]
pub struct RpcError<E: ToString> {
    method: String,
    error: E,
}

impl<E: ToString> RpcError<E> {
    pub fn new(method: &str, err: E) -> Self {
        Self {
            method: method.to_string(),
            error: err,
        }
    }
}

#[derive(Debug, Error)]
#[error("Error converting DecodedLog to BridgeEvent. Log is: {:?}", self.log)]
pub struct BridgeEventParseError {
    log: DecodedLog,
}

impl BridgeEventParseError {
    pub fn new(log: DecodedLog) -> Self {
        Self { log }
    }
}
