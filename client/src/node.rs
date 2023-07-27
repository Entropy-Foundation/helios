use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ethers::abi::RawLog;
use ethers::prelude::{Address, U256};
use ethers::types::{
    FeeHistory, Filter, Log, SyncProgress, SyncingStatus, Transaction, TransactionReceipt, H256
};
use eyre::{eyre, Result};

use common::errors::BlockNotFoundError;
use common::types::BlockTag;
use config::Config;

use consensus::rpc::nimbus_rpc::NimbusRpc;
use consensus::types::{ExecutionPayload, Header};
use consensus::ConsensusClient;
use execution::evm::Evm;
use execution::rpc::http_rpc::HttpRpc;
use execution::types::{CallOpts, ExecutionBlock};
use execution::ExecutionClient;

use crate::client::BridgeEvent;
use crate::errors::NodeError;

pub struct Node {
    pub consensus: ConsensusClient<NimbusRpc>,
    pub execution: Arc<ExecutionClient<HttpRpc>>,
    pub config: Arc<Config>,
    payloads: BTreeMap<u64, ExecutionPayload>,
    finalized_payloads: BTreeMap<u64, ExecutionPayload>,
    current_slot: Option<u64>,
    pub history_size: usize,
    
    last_processed: u64,
    // Map of verified BridgeEvents indexed by their global_action_id, which is
    // an identifier intended to be unique across all chains.
    verified_event_cache: BTreeMap<U256, BridgeEvent>,
    // Map of verified logs indexed by (block_no, tx_index, log_index)
    // verified_log_cache: BTreeMap<(U64, U64, U256), Log>,
} 

impl Node {
    pub fn new(config: Arc<Config>) -> Result<Self, NodeError> {
        let consensus_rpc = &config.consensus_rpc;
        let checkpoint_hash = &config.checkpoint.as_ref().unwrap();
        let execution_rpc = &config.execution_rpc;

        let consensus = ConsensusClient::new(consensus_rpc, checkpoint_hash, config.clone())
            .map_err(NodeError::ConsensusClientCreationError)?;
        let execution = Arc::new(
            ExecutionClient::new(execution_rpc).map_err(NodeError::ExecutionClientCreationError)?,
        );

        let payloads = BTreeMap::new();
        let finalized_payloads = BTreeMap::new();

        Ok(Node {
            consensus,
            execution,
            config,
            payloads,
            finalized_payloads,
            current_slot: None,
            history_size: 64,

            last_processed: 0,
            verified_event_cache: BTreeMap::new(),
        })
    }

    pub async fn sync(&mut self) -> Result<(), NodeError> {
        let chain_id = self.config.chain.chain_id;
        self.execution
            .check_rpc(chain_id)
            .await
            .map_err(NodeError::ExecutionError)?;

        self.consensus
            .check_rpc()
            .await
            .map_err(NodeError::ConsensusSyncError)?;

        self.consensus
            .sync()
            .await
            .map_err(NodeError::ConsensusSyncError)?;

        self.update_payloads().await?;

        // Check for new events
        log::info!("Syncing initial events...");
        self.check_latest_events(true).await.map_err(NodeError::ConsensusAdvanceError)
    }

    pub async fn advance(&mut self) -> Result<(), NodeError> {
        log::info!("Starting advance...");
        self.consensus
            .advance()
            .await
            .map_err(NodeError::ConsensusAdvanceError)?;
        log::info!("Updating payloads...");
        self.update_payloads().await?;

        // Check for new events
        log::info!("Checking for new events...");
        self.check_latest_events(false).await.map_err(NodeError::ConsensusAdvanceError)
    }

    pub fn duration_until_next_update(&self) -> Duration {
        self.consensus
            .duration_until_next_update()
            .to_std()
            .unwrap()
    }

    // TODO: Should return events only after event with given ID?
    pub fn get_bridge_events(&self) -> Vec<BridgeEvent> {
        return self.verified_event_cache.values().cloned().collect();
    }

    pub fn verify_bridge_events(&self, events: Vec<U256>) -> bool {
        return events.iter().all(|id| self.verified_event_cache.contains_key(&id));
    }

    // Should only be invoked with events that have been included in a block that has been finalized by the SMR.
    pub fn cleanup_bridge_events(&mut self, events: Vec<U256>) {
        for id in events {
            self.verified_event_cache.remove(&id);
        }
    }

    async fn check_latest_events(&mut self, initial_sync: bool) -> Result<()> {
        // TODO: Add address
        let eth_vault_contract_addr = "0x05fdBac96C17026c71681150aa44Cbd0DDDd3374".parse::<Address>().unwrap();
        let human_readable_event_abi = [
            "event Bridgeless(uint256 globalActionId, address from, string foreignAddress, uint256 foreignChainId, uint256 amount, uint256 conversionRate, uint256 conversionDecimals)"
        ];
        let abi = ethers::abi::parse_abi(&human_readable_event_abi).unwrap();
        let bridge_event = abi.event("Bridgeless").unwrap();

        log::info!("Have {} payloads during check", self.payloads.len());

        // Newest block in our current history that we haven't already processed. 
        // BTreeMap keys are sorted, so find works here.
        if let Some(start_block) = self.payloads.keys().find(|k| **k > self.last_processed) {
            // Newest block in our current history.
            if let Some(end_block) = self.payloads.last_key_value() {
                log::info!(
                    "Attempting to retrieve logs for blocks: {}-{}",
                    *start_block,
                    *end_block.0
                );

                let vault_event_filter = Filter::new()
                    .from_block(*start_block)
                    .to_block(*end_block.0)
                    .address(eth_vault_contract_addr);

                // TODO: Seems like RPC node might not be returning the logs for the latest payloads sometimes.
                // Might need to rely on finalised blocks instead, which it should hopefully always have complete
                // data for.
                let latest_vault_event_logs = 
                    if initial_sync {
                        self.execution.get_logs_unlimited(&vault_event_filter, &self.payloads).await?
                    } else {
                        self.execution.get_logs(&vault_event_filter, &self.payloads).await?
                    };

                log::info!(
                    "Received {} new logs",
                    latest_vault_event_logs.len(),
                );

                // Parse the new logs and add the events to the cache.
                for log in latest_vault_event_logs {
                    match (log.block_number, log.transaction_index, log.log_index) {
                        (Some(block_no), Some(tx_index), Some(log_index)) => {
                            let id = (block_no, tx_index, log_index);
                            // TODO: Remove
                            // self.verified_log_cache.insert(id, log);

                            let raw_log = RawLog::from(log);
                            let decoded_log = bridge_event.parse_log(raw_log)?;
                            let event = BridgeEvent::try_from(decoded_log)?;
                            self.verified_event_cache.insert(event.global_action_id, event);
                            
                        },
                        _ => log::warn!("Missing block number or transaction index for log: {:?}", log)
                    }
                }

                log::info!(
                    "Have {} events in cache.",
                    self.verified_event_cache.len()
                );

                self.last_processed = *end_block.0;
            }
            // else: Empty history
        }
        // else: Empty history

        Ok(())
    }

    async fn update_payloads(&mut self) -> Result<(), NodeError> {
        let latest_header = self.consensus.get_header();
        let latest_payload = self
            .consensus
            .get_execution_payload(&Some(latest_header.slot))
            .await
            .map_err(NodeError::ConsensusPayloadError)?;

        let finalized_header = self.consensus.get_finalized_header();
        let finalized_payload = self
            .consensus
            .get_execution_payload(&Some(finalized_header.slot))
            .await
            .map_err(NodeError::ConsensusPayloadError)?;

        self.payloads
            .insert(*latest_payload.block_number(), latest_payload);
        self.payloads
            .insert(*finalized_payload.block_number(), finalized_payload.clone());
        self.finalized_payloads
            .insert(*finalized_payload.block_number(), finalized_payload);

        let start_slot = self
            .current_slot
            .unwrap_or(latest_header.slot - self.history_size as u64);
        let backfill_payloads = self
            .consensus
            .get_payloads(start_slot, latest_header.slot)
            .await
            .map_err(NodeError::ConsensusPayloadError)?;

        log::info!("Received {} new payloads", backfill_payloads.len());

        for payload in backfill_payloads {
            // log::info!("Received payload for block: {}", payload.block_number());
            self.payloads.insert(*payload.block_number(), payload);
        }

        log::info!("Have {} payloads", self.payloads.len());

        self.current_slot = Some(latest_header.slot);

        while self.payloads.len() > self.history_size {
            self.payloads.pop_first();
        }

        log::info!("Have {} payloads after prune", self.payloads.len());

        // only save one finalized block per epoch
        // finality updates only occur on epoch boundaries
        while self.finalized_payloads.len() > usize::max(self.history_size / 32, 1) {
            self.finalized_payloads.pop_first();
        }

        Ok(())
    }

    pub async fn call(&self, opts: &CallOpts, block: BlockTag) -> Result<Vec<u8>, NodeError> {
        self.check_blocktag_age(&block)?;

        let payload = self.get_payload(block)?;
        let mut evm = Evm::new(
            self.execution.clone(),
            payload,
            &self.payloads,
            self.chain_id(),
        );
        evm.call(opts).await.map_err(NodeError::ExecutionEvmError)
    }

    pub async fn estimate_gas(&self, opts: &CallOpts) -> Result<u64, NodeError> {
        self.check_head_age()?;

        let payload = self.get_payload(BlockTag::Latest)?;
        let mut evm = Evm::new(
            self.execution.clone(),
            payload,
            &self.payloads,
            self.chain_id(),
        );
        evm.estimate_gas(opts)
            .await
            .map_err(NodeError::ExecutionEvmError)
    }

    pub async fn get_balance(&self, address: &Address, block: BlockTag) -> Result<U256> {
        self.check_blocktag_age(&block)?;

        let payload = self.get_payload(block)?;
        let account = self.execution.get_account(address, None, payload).await?;
        Ok(account.balance)
    }

    pub async fn get_nonce(&self, address: &Address, block: BlockTag) -> Result<u64> {
        self.check_blocktag_age(&block)?;

        let payload = self.get_payload(block)?;
        let account = self.execution.get_account(address, None, payload).await?;
        Ok(account.nonce)
    }

    pub fn get_block_transaction_count_by_hash(&self, hash: &Vec<u8>) -> Result<u64> {
        let payload = self.get_payload_by_hash(hash)?;
        let transaction_count = payload.1.transactions().len();

        Ok(transaction_count as u64)
    }

    pub fn get_block_transaction_count_by_number(&self, block: BlockTag) -> Result<u64> {
        let payload = self.get_payload(block)?;
        let transaction_count = payload.transactions().len();

        Ok(transaction_count as u64)
    }

    pub async fn get_code(&self, address: &Address, block: BlockTag) -> Result<Vec<u8>> {
        self.check_blocktag_age(&block)?;

        let payload = self.get_payload(block)?;
        let account = self.execution.get_account(address, None, payload).await?;
        Ok(account.code)
    }

    pub async fn get_storage_at(
        &self,
        address: &Address,
        slot: H256,
        block: BlockTag,
    ) -> Result<U256> {
        self.check_head_age()?;

        let payload = self.get_payload(block)?;
        let account = self
            .execution
            .get_account(address, Some(&[slot]), payload)
            .await?;

        let value = account.slots.get(&slot);
        match value {
            Some(value) => Ok(*value),
            None => Err(eyre!("slot not found")),
        }
    }

    pub async fn send_raw_transaction(&self, bytes: &[u8]) -> Result<H256> {
        self.execution.send_raw_transaction(bytes).await
    }

    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &H256,
    ) -> Result<Option<TransactionReceipt>> {
        self.execution
            .get_transaction_receipt(tx_hash, &self.payloads)
            .await
    }

    pub async fn get_transaction_by_hash(&self, tx_hash: &H256) -> Result<Option<Transaction>> {
        self.execution
            .get_transaction(tx_hash, &self.payloads)
            .await
    }

    pub async fn get_transaction_by_block_hash_and_index(
        &self,
        hash: &Vec<u8>,
        index: usize,
    ) -> Result<Option<Transaction>> {
        let payload = self.get_payload_by_hash(hash)?;

        self.execution
            .get_transaction_by_block_hash_and_index(payload.1, index)
            .await
    }

    pub async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        self.execution.get_logs(filter, &self.payloads).await
    }

    // assumes tip of 1 gwei to prevent having to prove out every tx in the block
    pub fn get_gas_price(&self) -> Result<U256> {
        self.check_head_age()?;

        let payload = self.get_payload(BlockTag::Latest)?;
        let base_fee = U256::from_little_endian(&payload.base_fee_per_gas().to_bytes_le());
        let tip = U256::from(10_u64.pow(9));
        Ok(base_fee + tip)
    }

    // assumes tip of 1 gwei to prevent having to prove out every tx in the block
    pub fn get_priority_fee(&self) -> Result<U256> {
        let tip = U256::from(10_u64.pow(9));
        Ok(tip)
    }

    pub fn get_block_number(&self) -> Result<u64> {
        self.check_head_age()?;

        let payload = self.get_payload(BlockTag::Latest)?;
        Ok(*payload.block_number())
    }

    pub fn get_block_hash(&self, block: BlockTag) -> Result<H256> {
        match block {
            BlockTag::Latest => self.check_head_age()?,
            _ => {}
        }

        let payload = self.get_payload(block)?;
        // Block hash in payload is parsed as Bytes32 instead of H256 for some reason.
        let hash_as_bytes = payload.block_hash().clone();
        Ok(H256::from_slice(&hash_as_bytes.as_slice()))
    }

    pub async fn get_block_by_number(
        &self,
        block: BlockTag,
        full_tx: bool,
    ) -> Result<Option<ExecutionBlock>> {
        self.check_blocktag_age(&block)?;

        match self.get_payload(block) {
            Ok(payload) => self.execution.get_block(payload, full_tx).await.map(Some),
            Err(_) => Ok(None),
        }
    }

    pub async fn get_fee_history(
        &self,
        block_count: u64,
        last_block: u64,
        reward_percentiles: &[f64],
    ) -> Result<Option<FeeHistory>> {
        self.execution
            .get_fee_history(block_count, last_block, reward_percentiles, &self.payloads)
            .await
    }

    pub async fn get_block_by_hash(
        &self,
        hash: &Vec<u8>,
        full_tx: bool,
    ) -> Result<Option<ExecutionBlock>> {
        let payload = self.get_payload_by_hash(hash);

        match payload {
            Ok(payload) => self.execution.get_block(payload.1, full_tx).await.map(Some),
            Err(_) => Ok(None),
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain.chain_id
    }

    pub fn syncing(&self) -> Result<SyncingStatus> {
        if self.check_head_age().is_ok() {
            Ok(SyncingStatus::IsFalse)
        } else {
            let latest_synced_block = self.get_block_number()?;
            let oldest_payload = self.payloads.first_key_value();
            let oldest_synced_block =
                oldest_payload.map_or(latest_synced_block, |(key, _value)| *key);
            let highest_block = self.consensus.expected_current_slot();
            Ok(SyncingStatus::IsSyncing(Box::new(SyncProgress {
                current_block: latest_synced_block.into(),
                highest_block: highest_block.into(),
                starting_block: oldest_synced_block.into(),
                pulled_states: None,
                known_states: None,
                healed_bytecode_bytes: None,
                healed_bytecodes: None,
                healed_trienode_bytes: None,
                healed_trienodes: None,
                healing_bytecode: None,
                healing_trienodes: None,
                synced_account_bytes: None,
                synced_accounts: None,
                synced_bytecode_bytes: None,
                synced_bytecodes: None,
                synced_storage: None,
                synced_storage_bytes: None,
            })))
        }
    }

    pub fn get_header(&self) -> Result<Header> {
        self.check_head_age()?;
        Ok(self.consensus.get_header().clone())
    }

    pub fn get_coinbase(&self) -> Result<Address> {
        self.check_head_age()?;
        let payload = self.get_payload(BlockTag::Latest)?;
        let coinbase_address = Address::from_slice(payload.fee_recipient());
        Ok(coinbase_address)
    }

    pub fn get_last_checkpoint(&self) -> Option<Vec<u8>> {
        self.consensus.last_checkpoint.clone()
    }

    fn get_payload(&self, block: BlockTag) -> Result<&ExecutionPayload, BlockNotFoundError> {
        match block {
            BlockTag::Latest => {
                let payload = self.payloads.last_key_value();
                Ok(payload.ok_or(BlockNotFoundError::new(BlockTag::Latest))?.1)
            }
            BlockTag::Finalized => {
                let payload = self.finalized_payloads.last_key_value();
                Ok(payload
                    .ok_or(BlockNotFoundError::new(BlockTag::Finalized))?
                    .1)
            }
            BlockTag::Number(num) => {
                let payload = self.payloads.get(&num);
                payload.ok_or(BlockNotFoundError::new(BlockTag::Number(num)))
            }
        }
    }

    fn get_payload_by_hash(&self, hash: &Vec<u8>) -> Result<(&u64, &ExecutionPayload)> {
        let payloads = self
            .payloads
            .iter()
            .filter(|entry| &entry.1.block_hash().to_vec() == hash)
            .collect::<Vec<(&u64, &ExecutionPayload)>>();

        payloads
            .get(0)
            .cloned()
            .ok_or(eyre!("Block not found by hash"))
    }

    fn check_head_age(&self) -> Result<(), NodeError> {
        let synced_slot = self.consensus.get_header().slot;
        let expected_slot = self.consensus.expected_current_slot();
        let slot_delay = expected_slot - synced_slot;

        if slot_delay > 10 {
            return Err(NodeError::OutOfSync(slot_delay));
        }

        Ok(())
    }

    fn check_blocktag_age(&self, block: &BlockTag) -> Result<(), NodeError> {
        match block {
            BlockTag::Latest => self.check_head_age(),
            BlockTag::Finalized => Ok(()),
            BlockTag::Number(_) => Ok(()),
        }
    }
}
