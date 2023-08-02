use std::{path::PathBuf, str::FromStr};

use config::{CliConfig, Config};
use dirs::home_dir;
use env_logger::Env;
use ethers::{types::{Address, Filter}, utils};
use eyre::Result;
use helios::{config::networks::Network, prelude::*};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let network = Network::GOERLI;
    // Load the config from the global config file
    let config_path = home_dir().unwrap().join(".helios/helios.toml");
    let config = Config::from_file(&config_path, "goerli", &CliConfig::default());
    // println!("Constructed config: {config:#?}");

    let mut c: Client<FileDB> = ClientBuilder::new()
        .config(config)
        .build()?;

    // Construct the checkpoint fallback services.
    // The `build` method will fetch a list of [CheckpointFallbackService]s from a community-mainained list by ethPandaOps.
    // This list is NOT guaranteed to be secure, but is provided in good faith.
    // The raw list can be found here: https://github.com/ethpandaops/checkpoint-sync-health-checks/blob/master/_data/endpoints.yaml
    // let cf = checkpoints::CheckpointFallback::new()
    //     .build()
    //     .await
    //     .unwrap();

    // // Fetch the latest goerli checkpoint
    // let goerli_checkpoint = cf
    //     .fetch_latest_checkpoint(&networks::Network::GOERLI)
    //     .await
    //     .unwrap();

    // let untrusted_rpc_url = "https://radial-methodical-owl.ethereum-goerli.quiknode.pro/cab0a92718b25ab1098cd0801b52471476571a90"; //"https://eth-mainnet.g.alchemy.com/v2/<YOUR_API_KEY>";
    // log::info!("Using untrusted RPC URL [REDACTED]");

    // let consensus_rpc = "http://unstable.prater.beacon-api.nimbus.team"; // "https://www.lightclientdata.org";
    // log::info!("Using consensus RPC URL: {}", consensus_rpc);

    // let mut client: Client<FileDB> = ClientBuilder::new()
    //     .network(network)
    //     .consensus_rpc(consensus_rpc)
    //     .execution_rpc(untrusted_rpc_url)
    //     .checkpoint(goerli_checkpoint)
    //     .data_dir(PathBuf::from("/tmp/helios"))
    //     .build()?;

    log::info!(
        "Built client on network \"{}\"",
        network
    );

    c.start().await?;

    log::info!(
        "Started client"
    );

    // TODO: Address is currently Uniswap v3 Factory
    let eth_vault_contract_addr = "0x7AacAa857584adA08ABB2bAA8f1C2094D4Ecb3bF".parse::<Address>().unwrap();
    // let last_final_block_hash = c.get_block_hash(BlockTag::Finalized).await?;
    let start_block = 9449965u64;
    let vault_event_filter = Filter::new()
        .from_block(start_block)
        .to_block(start_block)
        .address(eth_vault_contract_addr);
    let last_final_vault_event_logs = c.get_logs(&vault_event_filter).await?;

    log::info!(
        "Logs: {:?}",
        last_final_vault_event_logs
    );

    // let head_block_num = c.get_block_number().await?;
    // let addr = Address::from_str("0x00000000219ab540356cBB839Cbe05303d7705Fa")?;
    // let block = BlockTag::Latest;
    // let balance = c.get_balance(&addr, block).await?;

    // log::info!("synced up to block: {}", head_block_num);
    // log::info!(
    //     "balance of deposit contract: {}",
    //     utils::format_ether(balance)
    // );

    Ok(())
}
