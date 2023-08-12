use ethers::abi::Log as DecodedLog;
use ethers::prelude::{Address, U256};
use ethers::types::H160;
use ethers::utils::format_units;
use serde::{de::Error, Deserialize, Serialize};
use ssz_rs::Vector;
use core::panic;
use std::fmt::Display;

use crate::errors::BridgeEventParseError;

pub const APT_DECIMALS : u64 = 100000000;
pub const SUI_DECIMALS : u64 = 1000000000;

pub type Bytes32 = Vector<u8, 32>;

#[derive(Debug, Clone, Copy)]
pub enum BlockTag {
    Latest,
    Finalized,
    Number(u64),
}

impl Display for BlockTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let formatted = match self {
            Self::Latest => "latest".to_string(),
            Self::Finalized => "finalized".to_string(),
            Self::Number(num) => num.to_string(),
        };

        write!(f, "{formatted}")
    }
}

impl<'de> Deserialize<'de> for BlockTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let block: String = serde::Deserialize::deserialize(deserializer)?;
        let parse_error = D::Error::custom("could not parse block tag");

        let block_tag = match block.as_str() {
            "latest" => BlockTag::Latest,
            "finalized" => BlockTag::Finalized,
            _ => match block.strip_prefix("0x") {
                Some(hex_block) => {
                    let num = u64::from_str_radix(hex_block, 16).map_err(|_| parse_error)?;

                    BlockTag::Number(num)
                }
                None => {
                    let num = block.parse().map_err(|_| parse_error)?;

                    BlockTag::Number(num)
                }
            },
        };

        Ok(block_tag)
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeEvent {
    pub amount: U256,
    #[serde(rename = "conversionDecimals")]
    pub conversion_decimals: U256,
    #[serde(rename = "conversionRate")]
    pub conversion_rate: U256,
    #[serde(rename = "foreignAddress")]
    pub foreign_address: String,
    #[serde(rename = "foreignChainId")]
    pub foreign_chain_id: U256,
    pub from: Address,
    #[serde(rename = "globalActionId")]
    pub global_action_id: U256,
}

impl BridgeEvent {
    pub fn pretty_print_string(&self) -> String {
        let source_chain = "Ethereum Goerli Testnet";
        let source_currency = "ETH";
        let (dest_chain, dest_currency) = 
            match self.foreign_chain_id.as_u128() {
                1 => ("Aptos DevNet", "APT"),
                2 => ("Sui DevNet", "SUI"),
                _ => ("Unsupported Chain", "Unsupported Currency")
            };

        format!(
            "Action {}: Convert {}{} from {} on {} to {}{} for {} on {}", 
            self.global_action_id,
            self.get_amount_eth(), 
            source_currency, 
            self.from,
            source_chain, 
            self.get_dest_currency_amount_native(),
            dest_currency, 
            self.foreign_address,
            dest_chain
        )
    }

    pub fn get_amount_eth(&self) -> f64 {
        format_units(self.amount, "ether")
            .expect("Failed to parse transfer amount.")
            .parse::<f64>()
            .expect("Failed to parse Eth to f64.")
    }

    pub fn get_conversion_rate(&self) -> f64 {
        let conversion_numerator_eth = format_units(self.conversion_rate, "ether")
            .expect("Failed to parse conversion rate.")
            .parse::<f64>()
            .expect("Failed to parse Eth to f64.");
        let conversion_denominator_eth = format_units(self.conversion_decimals, "ether")
            .expect("Failed to parse conversion_decimals.")
            .parse::<f64>()
            .expect("Failed to parse Eth to f64.");
        conversion_numerator_eth / conversion_denominator_eth
    }

    pub fn get_dest_currency_amount(&self) -> f64 {
        let dest_amount_native = self.get_dest_currency_amount_native();

        let dest_decimals = 
            if self.foreign_chain_id == U256::from_dec_str("1").unwrap() {
                // 10^8 OCTA per APT
                APT_DECIMALS as f64
            } else if self.foreign_chain_id == U256::from_dec_str("2").unwrap() {
                // 10^9 MIST per SUI
                SUI_DECIMALS as f64
            } else {
                panic!("Unknown destination chain.") //TODO
            };      

        dest_amount_native * dest_decimals
    }

    pub fn get_dest_currency_amount_native(&self) -> f64 {
        let amount_eth = self.get_amount_eth();
        amount_eth * self.get_conversion_rate()
    }
}

impl Default for BridgeEvent {
    fn default() -> Self {
        BridgeEvent { 
            amount: U256::default(), 
            conversion_decimals: U256::default(), 
            conversion_rate: U256::default(), 
            foreign_address: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(), 
            foreign_chain_id: U256::from_dec_str("1").unwrap(), 
            from: H160::default(), 
            global_action_id: U256::default()
        }
    }
}

impl TryFrom<DecodedLog> for BridgeEvent {
    type Error = BridgeEventParseError;

    fn try_from(log: DecodedLog) -> Result<Self, Self::Error> {
        let mut result = Self::default();

        // Manually parse the struct. TODO: Check if there is a better way to do this.
        // Rupansh suggested using the abigen macro, but have not had the time to check yet.
        for param in &log.params {
            let mut v = param.value.clone();

            let parsable = match param.name.as_str() {
                "amount" 
                    | "conversionDecimals" 
                    | "conversionRate" 
                    | "foreignChainId" 
                    | "globalActionId" => v.into_uint().is_some(),
                "foreignAddress" => v.into_string().is_some(),
                "from" => v.into_address().is_some(),
                _ => true   // Ignore other params.
            };

            if ! parsable {
                return Err(BridgeEventParseError::new(log));
            }

            // Restore moved value.
            v = param.value.clone();

            match param.name.as_str() {
                "amount" => result.amount = v.into_uint().unwrap(),
                "conversionDecimals" => result.conversion_decimals = v.into_uint().unwrap(),
                "conversionRate" => result.conversion_rate = v.into_uint().unwrap(),
                "foreignAddress" => result.foreign_address = v.into_string().unwrap(),
                "foreignChainId" => result.foreign_chain_id = v.into_uint().unwrap(),
                "from" => result.from = v.into_address().unwrap(),
                "globalActionId" => result.global_action_id = v.into_uint().unwrap(),
                _ => ()
            }
        }

        Ok(result)
    }
}
