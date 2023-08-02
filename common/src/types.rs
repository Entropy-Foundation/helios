use ethers::abi::Log as DecodedLog;
use ethers::prelude::{Address, U256};
use serde::{de::Error, Deserialize, Serialize};
use ssz_rs::Vector;
use std::fmt::Display;

use crate::errors::BridgeEventParseError;

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


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
                "globalActionId" => result.global_action_id = v.into_uint().unwrap(),
                _ => ()
            }
        }

        Ok(result)
    }
}
