use serde::{Deserialize, Serialize};
use unionlabs::bounded::BoundedI64;

use crate::crypto::proof_ops::ProofOps;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseQuery {
    pub code: u32,
    /// nondeterministic
    pub log: String,
    /// nondeterministic
    pub info: String,
    pub index: i64,
    #[serde(with = "::serde_utils::hex_string")]
    pub key: Vec<u8>,
    #[serde(with = "::serde_utils::hex_string")]
    pub value: Vec<u8>,
    pub proof_ops: Option<ProofOps>,
    pub height: BoundedI64<0, { i64::MAX }>,
    pub codespace: String,
}

#[cfg(feature = "proto")]
pub mod proto {
    use unionlabs::bounded::BoundedIntError;

    use crate::abci::response_query::ResponseQuery;

    impl From<ResponseQuery> for protos::tendermint::abci::ResponseQuery {
        fn from(value: ResponseQuery) -> Self {
            Self {
                code: value.code,
                log: value.log,
                info: value.info,
                index: value.index,
                key: value.key,
                value: value.value,
                proof_ops: value.proof_ops.map(Into::into),
                height: value.height.inner(),
                codespace: value.codespace,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, thiserror::Error)]
    pub enum Error {
        #[error("invalid height")]
        Height(#[source] BoundedIntError<i64>),
    }

    impl TryFrom<protos::tendermint::abci::ResponseQuery> for ResponseQuery {
        type Error = Error;

        fn try_from(value: protos::tendermint::abci::ResponseQuery) -> Result<Self, Self::Error> {
            Ok(Self {
                code: value.code,
                log: value.log,
                info: value.info,
                index: value.index,
                key: value.key,
                value: value.value,
                proof_ops: value.proof_ops.map(Into::into),
                height: value.height.try_into().map_err(Error::Height)?,
                codespace: value.codespace,
            })
        }
    }
}
