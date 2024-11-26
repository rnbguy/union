use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignedMsgType {
    Unknown = 0,
    Prevote = 1,
    Precommit = 2,
    Proposal = 32,
}

#[cfg(feature = "proto")]
pub mod proto {
    use unionlabs::errors::UnknownEnumVariant;

    use crate::types::signed_msg_type::SignedMsgType;

    impl From<SignedMsgType> for protos::tendermint::types::SignedMsgType {
        fn from(value: SignedMsgType) -> Self {
            match value {
                SignedMsgType::Unknown => Self::Unknown,
                SignedMsgType::Prevote => Self::Prevote,
                SignedMsgType::Precommit => Self::Precommit,
                SignedMsgType::Proposal => Self::Proposal,
            }
        }
    }

    impl From<SignedMsgType> for i32 {
        fn from(value: SignedMsgType) -> Self {
            protos::tendermint::types::SignedMsgType::from(value).into()
        }
    }

    impl From<protos::tendermint::types::SignedMsgType> for SignedMsgType {
        fn from(value: protos::tendermint::types::SignedMsgType) -> Self {
            match value {
                protos::tendermint::types::SignedMsgType::Unknown => Self::Unknown,
                protos::tendermint::types::SignedMsgType::Prevote => Self::Prevote,
                protos::tendermint::types::SignedMsgType::Precommit => Self::Precommit,
                protos::tendermint::types::SignedMsgType::Proposal => Self::Proposal,
            }
        }
    }

    impl TryFrom<i32> for SignedMsgType {
        type Error = UnknownEnumVariant<i32>;

        fn try_from(value: i32) -> Result<Self, Self::Error> {
            Ok(
                match protos::tendermint::types::SignedMsgType::try_from(value)
                    .map_err(|_| UnknownEnumVariant(value))?
                {
                    protos::tendermint::types::SignedMsgType::Unknown => Self::Unknown,
                    protos::tendermint::types::SignedMsgType::Prevote => Self::Prevote,
                    protos::tendermint::types::SignedMsgType::Precommit => Self::Precommit,
                    protos::tendermint::types::SignedMsgType::Proposal => Self::Proposal,
                },
            )
        }
    }
}
