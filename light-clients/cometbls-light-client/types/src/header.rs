use serde::{Deserialize, Serialize};
use unionlabs::ibc::core::client::height::Height;

use crate::light_header::LightHeader;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub signed_header: LightHeader,
    pub trusted_height: Height,
    #[serde(with = "::serde_utils::hex_string")]
    pub zero_knowledge_proof: Vec<u8>,
}

#[cfg(feature = "proto")]
pub mod proto {
    use unionlabs::{errors::MissingField, impl_proto_via_try_from_into, required};

    use crate::{header::Header, light_header};

    impl_proto_via_try_from_into!(Header => protos::union::ibc::lightclients::cometbls::v1::Header);

    impl From<Header> for protos::union::ibc::lightclients::cometbls::v1::Header {
        fn from(value: Header) -> Self {
            Self {
                signed_header: Some(value.signed_header.into()),
                trusted_height: Some(value.trusted_height.into()),
                zero_knowledge_proof: value.zero_knowledge_proof,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, thiserror::Error)]
    pub enum Error {
        #[error(transparent)]
        MissingField(#[from] MissingField),
        #[error("invalid signed header")]
        SignedHeader(#[from] light_header::proto::Error),
    }

    impl TryFrom<protos::union::ibc::lightclients::cometbls::v1::Header> for Header {
        type Error = Error;

        fn try_from(
            value: protos::union::ibc::lightclients::cometbls::v1::Header,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                signed_header: required!(value.signed_header)?.try_into()?,
                trusted_height: required!(value.trusted_height)?.into(),
                zero_knowledge_proof: value.zero_knowledge_proof,
            })
        }
    }
}

#[cfg(feature = "ethabi")]
pub mod ethabi {

    use alloy::sol_types::SolValue;
    use unionlabs::{
        bounded::{BoundedI32, BoundedI64, BoundedIntError},
        encoding::{Decode, Encode, EthAbi},
        google::protobuf::timestamp::Timestamp,
        ibc::core::client::height::Height,
        TryFromEthAbiBytesErrorAlloy,
    };

    use crate::{Header, LightHeader};

    alloy::sol! {
        struct SolSignedHeader {
            uint64 height;
            uint64 secs;
            uint64 nanos;
            bytes32 validatorsHash;
            bytes32 nextValidatorsHash;
            bytes32 appHash;
        }

        struct SolHeader {
            SolSignedHeader signedHeader;
            uint64 trustedHeight;
            bytes zeroKnowledgeProof;
        }
    }

    impl Encode<EthAbi> for Header {
        fn encode(self) -> Vec<u8> {
            SolHeader {
                signedHeader: SolSignedHeader {
                    height: self
                        .signed_header
                        .height
                        .inner()
                        .try_into()
                        .expect("value is >= 0 and <= i64::MAX; qed;"),
                    secs: self
                        .signed_header
                        .time
                        .seconds
                        .inner()
                        // TODO: Figure out a better way to represent these types other than by saturating
                        .clamp(0, i64::MAX)
                        .try_into()
                        .expect("value is >= 0 and <= i64::MAX; qed;"),
                    nanos: self
                        .signed_header
                        .time
                        .nanos
                        .inner()
                        .try_into()
                        .expect("value is >= 0 and <= i32::MAX; qed;"),
                    validatorsHash: self.signed_header.validators_hash.into(),
                    nextValidatorsHash: self.signed_header.next_validators_hash.into(),
                    appHash: self.signed_header.app_hash.into(),
                },
                trustedHeight: self.trusted_height.revision_height,
                zeroKnowledgeProof: self.zero_knowledge_proof.into(),
            }
            .abi_encode()
        }
    }

    impl Decode<EthAbi> for Header {
        type Error = TryFromEthAbiBytesErrorAlloy<Error>;

        fn decode(bytes: &[u8]) -> Result<Self, Self::Error> {
            let header = SolHeader::abi_decode(bytes, true)?;

            Ok(Self {
                signed_header: LightHeader {
                    height: BoundedI64::new(header.signedHeader.height)
                        .map_err(Error::Height)
                        .map_err(TryFromEthAbiBytesErrorAlloy::Convert)?,
                    time: Timestamp {
                        seconds: BoundedI64::new(header.signedHeader.secs)
                            .map_err(Error::Secs)
                            .map_err(TryFromEthAbiBytesErrorAlloy::Convert)?,
                        nanos: BoundedI32::new(header.signedHeader.nanos)
                            .map_err(Error::Nanos)
                            .map_err(TryFromEthAbiBytesErrorAlloy::Convert)?,
                    },
                    validators_hash: header.signedHeader.validatorsHash.into(),
                    next_validators_hash: header.signedHeader.nextValidatorsHash.into(),
                    app_hash: header.signedHeader.appHash.into(),
                },
                trusted_height: Height {
                    revision_number: 0,
                    revision_height: header.trustedHeight,
                },
                zero_knowledge_proof: header.zeroKnowledgeProof.into(),
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, thiserror::Error)]
    pub enum Error {
        #[error("invalid height")]
        Height(#[source] BoundedIntError<i64, u64>),
        #[error("invalid secs")]
        Secs(#[source] BoundedIntError<i64, u64>),
        #[error("invalid nanos")]
        Nanos(#[source] BoundedIntError<i32, u64>),
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use serde_utils::Hex;
    use unionlabs::{
        encoding::{Bcs, DecodeAs, EncodeAs},
        hash::H256,
    };

    use super::*;

    #[test]
    fn bcs() {
        let bz = hex!("630e0000000000002239df6600000000406dcb0b2f4975ab7e75a677f43efebf53e0ec05460d2cf55506ad08d6b05254f96a500d2f4975ab7e75a677f43efebf53e0ec05460d2cf55506ad08d6b05254f96a500dfc45a4f41582fbfc1e3b7f79b0fd39d5f738133e68fdd47468fb037b0a44c9da01000000000000001d0900000000000080031c9bc15a0c4541aff1d12780d6cf4ae2bdc6e3afafceae9d4fa36209fa323b68002e9c77c223d830e5df6a80cdd683f0986353933ee3179970fccc5d893219d30726f3b8c0dbe630b815b01b5557228a0dfeb0e0435bb0d15d1ccff7f6133fc110937d9fceee2f9052468c198fafeca89d524142a0efa9dc4df445853ce617302059018fef03dc34456ad201d2a5420a7d1c8fac57cb48cbe6709ac4da27d1eb250f73eab007d26cbff41ceb4564ab1cdfa83e9ee88be4f816dc841bbf2e90c80186ad9437fce7655c71b54addae1ccea429da3edba3232d073cb7e89ff2d27218556f1af0c446962ace932f637279dd0ad3ef1501fb6da39d5f68282f54bcf6094999672f3d8cbbf0409aef1048175ffff50b03a5154016d307a2ef425ffee509cd447b22ce6331c7a3473b2c6da1f9d550e8c3ab19bde65e699e07f4f2886c03ec4ff2faa0e342de7ac5daf32025acd6070c19ed8b007c121db0d955472c7d2e38d5a943d15bc902613029e4baa8c26034ff280e3a4d5468fcd6745afe53b5");

        let header = Header {
            signed_header: LightHeader {
                height: 3683.try_into().unwrap(),
                time: "2024-09-09T18:06:26.197881152Z".parse().unwrap(),
                validators_hash: H256::new(hex!(
                    "2f4975ab7e75a677f43efebf53e0ec05460d2cf55506ad08d6b05254f96a500d"
                )),
                next_validators_hash: H256::new(hex!(
                    "2f4975ab7e75a677f43efebf53e0ec05460d2cf55506ad08d6b05254f96a500d"
                )),
                app_hash: H256::new(hex!(
                    "fc45a4f41582fbfc1e3b7f79b0fd39d5f738133e68fdd47468fb037b0a44c9da"
                )),
            },
            trusted_height: Height {
                revision_number: 1,
                revision_height: 2333,
            },
            zero_knowledge_proof: hex!("1c9bc15a0c4541aff1d12780d6cf4ae2bdc6e3afafceae9d4fa36209fa323b68002e9c77c223d830e5df6a80cdd683f0986353933ee3179970fccc5d893219d30726f3b8c0dbe630b815b01b5557228a0dfeb0e0435bb0d15d1ccff7f6133fc110937d9fceee2f9052468c198fafeca89d524142a0efa9dc4df445853ce617302059018fef03dc34456ad201d2a5420a7d1c8fac57cb48cbe6709ac4da27d1eb250f73eab007d26cbff41ceb4564ab1cdfa83e9ee88be4f816dc841bbf2e90c80186ad9437fce7655c71b54addae1ccea429da3edba3232d073cb7e89ff2d27218556f1af0c446962ace932f637279dd0ad3ef1501fb6da39d5f68282f54bcf6094999672f3d8cbbf0409aef1048175ffff50b03a5154016d307a2ef425ffee509cd447b22ce6331c7a3473b2c6da1f9d550e8c3ab19bde65e699e07f4f2886c03ec4ff2faa0e342de7ac5daf32025acd6070c19ed8b007c121db0d955472c7d2e38d5a943d15bc902613029e4baa8c26034ff280e3a4d5468fcd6745afe53b5").to_vec(),
        };

        dbg!(&header);

        let header_bz = header.encode_as::<Bcs>();

        dbg!(Hex(&header_bz));

        let header = Header::decode_as::<Bcs>(&bz).unwrap();

        dbg!(header);
    }
}
