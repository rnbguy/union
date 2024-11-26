use chain_utils::ethereum::ETHEREUM_REVISION_NUMBER;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    types::ErrorObject,
    Extensions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_utils::Hex;
use tracing::instrument;
use unionlabs::{
    self,
    encoding::{DecodeAs, EncodeAs, Proto},
    ethereum::config::PresetBaseKind,
    google::protobuf::any::Any,
    ibc::{
        core::client::height::Height,
        lightclients::{
            ethereum::{self, header::UnboundedHeader, storage_proof::StorageProof},
            wasm,
        },
    },
    ErrorReporter,
};
use voyager_message::{
    core::{
        ChainId, ClientStateMeta, ClientType, ConsensusStateMeta, IbcGo08WasmClientMetadata,
        IbcInterface,
    },
    module::{ClientModuleInfo, ClientModuleServer},
    run_client_module_server, ClientModule, FATAL_JSONRPC_ERROR_CODE,
};
use voyager_vm::BoxDynError;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    run_client_module_server::<Module>().await
}

#[derive(Debug, Clone)]
pub struct Module {
    pub chain_spec: PresetBaseKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub chain_spec: PresetBaseKind,
}

impl ClientModule for Module {
    type Config = Config;

    async fn new(config: Self::Config, info: ClientModuleInfo) -> Result<Self, BoxDynError> {
        info.ensure_client_type(match config.chain_spec {
            PresetBaseKind::Minimal => ClientType::ETHEREUM_MINIMAL,
            PresetBaseKind::Mainnet => ClientType::ETHEREUM_MAINNET,
        })?;
        info.ensure_consensus_type(match config.chain_spec {
            PresetBaseKind::Minimal => ClientType::ETHEREUM_MINIMAL,
            PresetBaseKind::Mainnet => ClientType::ETHEREUM_MAINNET,
        })?;
        info.ensure_ibc_interface(IbcInterface::IBC_GO_V8_08_WASM)?;

        Ok(Self {
            chain_spec: config.chain_spec,
        })
    }
}

type SelfConsensusState =
    Any<wasm::consensus_state::ConsensusState<ethereum::consensus_state::ConsensusState>>;
type SelfClientState = Any<wasm::client_state::ClientState<ethereum::client_state::ClientState>>;

impl Module {
    pub fn decode_consensus_state(consensus_state: &[u8]) -> RpcResult<SelfConsensusState> {
        SelfConsensusState::decode_as::<Proto>(consensus_state).map_err(|err| {
            ErrorObject::owned(
                FATAL_JSONRPC_ERROR_CODE,
                format!("unable to decode consensus state: {}", ErrorReporter(err)),
                None::<()>,
            )
        })
    }

    pub fn decode_client_state(client_state: &[u8]) -> RpcResult<SelfClientState> {
        <SelfClientState>::decode_as::<Proto>(client_state).map_err(|err| {
            ErrorObject::owned(
                FATAL_JSONRPC_ERROR_CODE,
                format!("unable to decode client state: {}", ErrorReporter(err)),
                None::<()>,
            )
        })
    }

    pub fn make_height(revision_height: u64) -> Height {
        Height {
            revision_number: ETHEREUM_REVISION_NUMBER,
            revision_height,
        }
    }
}

#[async_trait]
impl ClientModuleServer for Module {
    #[instrument]
    async fn decode_client_state_meta(
        &self,
        _: &Extensions,
        client_state: Hex<Vec<u8>>,
    ) -> RpcResult<ClientStateMeta> {
        let cs = Module::decode_client_state(&client_state.0)?;

        Ok(ClientStateMeta {
            chain_id: ChainId::new(cs.0.data.chain_id.to_string()),
            height: Module::make_height(cs.0.data.latest_slot),
        })
    }

    #[instrument]
    async fn decode_consensus_state_meta(
        &self,
        _: &Extensions,
        consensus_state: Hex<Vec<u8>>,
    ) -> RpcResult<ConsensusStateMeta> {
        let cs = Module::decode_consensus_state(&consensus_state.0)?;

        Ok(ConsensusStateMeta {
            timestamp_nanos: cs.0.data.timestamp,
        })
    }

    #[instrument]
    async fn decode_client_state(
        &self,
        _: &Extensions,
        client_state: Hex<Vec<u8>>,
    ) -> RpcResult<Value> {
        Ok(serde_json::to_value(Module::decode_client_state(&client_state.0)?).unwrap())
    }

    #[instrument]
    async fn decode_consensus_state(
        &self,
        _: &Extensions,
        consensus_state: Hex<Vec<u8>>,
    ) -> RpcResult<Value> {
        Ok(serde_json::to_value(Module::decode_consensus_state(&consensus_state.0)?).unwrap())
    }

    #[instrument]
    async fn encode_client_state(
        &self,
        _: &Extensions,
        client_state: Value,
        metadata: Value,
    ) -> RpcResult<Hex<Vec<u8>>> {
        let IbcGo08WasmClientMetadata { checksum } =
            serde_json::from_value(metadata).map_err(|err| {
                ErrorObject::owned(
                    FATAL_JSONRPC_ERROR_CODE,
                    format!("unable to deserialize metadata: {}", ErrorReporter(err)),
                    None::<()>,
                )
            })?;

        serde_json::from_value::<ethereum::client_state::ClientState>(client_state)
            .map_err(|err| {
                ErrorObject::owned(
                    FATAL_JSONRPC_ERROR_CODE,
                    format!("unable to deserialize client state: {}", ErrorReporter(err)),
                    None::<()>,
                )
            })
            .map(|cs| {
                Any(wasm::client_state::ClientState {
                    latest_height: Module::make_height(cs.latest_slot),
                    data: cs,
                    checksum,
                })
                .encode_as::<Proto>()
            })
            .map(Hex)
    }

    #[instrument]
    async fn encode_consensus_state(
        &self,
        _: &Extensions,
        consensus_state: Value,
    ) -> RpcResult<Hex<Vec<u8>>> {
        serde_json::from_value::<ethereum::consensus_state::ConsensusState>(consensus_state)
            .map_err(|err| {
                ErrorObject::owned(
                    FATAL_JSONRPC_ERROR_CODE,
                    format!(
                        "unable to deserialize consensus state: {}",
                        ErrorReporter(err)
                    ),
                    None::<()>,
                )
            })
            .map(|cs| Any(wasm::consensus_state::ConsensusState { data: cs }).encode_as::<Proto>())
            .map(Hex)
    }

    #[instrument(skip_all)]
    async fn reencode_counterparty_client_state(
        &self,
        _: &Extensions,
        _client_state: Hex<Vec<u8>>,
        _client_type: ClientType<'static>,
    ) -> RpcResult<Hex<Vec<u8>>> {
        // match client_type.as_str() {
        //     ClientType::COMETBLS_GROTH16 => {
        //         Ok(Hex(Any(cometbls::client_state::ClientState::decode_as::<
        //             EthAbi,
        //         >(&client_state.0)
        //         .map_err(|err| {
        //             ErrorObject::owned(
        //                 FATAL_JSONRPC_ERROR_CODE,
        //                 format!("unable to decode client state: {}", ErrorReporter(err)),
        //                 Some(json!({
        //                     "client_type": client_type,
        //                 })),
        //             )
        //         })?)
        //         .encode_as::<Proto>()))
        //     }
        //     _ => Ok(client_state),
        // }

        todo!()
    }

    #[instrument(skip_all)]
    async fn reencode_counterparty_consensus_state(
        &self,
        _: &Extensions,
        _consensus_state: Hex<Vec<u8>>,
        _client_type: ClientType<'static>,
    ) -> RpcResult<Hex<Vec<u8>>> {
        // match client_type.as_str() {
        //     ClientType::COMETBLS_GROTH16 => Ok(Hex(Any(wasm::consensus_state::ConsensusState {
        //         data: cometbls::consensus_state::ConsensusState::decode_as::<EthAbi>(
        //             &consensus_state.0,
        //         )
        //         .map_err(|err| {
        //             ErrorObject::owned(
        //                 FATAL_JSONRPC_ERROR_CODE,
        //                 format!("unable to decode client state: {}", ErrorReporter(err)),
        //                 Some(json!({
        //                     "client_type": client_type,
        //                 })),
        //             )
        //         })?,
        //     })
        //     .encode_as::<Proto>())),
        //     _ => Ok(consensus_state),
        // }

        todo!()
    }

    #[instrument]
    async fn encode_header(&self, _: &Extensions, header: Value) -> RpcResult<Hex<Vec<u8>>> {
        serde_json::from_value::<UnboundedHeader>(header)
            .map_err(|err| {
                ErrorObject::owned(
                    FATAL_JSONRPC_ERROR_CODE,
                    format!("unable to deserialize header: {}", ErrorReporter(err)),
                    None::<()>,
                )
            })
            .map(|header| {
                Any(wasm::client_message::ClientMessage { data: header }).encode_as::<Proto>()
            })
            .map(Hex)
    }

    #[instrument]
    async fn encode_proof(&self, _: &Extensions, proof: Value) -> RpcResult<Hex<Vec<u8>>> {
        serde_json::from_value::<StorageProof>(proof)
            .map_err(|err| {
                ErrorObject::owned(
                    FATAL_JSONRPC_ERROR_CODE,
                    format!("unable to deserialize proof: {}", ErrorReporter(err)),
                    None::<()>,
                )
            })
            .map(|cs| cs.encode_as::<Proto>())
            .map(Hex)
    }
}
