use cosmwasm_std::{Deps, DepsMut, Env};
use ethereum_verifier::{
    utils::{
        compute_slot_at_timestamp, compute_sync_committee_period_at_slot,
        compute_timestamp_at_slot, validate_signature_supermajority,
    },
    verify::{
        validate_light_client_update, verify_account_storage_root, verify_storage_absence,
        verify_storage_proof,
    },
};
use ics008_wasm_client::{
    storage_utils::{
        read_client_state, read_consensus_state, read_subject_client_state,
        read_substitute_client_state, read_substitute_consensus_state, save_client_state,
        save_consensus_state, save_subject_client_state, save_subject_consensus_state,
        update_client_state,
    },
    IbcClient, IbcClientError, Status, StorageState, FROZEN_HEIGHT, ZERO_HEIGHT,
};
use serde_utils::to_hex;
use sha2::{Digest, Sha256};
use unionlabs::{
    cosmwasm::wasm::union::custom_query::UnionCustomQuery,
    encoding::{DecodeAs, Proto},
    ensure,
    ethereum::{ibc_commitment_key_v2, keccak256},
    hash::H256,
    ibc::{
        core::{
            client::{genesis_metadata::GenesisMetadata, height::Height},
        },
        lightclients::ethereum::{
            client_state::ClientState, consensus_state::ConsensusState, header::Header,
            misbehaviour::Misbehaviour, storage_proof::StorageProof,
        },
    },
    uint::U256,
};

use crate::{
    consensus_state::TrustedConsensusState,
    context::LightClientContext,
    custom_query::VerificationContext,
    errors::{CanonicalizeStoredValueError, Error, InvalidCommitmentKey, StoredValueMismatch},
    Config,
};

type WasmClientState = unionlabs::ibc::lightclients::wasm::client_state::ClientState<ClientState>;
type WasmConsensusState =
    unionlabs::ibc::lightclients::wasm::consensus_state::ConsensusState<ConsensusState>;

pub struct EthereumLightClient;

impl IbcClient for EthereumLightClient {
    type Error = Error;

    type CustomQuery = UnionCustomQuery;

    type Header = Header<Config>;

    type Misbehaviour = Misbehaviour<Config>;

    type ClientState = ClientState;

    type ConsensusState = ConsensusState;

    type Encoding = Proto;

    fn verify_membership(
        deps: Deps<Self::CustomQuery>,
        height: Height,
        _delay_time_period: u64,
        _delay_block_period: u64,
        proof: Vec<u8>,
        path: Vec<Vec<u8>>,
        value: ics008_wasm_client::StorageState,
    ) -> Result<(), IbcClientError<Self>> {
        let consensus_state: WasmConsensusState =
            read_consensus_state(deps, &height)?.ok_or(Error::ConsensusStateNotFound(height))?;
        let client_state: WasmClientState = read_client_state(deps)?;

        let path = path.first().ok_or(Error::EmptyIbcPath)?;

        // This storage root is verified during the header update, so we don't need to verify it again.
        let storage_root = consensus_state.data.storage_root;

        let storage_proof =
            StorageProof::decode_as::<Proto>(&proof).map_err(Error::StorageProofDecode)?;

        match value {
            StorageState::Occupied(value) => do_verify_membership(
                path.to_vec(),
                storage_root,
                client_state.data.ibc_commitment_slot,
                storage_proof,
                value,
            )?,
            StorageState::Empty => do_verify_non_membership(
                path.to_vec(),
                storage_root,
                client_state.data.ibc_commitment_slot,
                storage_proof,
            )?,
        }

        Ok(())
    }

    fn verify_header(
        deps: Deps<Self::CustomQuery>,
        env: Env,
        header: Self::Header,
    ) -> Result<(), IbcClientError<Self>> {
        let trusted_sync_committee = header.trusted_sync_committee;
        let wasm_consensus_state =
            read_consensus_state(deps, &trusted_sync_committee.trusted_height)?.ok_or(
                Error::ConsensusStateNotFound(trusted_sync_committee.trusted_height),
            )?;

        let trusted_consensus_state = TrustedConsensusState::new(
            deps,
            wasm_consensus_state.data,
            trusted_sync_committee.sync_committee,
        )?;

        let wasm_client_state = read_client_state(deps)?;
        let ctx = LightClientContext::new(&wasm_client_state.data, trusted_consensus_state);

        // NOTE(aeryz): Ethereum consensus-spec says that we should use the slot
        // at the current timestamp.
        let current_slot = compute_slot_at_timestamp::<Config>(
            wasm_client_state.data.genesis_time,
            env.block.time.seconds(),
        )
        .ok_or(Error::IntegerOverflow)?;

        validate_light_client_update::<LightClientContext<Config>, VerificationContext>(
            &ctx,
            header.consensus_update.clone(),
            current_slot,
            wasm_client_state.data.genesis_validators_root,
            VerificationContext { deps },
        )
        .map_err(Error::ValidateLightClient)?;

        // check whether at least 2/3 of the sync committee signed
        ensure(
            validate_signature_supermajority::<Config>(
                &header.consensus_update.sync_aggregate.sync_committee_bits,
            ),
            Error::NotEnoughSignatures,
        )?;

        let proof_data = header.account_update.account_proof;

        verify_account_storage_root(
            header.consensus_update.attested_header.execution.state_root,
            &wasm_client_state.data.ibc_contract_address,
            &proof_data.proof,
            &proof_data.storage_root,
        )
        .map_err(|err| {
            Error::TestVerifyStorageProof(
                err,
                to_hex(
                    &header
                        .consensus_update
                        .attested_header
                        .execution
                        .state_root
                        .into_bytes(),
                ),
                to_hex(&wasm_client_state.data.ibc_contract_address.into_bytes()),
                to_hex(&proof_data.proof.first().unwrap()),
                to_hex(&proof_data.storage_root.into_bytes()),
            )
        });

        Ok(())
    }

    fn verify_misbehaviour(
        deps: Deps<Self::CustomQuery>,
        env: Env,
        misbehaviour: Self::Misbehaviour,
    ) -> Result<(), IbcClientError<Self>> {
        // There is no point to check for misbehaviour when the headers are not for the same height
        // TODO(aeryz): this will be `finalized_header` when we implement tracking justified header
        let (slot_1, slot_2) = (
            misbehaviour.update_1.attested_header.beacon.slot,
            misbehaviour.update_2.attested_header.beacon.slot,
        );
        ensure(
            slot_1 == slot_2,
            Error::MisbehaviourCannotExist(slot_1, slot_2),
        )?;

        let trusted_sync_committee = misbehaviour.trusted_sync_committee;
        let wasm_consensus_state =
            read_consensus_state(deps, &trusted_sync_committee.trusted_height)?.ok_or(
                Error::ConsensusStateNotFound(trusted_sync_committee.trusted_height),
            )?;

        let trusted_consensus_state = TrustedConsensusState::new(
            deps,
            wasm_consensus_state.data,
            trusted_sync_committee.sync_committee,
        )?;

        let wasm_client_state = read_client_state(deps)?;
        let ctx = LightClientContext::new(&wasm_client_state.data, trusted_consensus_state);

        let current_slot = compute_slot_at_timestamp::<Config>(
            wasm_client_state.data.genesis_time,
            env.block.time.seconds(),
        )
        .ok_or(Error::IntegerOverflow)?;

        // Make sure both headers would have been accepted by the light client
        validate_light_client_update::<LightClientContext<Config>, VerificationContext>(
            &ctx,
            misbehaviour.update_1,
            current_slot,
            wasm_client_state.data.genesis_validators_root,
            VerificationContext { deps },
        )
        .map_err(Error::ValidateLightClient)?;

        validate_light_client_update::<LightClientContext<Config>, VerificationContext>(
            &ctx,
            misbehaviour.update_2,
            current_slot,
            wasm_client_state.data.genesis_validators_root,
            VerificationContext { deps },
        )
        .map_err(Error::ValidateLightClient)?;

        Ok(())
    }

    fn update_state(
        mut deps: DepsMut<Self::CustomQuery>,
        _env: Env,
        header: Self::Header,
    ) -> Result<Vec<Height>, IbcClientError<Self>> {
        let trusted_sync_committee = header.trusted_sync_committee;
        let trusted_height = trusted_sync_committee.trusted_height;

        let mut consensus_state: WasmConsensusState =
            read_consensus_state(deps.as_ref(), &trusted_sync_committee.trusted_height)?.ok_or(
                Error::ConsensusStateNotFound(trusted_sync_committee.trusted_height),
            )?;

        let mut client_state: WasmClientState = read_client_state(deps.as_ref())?;
        let consensus_update = header.consensus_update;
        let account_update = header.account_update;

        let store_period =
            compute_sync_committee_period_at_slot::<Config>(consensus_state.data.slot);
        let update_finalized_period = compute_sync_committee_period_at_slot::<Config>(
            consensus_update.attested_header.beacon.slot,
        );

        if let Some(ref next_sync_committee) = consensus_state.data.next_sync_committee {
            // sync committee only changes when the period change
            if update_finalized_period == store_period + 1 {
                consensus_state.data.current_sync_committee = *next_sync_committee;
                consensus_state.data.next_sync_committee = consensus_update
                    .next_sync_committee
                    .map(|c| c.aggregate_pubkey);
            }
        } else {
            // if the finalized period is greater, we have to have a next sync committee
            ensure(
                update_finalized_period == store_period,
                Error::StorePeriodMustBeEqualToFinalizedPeriod,
            )?;
            consensus_state.data.next_sync_committee = consensus_update
                .next_sync_committee
                .map(|c| c.aggregate_pubkey);
        }

        // Some updates can be only for updating the sync committee, therefore the slot number can be
        // smaller. We don't want to save a new state if this is the case.
        let updated_height = core::cmp::max(
            trusted_height.revision_height,
            consensus_update.attested_header.beacon.slot,
        );

        if consensus_update.attested_header.beacon.slot > consensus_state.data.slot {
            consensus_state.data.slot = consensus_update.attested_header.beacon.slot;

            consensus_state.data.state_root = consensus_update.attested_header.execution.state_root;
            consensus_state.data.storage_root = account_update.account_proof.storage_root;

            // Normalize to nanoseconds to be ibc-go compliant
            consensus_state.data.timestamp = compute_timestamp_at_slot::<Config>(
                client_state.data.genesis_time,
                consensus_update.attested_header.beacon.slot,
            ) * 1_000_000_000;

            if client_state.data.latest_slot < consensus_update.attested_header.beacon.slot {
                client_state.data.latest_slot = consensus_update.attested_header.beacon.slot;
                update_client_state::<Self>(deps.branch(), client_state, updated_height);
            }
        }

        let updated_height = Height {
            revision_number: trusted_height.revision_number,
            revision_height: updated_height,
        };

        save_consensus_state::<Self>(deps, consensus_state, &updated_height);

        Ok(vec![updated_height])
    }

    fn update_state_on_misbehaviour(
        deps: DepsMut<Self::CustomQuery>,
        _env: Env,
        _client_message: Vec<u8>,
    ) -> Result<(), IbcClientError<Self>> {
        let mut client_state: WasmClientState = read_client_state(deps.as_ref())?;
        client_state.data.frozen_height = FROZEN_HEIGHT;
        save_client_state::<Self>(deps, client_state);

        Ok(())
    }

    fn check_for_misbehaviour_on_header(
        deps: Deps<Self::CustomQuery>,
        header: Self::Header,
    ) -> Result<bool, IbcClientError<Self>> {
        let height = Height {
            revision_number: 0,
            revision_height: header.consensus_update.attested_header.beacon.slot,
        };

        if let Some(consensus_state) = read_consensus_state::<Self>(deps, &height)? {
            // New header is given with the same height but the storage roots don't match.
            if consensus_state.data.storage_root != header.account_update.account_proof.storage_root
                || consensus_state.data.slot != header.consensus_update.attested_header.beacon.slot
            {
                return Ok(true);
            }

            // NOTE(aeryz): we don't check the timestamp here since it is calculated based on the
            // thn slot and we already check the slot.

            // NOTE(aeryz): we don't check the next sync committee because it's not being signed with
            // a header. so it should be an error during the state update not a misbehaviour.
        }

        Ok(false)
    }

    fn check_for_misbehaviour_on_misbehaviour(
        _deps: Deps<Self::CustomQuery>,
        misbehaviour: Self::Misbehaviour,
    ) -> Result<bool, IbcClientError<Self>> {
        if misbehaviour.update_1.attested_header.beacon.slot
            == misbehaviour.update_2.attested_header.beacon.slot
        {
            // TODO(aeryz): this will be the finalized header when we implement justified
            // This ensures that there are no conflicting justified/finalized headers at the same height
            if misbehaviour.update_1.attested_header != misbehaviour.update_2.attested_header {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn verify_upgrade_and_update_state(
        _deps: DepsMut<Self::CustomQuery>,
        _upgrade_client_state: Self::ClientState,
        _upgrade_consensus_state: Self::ConsensusState,
        _proof_upgrade_client: Vec<u8>,
        _proof_upgrade_consensus_state: Vec<u8>,
    ) -> Result<(), IbcClientError<Self>> {
        Err(Error::Unimplemented.into())
    }

    fn migrate_client_store(
        mut deps: DepsMut<Self::CustomQuery>,
    ) -> Result<(), IbcClientError<Self>> {
        let subject_client_state: WasmClientState = read_subject_client_state(deps.as_ref())?;
        let substitute_client_state: WasmClientState = read_substitute_client_state(deps.as_ref())?;

        ensure(
            substitute_client_state.data.frozen_height == ZERO_HEIGHT,
            Error::SubstituteClientFrozen,
        )?;

        ensure(
            migrate_check_allowed_fields(&subject_client_state.data, &substitute_client_state.data),
            Error::MigrateFieldsChanged,
        )?;

        let substitute_consensus_state: WasmConsensusState =
            read_substitute_consensus_state(deps.as_ref(), &substitute_client_state.latest_height)?
                .ok_or(Error::ConsensusStateNotFound(
                    substitute_client_state.latest_height,
                ))?;

        save_subject_consensus_state::<Self>(
            deps.branch(),
            substitute_consensus_state,
            &substitute_client_state.latest_height,
        );

        let scs = substitute_client_state.data;
        save_subject_client_state::<Self>(
            deps,
            WasmClientState {
                data: ClientState {
                    chain_id: scs.chain_id,
                    min_sync_committee_participants: scs.min_sync_committee_participants,
                    fork_parameters: scs.fork_parameters,
                    latest_slot: scs.latest_slot,
                    ibc_commitment_slot: scs.ibc_commitment_slot,
                    ibc_contract_address: scs.ibc_contract_address,
                    frozen_height: ZERO_HEIGHT,
                    ..subject_client_state.data
                },
                latest_height: substitute_client_state.latest_height,
                checksum: subject_client_state.checksum,
            },
        );

        Ok(())
    }

    fn status(deps: Deps<Self::CustomQuery>, _: &Env) -> Result<Status, IbcClientError<Self>> {
        let client_state: WasmClientState = read_client_state(deps)?;

        if client_state.data.frozen_height != ZERO_HEIGHT {
            return Ok(Status::Frozen);
        }

        Ok(Status::Active)
    }

    fn export_metadata(
        _deps: Deps<Self::CustomQuery>,
        _env: &Env,
    ) -> Result<Vec<GenesisMetadata>, IbcClientError<Self>> {
        Ok(Vec::new())
    }

    fn timestamp_at_height(
        deps: Deps<Self::CustomQuery>,
        height: Height,
    ) -> Result<u64, IbcClientError<Self>> {
        Ok(read_consensus_state::<Self>(deps, &height)?
            .ok_or(Error::ConsensusStateNotFound(height))?
            .data
            .timestamp)
    }
}

fn migrate_check_allowed_fields(
    subject_client_state: &ClientState,
    substitute_client_state: &ClientState,
) -> bool {
    subject_client_state.genesis_time == substitute_client_state.genesis_time
        && subject_client_state.genesis_validators_root
            == substitute_client_state.genesis_validators_root
        && subject_client_state.seconds_per_slot == substitute_client_state.seconds_per_slot
        && subject_client_state.slots_per_epoch == substitute_client_state.slots_per_epoch
        && subject_client_state.epochs_per_sync_committee_period
            == substitute_client_state.epochs_per_sync_committee_period
}

pub fn do_verify_membership(
    path: Vec<u8>,
    storage_root: H256,
    ibc_commitment_slot: U256,
    storage_proof: StorageProof,
    raw_value: Vec<u8>,
) -> Result<(), Error> {
    check_commitment_key(path, ibc_commitment_slot, storage_proof.key)?;

    let proof_value = storage_proof.value.to_be_bytes();

    if raw_value != proof_value {
        return Err(StoredValueMismatch {
            expected: serde_utils::to_hex(raw_value),
            stored: serde_utils::to_hex(proof_value),
        }
        .into());
    }

    verify_storage_proof(
        storage_root,
        storage_proof.key,
        &rlp::encode(&storage_proof.value),
        &storage_proof.proof,
    )
    .map_err(Error::VerifyStorageProof)
}

// this is required because ibc-go requires the client state to be a protobuf Any, even though
// the counterparty (ethereum in this case) stores it as raw bytes. this will no longer be
// required with ibc-go v9.
pub fn canonicalize_stored_value(
    _path: String,
    raw_value: Vec<u8>,
) -> Result<Vec<u8>, CanonicalizeStoredValueError> {
    // let path = path
    //     .parse::<Path>()
    //     .map_err(|_| CanonicalizeStoredValueError::UnknownIbcPath(path))?;

    // let canonical_value = match path {
    //     // proto(any<cometbls>) -> ethabi(cometbls)
    //     Path::ClientState(_) => {
    //         Any::<cometbls::client_state::ClientState>::decode_as::<Proto>(raw_value.as_ref())
    //             .map_err(CanonicalizeStoredValueError::CometblsClientStateDecode)?
    //             .0
    //             .encode_as::<EthAbi>()
    //     }
    //     // proto(any<wasm<cometbls>>) -> ethabi(cometbls)
    //     Path::ClientConsensusState(_) => Any::<
    //         wasm::consensus_state::ConsensusState<cometbls::consensus_state::ConsensusState>,
    //     >::decode_as::<Proto>(raw_value.as_ref())
    //     .map_err(CanonicalizeStoredValueError::CometblsConsensusStateDecode)?
    //     .0
    //     .data
    //     .encode_as::<EthAbi>(),
    //     _ => raw_value,
    // };

    Ok(raw_value)
}

/// Verifies that no value is committed at `path` in the counterparty light client's storage.
pub fn do_verify_non_membership(
    path: Vec<u8>,
    storage_root: H256,
    ibc_commitment_slot: U256,
    storage_proof: StorageProof,
) -> Result<(), Error> {
    check_commitment_key(path, ibc_commitment_slot, storage_proof.key)?;

    if verify_storage_absence(storage_root, storage_proof.key, &storage_proof.proof)
        .map_err(Error::VerifyStorageAbsence)?
    {
        Ok(())
    } else {
        Err(Error::CounterpartyStorageNotNil)
    }
}

pub fn check_commitment_key(
    path: Vec<u8>,
    ibc_commitment_slot: U256,
    key: U256,
) -> Result<(), InvalidCommitmentKey> {
    let expected_commitment_key = ibc_commitment_key_v2(path, ibc_commitment_slot);

    // Data MUST be stored to the commitment path that is defined in ICS23.
    if expected_commitment_key != key {
        Err(InvalidCommitmentKey {
            expected: expected_commitment_key,
            found: key,
        })
    } else {
        Ok(())
    }
}

#[cfg(all(test, feature = "mainnet"))]
mod test {
    use std::{cmp::Ordering, fs, marker::PhantomData};

    use cosmwasm_std::{
        testing::{mock_env, MockApi, MockQuerier, MockStorage},
        Binary, OwnedDeps, Timestamp,
    };

    use ics008_wasm_client::storage_utils::{
        consensus_db_key, read_subject_consensus_state, HOST_CLIENT_STATE_KEY,
        SUBJECT_CLIENT_STORE_PREFIX, SUBSTITUTE_CLIENT_STORE_PREFIX,
    };
    use serde::Deserialize;
    use unionlabs::{
        encoding::{Encode, Proto, EncodeAs},
        ethereum::config::{Mainnet, Minimal},
        google::protobuf::any::Any,
        ibc::{core::connection::connection_end::ConnectionEnd, lightclients::ethereum},
    };

    use super::*;
    use crate::client::EthereumLightClient;
    use crate::{client::test_utils::custom_query_handler, errors::Error};

    #[derive(Deserialize)]
    struct MembershipTest {
        #[serde(with = "unionlabs::uint::u256_big_endian_hex")]
        key: U256,
        #[serde(with = "unionlabs::uint::u256_big_endian_hex")]
        value: U256,
        #[serde(with = "::serde_utils::hex_string_list")]
        proof: Vec<Vec<u8>>,
        storage_root: H256,
        commitment_path: String,
        commitments_map_slot: U256,
        #[serde(with = "::serde_utils::hex_string")]
        expected_data: Vec<u8>,
    }

    const INITIAL_CONSENSUS_STATE_HEIGHT: Height = Height {
        revision_number: 0,
        revision_height: 3577152,
    };

    const INITIAL_SUBSTITUTE_CONSENSUS_STATE_HEIGHT: Height = Height {
        revision_number: 0,
        revision_height: 3577200,
    };

    lazy_static::lazy_static! {
        static ref UPDATES: Vec<ethereum::header::Header<Mainnet>> = {
            let mut update_files = vec![];
            for entry in fs::read_dir(UPDATES_DIR_PATH).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.file_name().is_some() {
                    update_files.push(path);
                }
            }

            update_files.sort_by(|lhs, rhs| {
                let lhs = lhs.file_name().unwrap().to_string_lossy().strip_suffix(".json").unwrap().to_string().parse::<u32>().unwrap();
                let rhs = rhs.file_name().unwrap().to_string_lossy().strip_suffix(".json").unwrap().to_string().parse().unwrap();
                if lhs > rhs {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            });

            let mut updates = vec![];
            let mut prev_height = 0;
            for f in update_files {
                let mut data: ethereum::header::Header<Mainnet>= serde_json::from_str(&fs::read_to_string(f).unwrap()).unwrap();
                if prev_height != 0 {
                    data.trusted_sync_committee.trusted_height.revision_height = prev_height;
                }
                prev_height = data.consensus_update.attested_header.beacon.slot;
                updates.push(data);
            }

            updates
        };
    }

    const UPDATES_DIR_PATH: &str = "src/test/updates/";

    //#[test]
    //fn query_status_returns_active() {
    //    let mut deps = OwnedDeps::<_, _, _, UnionCustomQuery> {
    //        storage: MockStorage::default(),
    //        api: MockApi::default(),
    //        querier: MockQuerier::<UnionCustomQuery>::new(&[])
    //            .with_custom_handler(custom_query_handler),
    //        custom_query_type: PhantomData,
    //    };
    //
    //    let wasm_client_state: WasmClientState =
    //        serde_json::from_str(include_str!("./test/client_state.json")).unwrap();
    //
    //    let wasm_consensus_state: WasmConsensusState =
    //        serde_json::from_str(include_str!("./test/consensus_state.json")).unwrap();
    //
    //    save_client_state::<EthereumLightClient>(deps.as_mut(), wasm_client_state);
    //
    //    save_consensus_state::<EthereumLightClient>(
    //        deps.as_mut(),
    //        wasm_consensus_state,
    //        &INITIAL_CONSENSUS_STATE_HEIGHT,
    //    );
    //
    //    let mut env = mock_env();
    //    env.block.time = Timestamp::from_seconds(0);
    //
    //    assert_eq!(
    //        EthereumLightClient::status(deps.as_ref(), &env),
    //        Ok(Status::Active)
    //    );
    //}

    //#[test]
    //fn query_status_returns_frozen() {
    //    let mut deps = OwnedDeps::<_, _, _, UnionCustomQuery> {
    //        storage: MockStorage::default(),
    //        api: MockApi::default(),
    //        querier: MockQuerier::<UnionCustomQuery>::new(&[])
    //            .with_custom_handler(custom_query_handler),
    //        custom_query_type: PhantomData,
    //    };
    //
    //    let mut wasm_client_state: WasmClientState =
    //        serde_json::from_str(include_str!("./test/client_state.json")).unwrap();
    //
    //    wasm_client_state.data.frozen_height = FROZEN_HEIGHT;
    //
    //    save_client_state::<EthereumLightClient>(deps.as_mut(), wasm_client_state);
    //
    //    assert_eq!(
    //        EthereumLightClient::status(deps.as_ref(), &mock_env()),
    //        Ok(Status::Frozen)
    //    );
    //}
    //
    //#[test]
    //fn verify_and_update_header_works_with_good_data() {
    //    let mut deps = OwnedDeps::<_, _, _, UnionCustomQuery> {
    //        storage: MockStorage::default(),
    //        api: MockApi::default(),
    //        querier: MockQuerier::<UnionCustomQuery>::new(&[])
    //            .with_custom_handler(custom_query_handler),
    //        custom_query_type: PhantomData,
    //    };
    //
    //    let wasm_client_state: WasmClientState =
    //        serde_json::from_str(include_str!("./test/client_state.json")).unwrap();
    //
    //    let wasm_consensus_state: WasmConsensusState =
    //        serde_json::from_str(include_str!("./test/consensus_state.json")).unwrap();
    //
    //    save_client_state::<EthereumLightClient>(deps.as_mut(), wasm_client_state);
    //    save_consensus_state::<EthereumLightClient>(
    //        deps.as_mut(),
    //        wasm_consensus_state,
    //        &INITIAL_CONSENSUS_STATE_HEIGHT,
    //    );
    //
    //    for update in &*UPDATES {
    //        let mut env = mock_env();
    //        env.block.time = cosmwasm_std::Timestamp::from_seconds(
    //            update.consensus_update.attested_header.execution.timestamp + 60 * 5,
    //        );
    //        EthereumLightClient::check_for_misbehaviour_on_header(deps.as_ref(), update.clone())
    //            .unwrap();
    //        EthereumLightClient::verify_header(deps.as_ref(), env.clone(), update.clone()).unwrap();
    //        EthereumLightClient::update_state(deps.as_mut(), env, update.clone()).unwrap();
    //        // Consensus state is saved to the updated height.
    //        if update.consensus_update.attested_header.beacon.slot
    //            > update.trusted_sync_committee.trusted_height.revision_height
    //        {
    //            // It's a finality update
    //            let wasm_consensus_state: WasmConsensusState =
    //                read_consensus_state::<EthereumLightClient>(
    //                    deps.as_ref(),
    //                    &Height {
    //                        revision_number: 0,
    //                        revision_height: update.consensus_update.attested_header.beacon.slot,
    //                    },
    //                )
    //                .unwrap()
    //                .unwrap();
    //            // Slot is updated.
    //            assert_eq!(
    //                wasm_consensus_state.data.slot,
    //                update.consensus_update.attested_header.beacon.slot
    //            );
    //            // Storage root is updated.
    //            assert_eq!(
    //                wasm_consensus_state.data.storage_root,
    //                update.account_update.account_proof.storage_root,
    //            );
    //            // Latest slot is updated.
    //            // TODO(aeryz): Add cases for `store_period == update_period` and `update_period == store_period + 1`
    //            let wasm_client_state: WasmClientState =
    //                read_client_state::<EthereumLightClient>(deps.as_ref()).unwrap();
    //            assert_eq!(
    //                wasm_client_state.data.latest_slot,
    //                update.consensus_update.attested_header.beacon.slot
    //            );
    //        } else {
    //            // It's a sync committee update
    //            let updated_height = core::cmp::max(
    //                update.trusted_sync_committee.trusted_height.revision_height,
    //                update.consensus_update.attested_header.beacon.slot,
    //            );
    //            let wasm_consensus_state: WasmConsensusState =
    //                read_consensus_state::<EthereumLightClient>(
    //                    deps.as_ref(),
    //                    &Height {
    //                        revision_number: 0,
    //                        revision_height: updated_height,
    //                    },
    //                )
    //                .unwrap()
    //                .unwrap();
    //
    //            assert_eq!(
    //                wasm_consensus_state.data.next_sync_committee.unwrap(),
    //                update
    //                    .consensus_update
    //                    .next_sync_committee
    //                    .clone()
    //                    .unwrap()
    //                    .aggregate_pubkey
    //            );
    //        }
    //    }
    //}

    #[allow(clippy::type_complexity)]
    fn prepare_test_data() -> (
        OwnedDeps<MockStorage, MockApi, MockQuerier<UnionCustomQuery>, UnionCustomQuery>,
        ethereum::header::Header<Mainnet>,
        Env,
    ) {
        let mut deps = OwnedDeps::<_, _, _, UnionCustomQuery> {
            storage: MockStorage::default(),
            api: MockApi::default(),
            querier: MockQuerier::<UnionCustomQuery>::new(&[])
                .with_custom_handler(custom_query_handler),
            custom_query_type: PhantomData,
        };

        let wasm_client_state: WasmClientState =
            serde_json::from_str(&fs::read_to_string("src/test/client_state.json").unwrap())
                .unwrap();

        let wasm_consensus_state: WasmConsensusState =
            serde_json::from_str(&fs::read_to_string("src/test/consensus_state.json").unwrap())
                .unwrap();

        save_client_state::<EthereumLightClient>(deps.as_mut(), wasm_client_state.clone());
        save_consensus_state::<EthereumLightClient>(
            deps.as_mut(),
            wasm_consensus_state.clone(),
            &wasm_client_state.latest_height,
        );

        let update = UPDATES[0].clone();

        let mut env = mock_env();
        env.block.time =
            cosmwasm_std::Timestamp::from_seconds(wasm_consensus_state.data.timestamp + 60 * 5);

        (deps, update, env)
    }

    //#[test]
    //fn verify_header_fails_when_sync_committee_aggregate_pubkey_is_incorrect() {
    //    let (deps, mut update, env) = prepare_test_data();
    //
    //    let mut pubkey = update
    //        .trusted_sync_committee
    //        .sync_committee
    //        .get()
    //        .aggregate_pubkey;
    //    pubkey.0[0] ^= u8::MAX;
    //    update
    //        .trusted_sync_committee
    //        .sync_committee
    //        .get_mut()
    //        .aggregate_pubkey = pubkey;
    //    assert!(EthereumLightClient::verify_header(deps.as_ref(), env, update).is_err());
    //}
    //
    //#[test]
    //fn verify_header_fails_when_finalized_header_execution_branch_merkle_is_invalid() {
    //    let (deps, mut update, env) = prepare_test_data();
    //    update.consensus_update.finalized_header.execution_branch[0].0[0] ^= u8::MAX;
    //    assert!(EthereumLightClient::verify_header(deps.as_ref(), env, update).is_err());
    //}
    //
    //#[test]
    //fn verify_header_fails_when_finality_branch_merkle_is_invalid() {
    //    let (deps, mut update, env) = prepare_test_data();
    //    update.consensus_update.finality_branch[0].0[0] ^= u8::MAX;
    //    assert!(EthereumLightClient::verify_header(deps.as_ref(), env, update).is_err());
    //}

    /*#[test]
    fn verify_header_fails_when_finalized_header_execution_branch_merkle_is_invalid() {
        let (deps, mut update, env) = prepare_test_data();
        update.consensus_update.finalized_header.execution_branch[0].get_mut()[0] ^= u8::MAX;
        assert!(EthereumLightClient::verify_header(deps.as_ref(), env, update).is_err());
    }

    #[test]
    fn verify_header_fails_when_finality_branch_merkle_is_invalid() {
        let (deps, mut update, env) = prepare_test_data();
        update.consensus_update.finality_branch[0].get_mut()[0] ^= u8::MAX;
        assert!(EthereumLightClient::verify_header(deps.as_ref(), env, update).is_err());
    }*/

    // TODO(aeryz): These won't work now since they now eth abi encoded
    // #[test]
    // fn membership_verification_works_for_client_state() {
    //     do_membership_test::<
    //         unionlabs::google::protobuf::any::Any<
    //             wasm::client_state::ClientState<cometbls::client_state::ClientState>,
    //         >,
    //     >("src/test/memberships/valid_client_state.json")
    //     .expect("Membership verification of client state failed");
    // }

    // #[test]
    // fn membership_verification_works_for_consensus_state() {
    //     do_membership_test::<
    //         unionlabs::google::protobuf::any::Any<
    //             wasm::consensus_state::ConsensusState<cometbls::consensus_state::ConsensusState>,
    //         >,
    //     >("src/test/memberships/valid_consensus_state.json")
    //     .expect("Membership verification of client state failed");
    // }

    #[test]
    fn gg() {
        let (deps, update, env) = prepare_test_data();
        let (proof, commitment_path, slot, storage_root, expected_data) =
            membership_data("src/test/memberships/gg_test.json");

        let mut merkle_path: Vec<Vec<u8>> = Vec::new();
        merkle_path.push(commitment_path);

        EthereumLightClient::verify_membership(
            deps.as_ref(),
            Height {
                revision_number: 0,
                revision_height: 5332,
            },
            0,
            0,
            proof,
            merkle_path,
            StorageState::Occupied(expected_data),
        )
        .unwrap();
    }

    #[test]
    fn header_encode_decode() {
        let base64_str = "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";

        let vec_u8 = base64::decode(base64_str).unwrap();
        let header_as_binary = Binary::from(vec_u8);

        let header =
            ethereum::header::Header::<Minimal>::decode_as::<Proto>(&header_as_binary).unwrap();

        println!("header: {:?}", header);

        assert!(true);
    }

    fn membership_data(path: &str) -> (Vec<u8>, Vec<u8>, U256, H256, Vec<u8>) {
        let data: MembershipTest =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

        let proof = StorageProof {
            key: data.key,
            value: data.value,
            proof: data.proof.into_iter().map(Into::into).collect(),
        };

        let proof_bz = StorageProof::encode_as::<Proto>(proof);

        (
            proof_bz,
            data.commitment_path.into_bytes(),
            data.commitments_map_slot,
            data.storage_root.as_ref().try_into().unwrap(),
            data.expected_data,
        )
    }

    /*fn do_membership_test<T: serde::de::DeserializeOwned + Encode<Proto>>(
        path: &str,
    ) -> Result<(), Error> {
        let (proof, commitment_path, slot, storage_root, expected_data) =
            membership_data::<T>(path);
        do_verify_membership(
            commitment_path,
            storage_root.as_ref().try_into().unwrap(),
            slot,
            proof,
            expected_data.encode_as::<Proto>(),
        )
    }

    #[test]
    fn membership_verification_works_for_connection_end() {
        do_membership_test::<ConnectionEnd>("src/test/memberships/valid_connection_end.json")
            .expect("Membership verification of client state failed");
    }

    #[test]
    fn membership_verification_fails_for_incorrect_proofs() {
        let (mut proof, commitment_path, slot, storage_root, connection_end) =
            membership_data::<ConnectionEnd>("src/test/memberships/valid_connection_end.json");

        let proofs = vec![
            {
                let mut proof = proof.clone();
                proof.key.0 .0[0] ^= u64::MAX;
                proof
            },
            {
                proof.proof[0][10] ^= u8::MAX;
                proof
            },
        ];

        for proof in proofs {
            assert!(do_verify_membership(
                commitment_path.clone(),
                storage_root,
                slot,
                proof,
                connection_end.clone().encode_as::<Proto>(),
            )
            .is_err());
        }
    }

    #[test]
    fn membership_verification_fails_for_incorrect_storage_root() {
        let (proof, commitment_path, slot, mut storage_root, connection_end) =
            membership_data::<ConnectionEnd>("src/test/memberships/valid_connection_end.json");

        storage_root.get_mut()[10] ^= u8::MAX;

        assert!(do_verify_membership(
            commitment_path,
            storage_root,
            slot,
            proof,
            connection_end.encode_as::<Proto>(),
        )
        .is_err());
    }

    #[test]
    fn membership_verification_fails_for_incorrect_data() {
        let (proof, commitment_path, slot, storage_root, mut connection_end) =
            membership_data::<ConnectionEnd>("src/test/memberships/valid_connection_end.json");

        connection_end.client_id =
            unionlabs::validated::Validated::new("08-client-1".into()).unwrap();

        assert!(do_verify_membership(
            commitment_path,
            storage_root,
            slot,
            proof,
            connection_end.encode_as::<Proto>(),
        )
        .is_err());
    }

    #[test]
    fn non_membership_verification_works() {
        let (proof, commitment_path, slot, storage_root, _) =
            membership_data::<()>("src/test/memberships/valid_non_membership_proof.json");

        do_verify_non_membership(commitment_path, storage_root, slot, proof)
            .expect("Membership verification of client state failed");
    }

    #[test]
    fn non_membership_verification_fails_when_value_not_empty() {
        let (proof, commitment_path, slot, storage_root, _) =
            membership_data::<ConnectionEnd>("src/test/memberships/valid_connection_end.json");
        assert_eq!(
            do_verify_non_membership(commitment_path, storage_root, slot, proof),
            Err(Error::CounterpartyStorageNotNil)
        );
    }

    #[test]
    fn update_state_on_misbehaviour_works() {
        let (mut deps, _, env) = prepare_test_data();

        EthereumLightClient::update_state_on_misbehaviour(deps.as_mut(), env.clone(), Vec::new())
            .unwrap();

        assert_eq!(
            EthereumLightClient::status(deps.as_ref(), &env),
            Ok(Status::Frozen)
        );
    }

    fn save_states_to_migrate_store(
        deps: DepsMut<UnionCustomQuery>,
        subject_client_state: &WasmClientState,
        substitute_client_state: &WasmClientState,
        subject_consensus_state: &WasmConsensusState,
        substitute_consensus_state: &WasmConsensusState,
    ) {
        deps.storage.set(
            format!("{SUBJECT_CLIENT_STORE_PREFIX}{HOST_CLIENT_STATE_KEY}").as_bytes(),
            &Any(subject_client_state.clone()).encode_as::<Proto>(),
        );
        deps.storage.set(
            format!(
                "{SUBJECT_CLIENT_STORE_PREFIX}{}",
                consensus_db_key(&INITIAL_CONSENSUS_STATE_HEIGHT)
            )
            .as_bytes(),
            &Any(subject_consensus_state.clone()).encode_as::<Proto>(),
        );
        deps.storage.set(
            format!("{SUBSTITUTE_CLIENT_STORE_PREFIX}{HOST_CLIENT_STATE_KEY}").as_bytes(),
            &Any(substitute_client_state.clone()).encode_as::<Proto>(),
        );
        deps.storage.set(
            format!(
                "{SUBSTITUTE_CLIENT_STORE_PREFIX}{}",
                consensus_db_key(&INITIAL_SUBSTITUTE_CONSENSUS_STATE_HEIGHT)
            )
            .as_bytes(),
            &Any(substitute_consensus_state.clone()).encode_as::<Proto>(),
        );
    }

    #[allow(clippy::type_complexity)]
    fn prepare_migrate_tests() -> (
        OwnedDeps<MockStorage, MockApi, MockQuerier<UnionCustomQuery>, UnionCustomQuery>,
        WasmClientState,
        WasmConsensusState,
        WasmClientState,
        WasmConsensusState,
    ) {
        (
            OwnedDeps::<_, _, _, UnionCustomQuery> {
                storage: MockStorage::default(),
                api: MockApi::default(),
                querier: MockQuerier::<UnionCustomQuery>::new(&[])
                    .with_custom_handler(custom_query_handler),
                custom_query_type: PhantomData,
            },
            serde_json::from_str(&fs::read_to_string("src/test/client_state.json").unwrap())
                .unwrap(),
            serde_json::from_str(&fs::read_to_string("src/test/consensus_state.json").unwrap())
                .unwrap(),
            serde_json::from_str(
                &fs::read_to_string("src/test/substitute_client_state.json").unwrap(),
            )
            .unwrap(),
            serde_json::from_str(
                &fs::read_to_string("src/test/substitute_consensus_state.json").unwrap(),
            )
            .unwrap(),
        )
    }*/

    /*#[test]
    fn migrate_client_store_works() {
        let (
            mut deps,
            mut wasm_client_state,
            wasm_consensus_state,
            substitute_wasm_client_state,
            substitute_wasm_consensus_state,
        ) = prepare_migrate_tests();

        wasm_client_state.data.frozen_height = FROZEN_HEIGHT;

        save_states_to_migrate_store(
            deps.as_mut(),
            &wasm_client_state,
            &substitute_wasm_client_state,
            &wasm_consensus_state,
            &substitute_wasm_consensus_state,
        );

        EthereumLightClient::migrate_client_store(deps.as_mut()).unwrap();

        let wasm_client_state: WasmClientState =
            read_subject_client_state::<EthereumLightClient>(deps.as_ref()).unwrap();
        // we didn't miss updating any fields
        assert_eq!(wasm_client_state, substitute_wasm_client_state);
        // client is unfrozen
        assert_eq!(wasm_client_state.data.frozen_height, ZERO_HEIGHT);

        // the new consensus state is saved under the correct height
        assert_eq!(
            read_subject_consensus_state::<EthereumLightClient>(
                deps.as_ref(),
                &INITIAL_SUBSTITUTE_CONSENSUS_STATE_HEIGHT
            )
            .unwrap()
            .unwrap(),
            substitute_wasm_consensus_state
        )
    }

    #[test]
    fn migrate_client_store_fails_when_invalid_change() {
        let (
            mut deps,
            wasm_client_state,
            wasm_consensus_state,
            substitute_wasm_client_state,
            substitute_wasm_consensus_state,
        ) = prepare_migrate_tests();

        macro_rules! modify_fns {
            ($param:ident, $($m:expr), + $(,)?) => ([$(|$param: &mut ClientState| $m),+])
        }

        let modifications = modify_fns! { s,
            s.genesis_time ^= u64::MAX,
            s.genesis_validators_root.get_mut()[0] ^= u8::MAX,
            s.seconds_per_slot ^= u64::MAX,
            s.slots_per_epoch ^= u64::MAX,
            s.epochs_per_sync_committee_period ^= u64::MAX,
        };

        for m in modifications {
            let mut state = substitute_wasm_client_state.clone();
            m(&mut state.data);

            save_states_to_migrate_store(
                deps.as_mut(),
                &wasm_client_state,
                &state,
                &wasm_consensus_state,
                &substitute_wasm_consensus_state,
            );
            assert_eq!(
                EthereumLightClient::migrate_client_store(deps.as_mut()),
                Err(Error::MigrateFieldsChanged.into())
            );
        }
    }

    #[test]
    fn migrate_client_store_fails_when_substitute_client_frozen() {
        let (
            mut deps,
            wasm_client_state,
            wasm_consensus_state,
            mut substitute_wasm_client_state,
            substitute_wasm_consensus_state,
        ) = prepare_migrate_tests();

        substitute_wasm_client_state.data.frozen_height = FROZEN_HEIGHT;

        save_states_to_migrate_store(
            deps.as_mut(),
            &wasm_client_state,
            &substitute_wasm_client_state,
            &wasm_consensus_state,
            &substitute_wasm_consensus_state,
        );

        assert_eq!(
            EthereumLightClient::migrate_client_store(deps.as_mut()),
            Err(Error::SubstituteClientFrozen.into())
        );
    }*/
}

#[cfg(any(feature = "test-utils", test))]
pub mod test_utils {
    use cosmwasm_std::{testing::MockQuerierCustomHandlerResult, Binary, SystemResult};
    use ethereum_verifier::crypto::{
        eth_aggregate_public_keys_unchecked, fast_aggregate_verify_unchecked,
    };
    use unionlabs::{bls::BlsPublicKey, cosmwasm::wasm::union::custom_query::UnionCustomQuery};

    pub fn custom_query_handler(query: &UnionCustomQuery) -> MockQuerierCustomHandlerResult {
        match query {
            UnionCustomQuery::AggregateVerify {
                public_keys,
                message,
                signature,
            } => {
                let pubkeys: Vec<BlsPublicKey> = public_keys
                    .iter()
                    .map(|pk| pk.0.clone().try_into().unwrap())
                    .collect();

                let res = fast_aggregate_verify_unchecked(
                    pubkeys.iter().collect::<Vec<&BlsPublicKey>>().as_slice(),
                    message.as_ref(),
                    &signature.0.clone().try_into().unwrap(),
                );

                SystemResult::Ok(cosmwasm_std::ContractResult::Ok::<Binary>(
                    serde_json::to_vec(&res.is_ok()).unwrap().into(),
                ))
            }
            UnionCustomQuery::Aggregate { public_keys } => {
                let pubkey = eth_aggregate_public_keys_unchecked(
                    public_keys
                        .iter()
                        .map(|pk| pk.as_ref().try_into().unwrap())
                        .collect::<Vec<BlsPublicKey>>()
                        .as_slice(),
                )
                .unwrap();

                SystemResult::Ok(cosmwasm_std::ContractResult::Ok::<Binary>(
                    serde_json::to_vec(&Binary(pubkey.into())).unwrap().into(),
                ))
            }
        }
    }
}
