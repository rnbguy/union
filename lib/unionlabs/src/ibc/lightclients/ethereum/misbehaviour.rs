use macros::model;

use crate::{
    errors::{required, MissingField},
    ethereum::config::{BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES, SYNC_COMMITTEE_SIZE},
    ibc::lightclients::ethereum::{
        light_client_update::{LightClientUpdate, TryFromLightClientUpdateError},
        trusted_sync_committee::{TrustedSyncCommittee, TryFromTrustedSyncCommitteeError},
    },
};

// trait alias would be nice
#[model(proto(
    raw(protos::union::ibc::lightclients::ethereum::v1::Misbehaviour),
    into,
    from
))]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Misbehaviour<C: SYNC_COMMITTEE_SIZE + BYTES_PER_LOGS_BLOOM + MAX_EXTRA_DATA_BYTES> {
    pub trusted_sync_committee: TrustedSyncCommittee<C>,
    pub update_1: LightClientUpdate<C>,
    pub update_2: LightClientUpdate<C>,
}

impl<C: SYNC_COMMITTEE_SIZE + BYTES_PER_LOGS_BLOOM + MAX_EXTRA_DATA_BYTES> From<Misbehaviour<C>>
    for protos::union::ibc::lightclients::ethereum::v1::Misbehaviour
{
    fn from(value: Misbehaviour<C>) -> Self {
        Self {
            trusted_sync_committee: Some(value.trusted_sync_committee.into()),
            update_1: Some(value.update_1.into()),
            update_2: Some(value.update_2.into()),
        }
    }
}

#[derive(Debug, PartialEq, Clone, thiserror::Error)]
pub enum TryFromMisbehaviourError {
    #[error(transparent)]
    MissingField(#[from] MissingField),
    #[error("invalid trusted_sync_committee")]
    TrustedSyncCommittee(#[source] TryFromTrustedSyncCommitteeError),
    #[error("invalid update1")]
    Update1(#[source] TryFromLightClientUpdateError),
    #[error("invalid update2")]
    Update2(#[source] TryFromLightClientUpdateError),
}

impl<C: SYNC_COMMITTEE_SIZE + BYTES_PER_LOGS_BLOOM + MAX_EXTRA_DATA_BYTES>
    TryFrom<protos::union::ibc::lightclients::ethereum::v1::Misbehaviour> for Misbehaviour<C>
{
    type Error = TryFromMisbehaviourError;

    fn try_from(
        value: protos::union::ibc::lightclients::ethereum::v1::Misbehaviour,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            trusted_sync_committee: required!(value.trusted_sync_committee)?
                .try_into()
                .map_err(TryFromMisbehaviourError::TrustedSyncCommittee)?,
            update_1: required!(value.update_1)?
                .try_into()
                .map_err(TryFromMisbehaviourError::Update1)?,
            update_2: required!(value.update_2)?
                .try_into()
                .map_err(TryFromMisbehaviourError::Update2)?,
        })
    }
}
