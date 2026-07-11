use crate::identity::{ControllerIdentity, IdentityError};
use control_protocol::crypto::{ed25519_signing_key_id, Sha256Digest};
use control_protocol::desired::{
    desired_state_transcript, verify_desired_state_signature, DesiredStateCryptoError,
};
use control_protocol::id::{
    ControllerInstanceId, NetworkId, NodeId, Revision, SigningKeyId, Timestamp,
};
use control_protocol::node::{
    DesiredStateDocument, DesiredUser, DesiredXrayState, SignedDesiredState,
};
use control_protocol::validation::ProtocolValidationError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub(crate) const DESIRED_STATE_SCHEMA_VERSION: u16 =
    control_protocol::version::DESIRED_STATE_SCHEMA_VERSION;
pub(crate) const SUPPORTED_DESIRED_STATE_SCHEMA_VERSIONS: &[u16] =
    control_protocol::version::SUPPORTED_DESIRED_STATE_SCHEMA_VERSIONS;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DesiredStateDraft {
    pub min_agent_version: String,
    pub users: Vec<DesiredUser>,
    pub xray: DesiredXrayState,
}

impl DesiredStateDraft {
    fn canonicalize(&mut self) {
        self.users.sort_by(|left, right| {
            left.user_id
                .cmp(&right.user_id)
                .then_with(|| left.credential_id.cmp(&right.credential_id))
        });
        self.xray.server_names.sort();
    }
}

pub(crate) struct PublishedDesiredState {
    pub envelope: SignedDesiredState,
    pub artifact_json: String,
    pub artifact_digest: Sha256Digest,
    pub transcript_digest: Sha256Digest,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_signed_desired_state(
    identity: &ControllerIdentity,
    network_id: NetworkId,
    node_id: NodeId,
    revision: Revision,
    created_at: Timestamp,
    controller_instance_id: ControllerInstanceId,
    mut draft: DesiredStateDraft,
) -> Result<PublishedDesiredState, DesiredStateError> {
    draft.canonicalize();
    let signing_key_id = controller_signing_key_id(identity)?;
    let document = DesiredStateDocument {
        schema_version: DESIRED_STATE_SCHEMA_VERSION,
        network_id,
        node_id,
        revision,
        created_at,
        min_agent_version: draft.min_agent_version,
        users: draft.users,
        xray: draft.xray,
        signing_key_id,
        controller_instance_id,
    };
    document.validate_for(
        network_id,
        node_id,
        controller_instance_id,
        None,
        &[DESIRED_STATE_SCHEMA_VERSION],
    )?;
    let transcript = desired_state_transcript(&document)?;
    let signature = identity.sign(&transcript)?;
    let envelope = SignedDesiredState {
        document,
        signature,
    };
    let artifact_json = serde_json::to_string(&envelope)?;

    Ok(PublishedDesiredState {
        envelope,
        artifact_digest: sha256_digest(artifact_json.as_bytes()),
        transcript_digest: sha256_digest(&transcript),
        artifact_json,
    })
}

pub(crate) struct StoredDesiredState<'a> {
    pub schema_version: u16,
    pub network_id: NetworkId,
    pub node_id: NodeId,
    pub revision: Revision,
    pub created_at: Timestamp,
    pub controller_instance_id: ControllerInstanceId,
    pub signing_key_id: SigningKeyId,
    pub artifact_json: &'a str,
    pub artifact_digest: &'a str,
    pub transcript_digest: &'a str,
    pub signature: &'a str,
}

pub(crate) fn verify_stored_desired_state(
    identity: &ControllerIdentity,
    stored: &StoredDesiredState<'_>,
) -> Result<SignedDesiredState, DesiredStateError> {
    if sha256_digest(stored.artifact_json.as_bytes()).as_str() != stored.artifact_digest {
        return Err(DesiredStateError::Integrity);
    }

    let envelope: SignedDesiredState = serde_json::from_str(stored.artifact_json)?;
    envelope.validate_for(
        stored.network_id,
        stored.node_id,
        stored.controller_instance_id,
        None,
        SUPPORTED_DESIRED_STATE_SCHEMA_VERSIONS,
    )?;
    if envelope.document.revision != stored.revision
        || envelope.document.schema_version != stored.schema_version
        || envelope.document.created_at != stored.created_at
        || envelope.document.signing_key_id != stored.signing_key_id
        || envelope.signature.as_str() != stored.signature
        || stored.signing_key_id != controller_signing_key_id(identity)?
    {
        return Err(DesiredStateError::Integrity);
    }

    let transcript = desired_state_transcript(&envelope.document)?;
    if sha256_digest(&transcript).as_str() != stored.transcript_digest {
        return Err(DesiredStateError::Integrity);
    }
    verify_desired_state_signature(
        &envelope.document,
        &envelope.signature,
        &identity.public_key(),
    )?;
    Ok(envelope)
}

pub(crate) fn controller_signing_key_id(
    identity: &ControllerIdentity,
) -> Result<SigningKeyId, DesiredStateError> {
    ed25519_signing_key_id(&identity.public_key()).map_err(|_| DesiredStateError::ControllerKey)
}

fn sha256_digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(value).into())
}

#[derive(Debug, Error)]
pub enum DesiredStateError {
    #[error(transparent)]
    Validation(#[from] ProtocolValidationError),
    #[error(transparent)]
    Crypto(#[from] DesiredStateCryptoError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("the controller public key is invalid")]
    ControllerKey,
    #[error("the stored desired-state artifact failed integrity verification")]
    Integrity,
}

#[cfg(test)]
mod tests {
    use super::{
        controller_signing_key_id, desired_state_transcript, sha256_digest,
        verify_stored_desired_state, StoredDesiredState,
    };
    use crate::identity::ControllerIdentity;
    use control_protocol::id::{ControllerInstanceId, NetworkId, NodeId, Revision, Timestamp};
    use control_protocol::node::{DesiredStateDocument, DesiredXrayState, SignedDesiredState};

    #[test]
    fn stored_version_one_artifact_remains_verifiable_after_version_two_release() {
        let directory = tempfile::tempdir().unwrap();
        let identity =
            ControllerIdentity::load_or_create(&directory.path().join("control.sqlite3")).unwrap();
        let network_id = NetworkId::new();
        let node_id = NodeId::new();
        let revision = Revision::new(1).unwrap();
        let created_at = "2026-07-11T20:00:00Z".parse::<Timestamp>().unwrap();
        let controller_instance_id = ControllerInstanceId::new();
        let signing_key_id = controller_signing_key_id(&identity).unwrap();
        let document = DesiredStateDocument {
            schema_version: 1,
            network_id,
            node_id,
            revision,
            created_at,
            min_agent_version: "0.1.0".to_string(),
            users: Vec::new(),
            xray: DesiredXrayState {
                listen_port: 443,
                public_port: None,
                server_names: vec!["www.microsoft.com".to_string()],
                target: "www.microsoft.com:443".to_string(),
            },
            signing_key_id,
            controller_instance_id,
        };
        let transcript = desired_state_transcript(&document).unwrap();
        let signature = identity.sign(&transcript).unwrap();
        let envelope = SignedDesiredState {
            document,
            signature,
        };
        let artifact_json = serde_json::to_string(&envelope).unwrap();
        let artifact_digest = sha256_digest(artifact_json.as_bytes());
        let transcript_digest = sha256_digest(&transcript);
        let stored = StoredDesiredState {
            schema_version: 1,
            network_id,
            node_id,
            revision,
            created_at,
            controller_instance_id,
            signing_key_id,
            artifact_json: &artifact_json,
            artifact_digest: artifact_digest.as_str(),
            transcript_digest: transcript_digest.as_str(),
            signature: envelope.signature.as_str(),
        };

        let verified = verify_stored_desired_state(&identity, &stored).unwrap();

        assert_eq!(verified.document.schema_version, 1);
        assert_eq!(verified.document.xray.public_port, None);

        let mismatched = StoredDesiredState {
            schema_version: 2,
            ..stored
        };
        assert!(matches!(
            verify_stored_desired_state(&identity, &mismatched),
            Err(super::DesiredStateError::Integrity)
        ));
    }
}
