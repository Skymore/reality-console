//! Controller-side relay grant issuance and replayable route publication.

use crate::config::RelayProvisioningConfig;
use crate::db::{Database, DatabaseError, RelayOutboxAction};
use crate::identity::{ControllerIdentity, IdentityError};
use control_protocol::crypto::ed25519_signing_key_id;
use control_protocol::id::{NodeId, RelayGrantId};
use control_protocol::relay::{
    encrypt_relay_material, relay_assignment_transcript, relay_route_transcript,
    AcknowledgeRelayAssignmentRequest, EnsureRelayAssignmentRequest, RelayLimits,
    SignedRelayAssignment, SignedRelayRoute,
};
use relay_provisioning::{ManagedRouteStore, ProvisioningError, RelayCertificateAuthority};
use std::sync::Arc;
use thiserror::Error;

const RELAY_RENEWAL_WINDOW_SECONDS: i64 = 60 * 60;

/// Static relay material plus durable database coordination.
#[derive(Clone)]
pub struct RelayProvisioner {
    database: Database,
    identity: ControllerIdentity,
    config: RelayProvisioningConfig,
    authority: Arc<RelayCertificateAuthority>,
    routes: ManagedRouteStore,
}

impl RelayProvisioner {
    /// Opens owner-only static relay inputs. Startup fails rather than running
    /// with a partially configured relay.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProvisioningError`] for unsafe static material.
    pub fn new(
        database: Database,
        identity: ControllerIdentity,
        config: RelayProvisioningConfig,
    ) -> Result<Self, RelayProvisioningError> {
        let authority = RelayCertificateAuthority::load(
            &config.ca_certificate_path,
            &config.ca_private_key_path,
        )?;
        let routes = ManagedRouteStore::open(&config.managed_route_dir)?;
        Ok(Self {
            database,
            identity,
            config,
            authority: Arc::new(authority),
            routes,
        })
    }

    /// Returns an already publishable assignment or creates the next generation.
    /// The authenticated signed node request that reaches this method is the
    /// provider's current action consent; eligibility also requires the durable
    /// enrollment consent and `relay-tcp` capability.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProvisioningError`] when issuance or reconciliation fails.
    pub async fn ensure_assignment(
        &self,
        node_id: NodeId,
        request: EnsureRelayAssignmentRequest,
    ) -> Result<Option<SignedRelayAssignment>, RelayProvisioningError> {
        request.validate()?;
        let limits = lower_limits(self.config.limits, request.provider_limits);
        self.reconcile().await?;
        if let Some(assignment) = self.database.relay_assignment(node_id).await? {
            let remaining =
                assignment.header.expires_at.as_datetime() - time::OffsetDateTime::now_utc();
            if remaining.whole_seconds() > RELAY_RENEWAL_WINDOW_SECONDS
                && limits_within(assignment.header.limits, limits)
            {
                return Ok(Some(assignment));
            }
        }
        self.issue_generation(node_id, limits).await?;
        self.reconcile().await?;
        self.database
            .relay_assignment(node_id)
            .await
            .map_err(Into::into)
    }

    /// Accepts a signed node acknowledgement only after the successor
    /// generation has registered, then removes older generations in order.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProvisioningError`] for a conflicting acknowledgement or
    /// route-removal reconciliation failure.
    pub async fn acknowledge_assignment(
        &self,
        node_id: NodeId,
        acknowledgement: AcknowledgeRelayAssignmentRequest,
    ) -> Result<(), RelayProvisioningError> {
        acknowledgement.validate()?;
        self.database
            .acknowledge_relay_assignment(node_id, acknowledgement)
            .await?;
        self.reconcile().await
    }

    /// Queues administrative revocation and attempts it synchronously once.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProvisioningError`] when the grant cannot be revoked.
    pub async fn revoke(&self, grant_id: RelayGrantId) -> Result<(), RelayProvisioningError> {
        self.database.revoke_relay_grant(grant_id).await?;
        self.reconcile().await
    }

    /// Repairs every incomplete publish/revoke operation. File writes happen
    /// outside `SQLite` transactions and are verified before durable completion.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProvisioningError`] when an outbox operation cannot be reconciled.
    pub async fn reconcile(&self) -> Result<(), RelayProvisioningError> {
        self.database.expire_relay_grants().await?;
        // A successful N+1 publish creates N's revoke row. Two passes finish
        // that ordered handoff without bypassing retry backoff on failures.
        for _ in 0..2 {
            let jobs = self.database.due_relay_outbox().await?;
            if jobs.is_empty() {
                break;
            }
            for job in jobs {
                let result = match job.action {
                    RelayOutboxAction::Publish => {
                        let route = job
                            .route
                            .as_ref()
                            .ok_or(RelayProvisioningError::MissingRoute)?;
                        self.routes.publish(route).map(|_| ())
                    }
                    RelayOutboxAction::Revoke => self.routes.revoke(job.grant_id).map(|_| ()),
                };
                match result {
                    Ok(()) => match job.action {
                        RelayOutboxAction::Publish => {
                            self.database.mark_relay_published(job.grant_id).await?;
                        }
                        RelayOutboxAction::Revoke => {
                            self.database.mark_relay_revoked(job.grant_id).await?;
                        }
                    },
                    Err(_) => {
                        self.database
                            .record_relay_outbox_failure(job.grant_id, job.action)
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn issue_generation(
        &self,
        node_id: NodeId,
        limits: RelayLimits,
    ) -> Result<(), RelayProvisioningError> {
        let draft = self
            .database
            .prepare_relay_grant(
                node_id,
                self.config.relay_id,
                self.config.public_host.clone(),
                self.config.tunnel_host.clone(),
                self.config.tunnel_port,
                self.config.tls_server_name.clone(),
                self.config.public_port_start,
                self.config.public_port_end,
                limits,
            )
            .await?;
        let issued = self.authority.issue(
            draft.header.node_id,
            draft.header.grant_id,
            draft.header.not_before,
            draft.header.expires_at,
        )?;
        let encrypted_material = encrypt_relay_material(
            &draft.recipient_encryption_key,
            &draft.header,
            &issued.assignment,
        )?;
        let signing_key_id = ed25519_signing_key_id(&self.identity.public_key())
            .map_err(|_| RelayProvisioningError::SigningKey)?;
        let mut assignment = SignedRelayAssignment {
            header: draft.header.clone(),
            encrypted_material,
            signing_key_id,
            signature: self.identity.sign(&[])?,
        };
        assignment.signature = self
            .identity
            .sign(&relay_assignment_transcript(&assignment)?)?;
        let mut route = SignedRelayRoute {
            header: draft.header,
            route_token_sha256: issued.route_token_sha256,
            client_certificate_sha256: issued.client_certificate_sha256,
            signing_key_id,
            signature: self.identity.sign(&[])?,
        };
        route.signature = self.identity.sign(&relay_route_transcript(&route)?)?;
        // `issued.assignment` never crosses the persistence boundary.
        self.database
            .store_pending_relay_grant(assignment, route)
            .await?;
        Ok(())
    }
}

fn lower_limits(operator: RelayLimits, provider: RelayLimits) -> RelayLimits {
    RelayLimits {
        max_concurrent_streams: operator
            .max_concurrent_streams
            .min(provider.max_concurrent_streams),
        max_bytes_per_second: operator
            .max_bytes_per_second
            .min(provider.max_bytes_per_second),
        max_bytes_per_connection: operator
            .max_bytes_per_connection
            .min(provider.max_bytes_per_connection),
        monthly_byte_limit: operator.monthly_byte_limit.min(provider.monthly_byte_limit),
    }
}

fn limits_within(current: RelayLimits, requested: RelayLimits) -> bool {
    current.max_concurrent_streams <= requested.max_concurrent_streams
        && current.max_bytes_per_second <= requested.max_bytes_per_second
        && current.max_bytes_per_connection <= requested.max_bytes_per_connection
        && current.monthly_byte_limit <= requested.monthly_byte_limit
}

/// Runs startup and periodic reconciliation until the supplied future resolves.
pub async fn run_relay_reconciliation_until<F>(provisioner: RelayProvisioner, shutdown: F)
where
    F: std::future::Future<Output = ()>,
{
    tokio::pin!(shutdown);
    loop {
        if let Err(error) = provisioner.reconcile().await {
            tracing::warn!(error = %error, "relay route reconciliation failed; will retry");
        }
        tokio::select! {
            () = &mut shutdown => return,
            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
        }
    }
}

#[derive(Debug, Error)]
pub enum RelayProvisioningError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    Provisioning(#[from] ProvisioningError),
    #[error(transparent)]
    Crypto(#[from] control_protocol::relay::RelayCryptoError),
    #[error(transparent)]
    Validation(#[from] control_protocol::ProtocolValidationError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("controller signing key could not be encoded")]
    SigningKey,
    #[error("durable relay outbox publish job has no route")]
    MissingRoute,
}

#[cfg(test)]
mod tests {
    use super::{limits_within, lower_limits};
    use control_protocol::relay::RelayLimits;

    #[test]
    fn provider_limits_are_intersected_with_operator_limits() {
        let operator = RelayLimits {
            max_concurrent_streams: 20,
            max_bytes_per_second: 2_000,
            max_bytes_per_connection: 2_000_000,
            monthly_byte_limit: 2_000_000,
        };
        let provider = RelayLimits {
            max_concurrent_streams: 10,
            max_bytes_per_second: 4_000,
            max_bytes_per_connection: 1_500_000,
            monthly_byte_limit: 3_000_000,
        };
        let effective = lower_limits(operator, provider);
        assert_eq!(effective.max_concurrent_streams, 10);
        assert_eq!(effective.max_bytes_per_second, 2_000);
        assert_eq!(effective.max_bytes_per_connection, 1_500_000);
        assert_eq!(effective.monthly_byte_limit, 2_000_000);
        assert!(limits_within(effective, provider));
    }
}
