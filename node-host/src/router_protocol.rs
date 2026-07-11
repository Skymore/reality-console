use async_trait::async_trait;
use control_protocol::id::{NodeId, Revision};
use control_protocol::node::EndpointSource;
use crab_nat::{
    natpmp, pcp, InternetProtocol, PortMapping, PortMappingOptions, PortMappingType, TimeoutConfig,
};
use igd_next::aio::tokio::{search_gateway, Tokio};
use igd_next::aio::Gateway;
use igd_next::{
    AddAnyPortError, AddPortError, GetGenericPortMappingEntryError, PortMappingProtocol,
    RemovePortError, SearchError, SearchOptions,
};
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::time::Duration;

const LEASE_SECONDS: u32 = 60 * 60;
const MAX_ACCEPTED_LEASE_SECONDS: u32 = 24 * 60 * 60;
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
const UPNP_SEARCH_TIMEOUT: Duration = Duration::from_secs(3);
const UPNP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UPNP_ENTRIES: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingFailureCode {
    RouteUnavailable,
    PrivateAddressUnavailable,
    ProtocolUnavailable,
    Unauthorized,
    Timeout,
    InvalidResponse,
    NonPublicAddress,
    PermanentLeaseUnsupported,
    OwnershipLost,
    TopologyChanged,
    ReleaseFailed,
}

impl MappingFailureCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RouteUnavailable => "mapping_route_unavailable",
            Self::PrivateAddressUnavailable => "mapping_private_address_unavailable",
            Self::ProtocolUnavailable => "mapping_protocol_unavailable",
            Self::Unauthorized => "mapping_unauthorized",
            Self::Timeout => "mapping_timeout",
            Self::InvalidResponse => "mapping_invalid_response",
            Self::NonPublicAddress => "mapping_non_public_address",
            Self::PermanentLeaseUnsupported => "mapping_permanent_lease_unsupported",
            Self::OwnershipLost => "mapping_ownership_lost",
            Self::TopologyChanged => "mapping_topology_changed",
            Self::ReleaseFailed => "mapping_release_failed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MappingRequest {
    pub node_id: NodeId,
    pub revision: Revision,
    pub internal_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableMapping {
    pub source: EndpointSource,
    pub gateway_address: IpAddr,
    pub internal_address: IpAddr,
    pub internal_port: u16,
    pub external_address: IpAddr,
    pub external_port: u16,
    pub pcp_nonce: Option<[u8; 12]>,
    pub upnp_description: Option<String>,
    pub gateway_epoch: Option<u32>,
    pub lifetime_seconds: u32,
    pub topology_fingerprint: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatedMapping {
    pub source: EndpointSource,
    pub gateway_address: IpAddr,
    pub internal_address: IpAddr,
    pub internal_port: u16,
    pub external_address: IpAddr,
    pub external_port: u16,
    pub pcp_nonce: Option<[u8; 12]>,
    pub upnp_description: Option<String>,
    pub gateway_epoch: Option<u32>,
    pub lifetime_seconds: u32,
    pub topology_fingerprint: [u8; 32],
}

impl From<&CreatedMapping> for DurableMapping {
    fn from(mapping: &CreatedMapping) -> Self {
        Self {
            source: mapping.source,
            gateway_address: mapping.gateway_address,
            internal_address: mapping.internal_address,
            internal_port: mapping.internal_port,
            external_address: mapping.external_address,
            external_port: mapping.external_port,
            pcp_nonce: mapping.pcp_nonce,
            upnp_description: mapping.upnp_description.clone(),
            gateway_epoch: mapping.gateway_epoch,
            lifetime_seconds: mapping.lifetime_seconds,
            topology_fingerprint: Some(mapping.topology_fingerprint),
        }
    }
}

#[async_trait]
pub(crate) trait MappingBackend: Send {
    fn topology_matches(&self, mapping: &DurableMapping) -> bool;

    async fn create(
        &mut self,
        request: &MappingRequest,
    ) -> Result<CreatedMapping, MappingFailureCode>;

    async fn renew(
        &mut self,
        mapping: &DurableMapping,
    ) -> Result<CreatedMapping, MappingFailureCode>;

    async fn release(&mut self, mapping: &DurableMapping) -> Result<(), MappingFailureCode>;
}

#[derive(Default)]
pub(crate) struct SystemMappingBackend;

#[async_trait]
impl MappingBackend for SystemMappingBackend {
    fn topology_matches(&self, mapping: &DurableMapping) -> bool {
        mapping_route(mapping).is_ok()
    }

    async fn create(
        &mut self,
        request: &MappingRequest,
    ) -> Result<CreatedMapping, MappingFailureCode> {
        let route = discover_default_route()?;
        let internal_port =
            NonZeroU16::new(request.internal_port).ok_or(MappingFailureCode::InvalidResponse)?;
        let mut failures = Vec::with_capacity(3);

        let nonce = random_pcp_nonce();
        match create_pcp(route, internal_port, nonce, None, Some(internal_port)).await {
            Ok(mapping) => return Ok(mapping),
            Err(code) => failures.push(code),
        }
        match create_nat_pmp(route, internal_port, Some(internal_port), None).await {
            Ok(mapping) => return Ok(mapping),
            Err(code) => failures.push(code),
        }
        let description = mapping_description(request.node_id, request.revision);
        match create_upnp(
            route,
            request.internal_port,
            request.internal_port,
            &description,
        )
        .await
        {
            Ok(mapping) => Ok(mapping),
            Err(code) => {
                failures.push(code);
                Err(select_failure(&failures))
            }
        }
    }

    async fn renew(
        &mut self,
        mapping: &DurableMapping,
    ) -> Result<CreatedMapping, MappingFailureCode> {
        match mapping.source {
            EndpointSource::Pcp => {
                let route = mapping_route(mapping)?;
                let nonce = mapping
                    .pcp_nonce
                    .map(nonce_from_bytes)
                    .ok_or(MappingFailureCode::OwnershipLost)?;
                create_pcp(
                    route,
                    nonzero(mapping.internal_port)?,
                    nonce,
                    Some(mapping.external_address),
                    Some(nonzero(mapping.external_port)?),
                )
                .await
            }
            EndpointSource::NatPmp => {
                let IpAddr::V4(external_address) = mapping.external_address else {
                    return Err(MappingFailureCode::InvalidResponse);
                };
                create_nat_pmp(
                    mapping_route(mapping)?,
                    nonzero(mapping.internal_port)?,
                    Some(nonzero(mapping.external_port)?),
                    Some(external_address),
                )
                .await
            }
            EndpointSource::Upnp => renew_upnp(mapping).await,
            EndpointSource::Manual | EndpointSource::Relay => {
                Err(MappingFailureCode::InvalidResponse)
            }
        }
    }

    async fn release(&mut self, mapping: &DurableMapping) -> Result<(), MappingFailureCode> {
        match mapping.source {
            EndpointSource::Pcp => release_pcp(mapping).await,
            EndpointSource::NatPmp => release_nat_pmp(mapping).await,
            EndpointSource::Upnp => release_upnp(mapping).await,
            EndpointSource::Manual | EndpointSource::Relay => {
                Err(MappingFailureCode::ReleaseFailed)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Route {
    gateway: Ipv4Addr,
    client: Ipv4Addr,
    topology_fingerprint: [u8; 32],
}

fn discover_default_route() -> Result<Route, MappingFailureCode> {
    let interface =
        netdev::get_default_interface().map_err(|_| MappingFailureCode::RouteUnavailable)?;
    if !interface.is_up()
        || !interface.is_running()
        || interface.is_loopback()
        || interface.is_point_to_point()
        || interface.is_tun()
    {
        return Err(MappingFailureCode::RouteUnavailable);
    }
    let gateway_device = interface
        .gateway
        .as_ref()
        .ok_or(MappingFailureCode::RouteUnavailable)?;
    let gateway = gateway_device
        .ipv4
        .first()
        .copied()
        .filter(|address| is_private_router_address(*address))
        .ok_or(MappingFailureCode::RouteUnavailable)?;
    let network = interface
        .ipv4
        .iter()
        .find(|network| network.contains(&gateway) && is_private_router_address(network.addr()))
        .or_else(|| {
            interface
                .ipv4
                .iter()
                .find(|network| is_private_router_address(network.addr()))
        })
        .ok_or(MappingFailureCode::PrivateAddressUnavailable)?;
    let client = network.addr();
    let gateway_mac = gateway_device.mac_addr.octets();
    let gateway_mac = (gateway_mac != [0; 6]).then_some(gateway_mac);
    Ok(Route {
        gateway,
        client,
        topology_fingerprint: topology_fingerprint(
            interface.index,
            &interface.name,
            gateway,
            client,
            network.prefix_len(),
            gateway_mac,
        ),
    })
}

fn mapping_route(mapping: &DurableMapping) -> Result<Route, MappingFailureCode> {
    let IpAddr::V4(gateway) = mapping.gateway_address else {
        return Err(MappingFailureCode::RouteUnavailable);
    };
    let IpAddr::V4(client) = mapping.internal_address else {
        return Err(MappingFailureCode::PrivateAddressUnavailable);
    };
    if !is_private_router_address(gateway) || !is_private_router_address(client) {
        return Err(MappingFailureCode::TopologyChanged);
    }
    let current = discover_default_route()?;
    if current.gateway != gateway
        || current.client != client
        || mapping
            .topology_fingerprint
            .is_some_and(|fingerprint| fingerprint != current.topology_fingerprint)
    {
        return Err(MappingFailureCode::TopologyChanged);
    }
    Ok(current)
}

fn topology_fingerprint(
    interface_index: u32,
    interface_name: &str,
    gateway: Ipv4Addr,
    client: Ipv4Addr,
    prefix_length: u8,
    gateway_mac: Option<[u8; 6]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"friend-node/router-topology/v1\0");
    hasher.update(interface_index.to_be_bytes());
    hasher.update(
        u64::try_from(interface_name.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(interface_name.as_bytes());
    hasher.update(gateway.octets());
    hasher.update(client.octets());
    hasher.update([prefix_length]);
    match gateway_mac {
        Some(address) => {
            hasher.update([1]);
            hasher.update(address);
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

async fn create_pcp(
    route: Route,
    internal_port: NonZeroU16,
    nonce: pcp::Nonce,
    external_ip: Option<IpAddr>,
    external_port: Option<NonZeroU16>,
) -> Result<CreatedMapping, MappingFailureCode> {
    let options = port_mapping_options(external_port);
    let result = bounded(pcp::try_port_mapping(
        pcp::BaseMapRequest::new(
            IpAddr::V4(route.gateway),
            IpAddr::V4(route.client),
            InternetProtocol::Tcp,
            internal_port,
        ),
        Some(nonce),
        external_ip,
        options,
    ))
    .await?
    .map_err(|error| classify_pcp_failure(&error))?;
    let PortMappingType::Pcp {
        nonce, external_ip, ..
    } = result.mapping_type()
    else {
        return Err(cleanup_failure_or(result, MappingFailureCode::InvalidResponse).await);
    };
    build_crab_mapping(
        result,
        EndpointSource::Pcp,
        IpAddr::V4(route.client),
        external_ip,
        Some(nonce),
        route.topology_fingerprint,
    )
    .await
}

async fn create_nat_pmp(
    route: Route,
    internal_port: NonZeroU16,
    external_port: Option<NonZeroU16>,
    known_external_address: Option<Ipv4Addr>,
) -> Result<CreatedMapping, MappingFailureCode> {
    let deadline = tokio::time::Instant::now() + PROTOCOL_TIMEOUT;
    let mapping = tokio::time::timeout_at(
        deadline,
        natpmp::try_port_mapping(
            IpAddr::V4(route.gateway),
            InternetProtocol::Tcp,
            internal_port,
            port_mapping_options(external_port),
        ),
    )
    .await
    .map_err(|_| MappingFailureCode::Timeout)?
    .map_err(|error| classify_nat_pmp_failure(&error))?;
    let external_ip = match known_external_address {
        Some(address) => address,
        None => match tokio::time::timeout_at(
            deadline,
            natpmp::try_external_address(IpAddr::V4(route.gateway), Some(short_timeout_config())),
        )
        .await
        {
            Ok(Ok(address)) => address,
            Ok(Err(error)) => {
                let code = classify_nat_pmp_failure(&error);
                return Err(cleanup_failure_or(mapping, code).await);
            }
            Err(_) => {
                return Err(cleanup_failure_or(mapping, MappingFailureCode::Timeout).await);
            }
        },
    };
    build_crab_mapping(
        mapping,
        EndpointSource::NatPmp,
        IpAddr::V4(route.client),
        IpAddr::V4(external_ip),
        None,
        route.topology_fingerprint,
    )
    .await
}

async fn build_crab_mapping(
    mapping: PortMapping,
    source: EndpointSource,
    internal_address: IpAddr,
    external_address: IpAddr,
    nonce: Option<pcp::Nonce>,
    topology_fingerprint: [u8; 32],
) -> Result<CreatedMapping, MappingFailureCode> {
    let lifetime_seconds = mapping.lifetime();
    if !valid_finite_lifetime(lifetime_seconds)
        || !is_publishable_external_address(external_address)
    {
        let code = if lifetime_seconds == 0 || lifetime_seconds > MAX_ACCEPTED_LEASE_SECONDS {
            MappingFailureCode::InvalidResponse
        } else {
            MappingFailureCode::NonPublicAddress
        };
        return Err(cleanup_failure_or(mapping, code).await);
    }
    Ok(CreatedMapping {
        source,
        gateway_address: mapping.gateway(),
        internal_address,
        internal_port: mapping.internal_port().get(),
        external_address,
        external_port: mapping.external_port().get(),
        pcp_nonce: nonce.map(nonce_to_bytes),
        upnp_description: None,
        gateway_epoch: Some(mapping.gateway_epoch()),
        lifetime_seconds,
        topology_fingerprint,
    })
}

async fn release_pcp(mapping: &DurableMapping) -> Result<(), MappingFailureCode> {
    let route = mapping_route(mapping)?;
    let nonce = mapping
        .pcp_nonce
        .map(nonce_from_bytes)
        .ok_or(MappingFailureCode::OwnershipLost)?;
    bounded(pcp::try_drop_mapping(
        IpAddr::V4(route.gateway),
        IpAddr::V4(route.client),
        nonce,
        pcp::DropMappingRange::Single {
            internal_port: nonzero(mapping.internal_port)?,
            protocol: InternetProtocol::Tcp,
        },
        Some(short_timeout_config()),
    ))
    .await?
    .map_err(|_| MappingFailureCode::ReleaseFailed)
}

async fn release_nat_pmp(mapping: &DurableMapping) -> Result<(), MappingFailureCode> {
    let route = mapping_route(mapping)?;
    bounded(natpmp::try_drop_mapping(
        IpAddr::V4(route.gateway),
        InternetProtocol::Tcp,
        Some(nonzero(mapping.internal_port)?),
        Some(short_timeout_config()),
    ))
    .await?
    .map_err(|_| MappingFailureCode::ReleaseFailed)
}

async fn create_upnp(
    route: Route,
    internal_port: u16,
    requested_external_port: u16,
    description: &str,
) -> Result<CreatedMapping, MappingFailureCode> {
    let operation = async {
        let gateway = discover_upnp_gateway(route).await?;
        let external_address = gateway
            .get_external_ip()
            .await
            .map_err(|_| MappingFailureCode::ProtocolUnavailable)?;
        if !is_publishable_external_address(external_address) {
            return Err(MappingFailureCode::NonPublicAddress);
        }
        let local = SocketAddr::new(IpAddr::V4(route.client), internal_port);
        let external_port = match gateway
            .add_port(
                PortMappingProtocol::TCP,
                requested_external_port,
                local,
                LEASE_SECONDS,
                description,
            )
            .await
        {
            Ok(()) => requested_external_port,
            Err(AddPortError::PortInUse) => gateway
                .add_any_port(PortMappingProtocol::TCP, local, LEASE_SECONDS, description)
                .await
                .map_err(|error| classify_add_any_error(&error))?,
            Err(error) => return Err(classify_add_port_error(&error)),
        };
        let ownership = inspect_upnp_ownership(
            &gateway,
            external_port,
            route.client,
            internal_port,
            description,
        )
        .await
        .map_err(|_| MappingFailureCode::ReleaseFailed)?;
        let OwnedUpnp::Owned { lease_seconds } = ownership else {
            return Err(MappingFailureCode::ReleaseFailed);
        };
        if lease_seconds == 0 {
            return Err(upnp_cleanup_failure_or(
                &gateway,
                external_port,
                MappingFailureCode::PermanentLeaseUnsupported,
            )
            .await);
        }
        if !valid_finite_lifetime(lease_seconds) {
            return Err(upnp_cleanup_failure_or(
                &gateway,
                external_port,
                MappingFailureCode::InvalidResponse,
            )
            .await);
        }
        Ok(CreatedMapping {
            source: EndpointSource::Upnp,
            gateway_address: gateway.addr.ip(),
            internal_address: IpAddr::V4(route.client),
            internal_port,
            external_address,
            external_port,
            pcp_nonce: None,
            upnp_description: Some(description.to_string()),
            gateway_epoch: None,
            lifetime_seconds: lease_seconds,
            topology_fingerprint: route.topology_fingerprint,
        })
    };
    tokio::time::timeout(PROTOCOL_TIMEOUT, operation)
        .await
        .map_err(|_| MappingFailureCode::Timeout)?
}

async fn renew_upnp(mapping: &DurableMapping) -> Result<CreatedMapping, MappingFailureCode> {
    let route = mapping_route(mapping)?;
    let description = mapping
        .upnp_description
        .as_deref()
        .ok_or(MappingFailureCode::OwnershipLost)?;
    let operation = async {
        let gateway = discover_upnp_gateway(route).await?;
        if gateway.addr.ip() != mapping.gateway_address {
            return Err(MappingFailureCode::OwnershipLost);
        }
        let external_address = gateway
            .get_external_ip()
            .await
            .map_err(|_| MappingFailureCode::ProtocolUnavailable)?;
        if !is_publishable_external_address(external_address) {
            return Err(MappingFailureCode::NonPublicAddress);
        }
        match inspect_upnp_ownership(
            &gateway,
            mapping.external_port,
            route.client,
            mapping.internal_port,
            description,
        )
        .await?
        {
            OwnedUpnp::Owned { .. } => {}
            OwnedUpnp::Absent | OwnedUpnp::Foreign => {
                return Err(MappingFailureCode::OwnershipLost);
            }
        }
        gateway
            .add_port(
                PortMappingProtocol::TCP,
                mapping.external_port,
                SocketAddr::new(IpAddr::V4(route.client), mapping.internal_port),
                LEASE_SECONDS,
                description,
            )
            .await
            .map_err(|error| classify_add_port_error(&error))?;
        let OwnedUpnp::Owned { lease_seconds } = inspect_upnp_ownership(
            &gateway,
            mapping.external_port,
            route.client,
            mapping.internal_port,
            description,
        )
        .await?
        else {
            return Err(MappingFailureCode::OwnershipLost);
        };
        if !valid_finite_lifetime(lease_seconds) {
            return Err(if lease_seconds == 0 {
                MappingFailureCode::PermanentLeaseUnsupported
            } else {
                MappingFailureCode::InvalidResponse
            });
        }
        Ok(CreatedMapping {
            source: EndpointSource::Upnp,
            gateway_address: gateway.addr.ip(),
            internal_address: IpAddr::V4(route.client),
            internal_port: mapping.internal_port,
            external_address,
            external_port: mapping.external_port,
            pcp_nonce: None,
            upnp_description: Some(description.to_string()),
            gateway_epoch: None,
            lifetime_seconds: lease_seconds,
            topology_fingerprint: route.topology_fingerprint,
        })
    };
    tokio::time::timeout(PROTOCOL_TIMEOUT, operation)
        .await
        .map_err(|_| MappingFailureCode::Timeout)?
}

async fn release_upnp(mapping: &DurableMapping) -> Result<(), MappingFailureCode> {
    let route = mapping_route(mapping)?;
    let description = mapping
        .upnp_description
        .as_deref()
        .ok_or(MappingFailureCode::OwnershipLost)?;
    let operation = async {
        let gateway = discover_upnp_gateway(route).await?;
        if gateway.addr.ip() != mapping.gateway_address {
            return Err(MappingFailureCode::OwnershipLost);
        }
        match inspect_upnp_ownership(
            &gateway,
            mapping.external_port,
            route.client,
            mapping.internal_port,
            description,
        )
        .await?
        {
            OwnedUpnp::Absent => Ok(()),
            OwnedUpnp::Foreign => Err(MappingFailureCode::OwnershipLost),
            OwnedUpnp::Owned { .. } => gateway
                .remove_port(PortMappingProtocol::TCP, mapping.external_port)
                .await
                .or_else(|error| match error {
                    RemovePortError::NoSuchPortMapping => Ok(()),
                    _ => Err(error),
                })
                .map_err(|_| MappingFailureCode::ReleaseFailed),
        }
    };
    tokio::time::timeout(PROTOCOL_TIMEOUT, operation)
        .await
        .map_err(|_| MappingFailureCode::Timeout)?
}

async fn discover_upnp_gateway(route: Route) -> Result<Gateway<Tokio>, MappingFailureCode> {
    let options = SearchOptions {
        bind_addr: SocketAddr::new(IpAddr::V4(route.client), 0),
        timeout: Some(UPNP_SEARCH_TIMEOUT),
        single_search_timeout: Some(UPNP_RESPONSE_TIMEOUT),
        ..SearchOptions::default()
    };
    let gateway = search_gateway(options)
        .await
        .map_err(|error| classify_search_error(&error))?;
    if gateway.addr.ip() != IpAddr::V4(route.gateway) {
        return Err(MappingFailureCode::ProtocolUnavailable);
    }
    Ok(gateway)
}

enum OwnedUpnp {
    Owned { lease_seconds: u32 },
    Absent,
    Foreign,
}

async fn inspect_upnp_ownership(
    gateway: &Gateway<Tokio>,
    external_port: u16,
    internal_address: Ipv4Addr,
    internal_port: u16,
    description: &str,
) -> Result<OwnedUpnp, MappingFailureCode> {
    let mut foreign_port = false;
    for index in 0..MAX_UPNP_ENTRIES {
        let entry = match gateway.get_generic_port_mapping_entry(index).await {
            Ok(entry) => entry,
            Err(GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid) => break,
            Err(_) => return Err(MappingFailureCode::OwnershipLost),
        };
        if entry.protocol != PortMappingProtocol::TCP || entry.external_port != external_port {
            continue;
        }
        let internal_matches = entry
            .internal_client
            .parse::<IpAddr>()
            .is_ok_and(|value| value == IpAddr::V4(internal_address));
        if internal_matches
            && entry.internal_port == internal_port
            && entry.port_mapping_description == description
            && entry.enabled
            && entry.remote_host.is_empty()
        {
            return Ok(OwnedUpnp::Owned {
                lease_seconds: entry.lease_duration,
            });
        }
        foreign_port = true;
    }
    Ok(if foreign_port {
        OwnedUpnp::Foreign
    } else {
        OwnedUpnp::Absent
    })
}

fn port_mapping_options(external_port: Option<NonZeroU16>) -> PortMappingOptions {
    PortMappingOptions {
        external_port,
        lifetime_seconds: Some(LEASE_SECONDS),
        timeout_config: Some(short_timeout_config()),
    }
}

const fn short_timeout_config() -> TimeoutConfig {
    TimeoutConfig {
        initial_timeout: Duration::from_secs(1),
        max_retries: 1,
        max_retry_timeout: Some(Duration::from_secs(2)),
    }
}

async fn bounded<F, T>(future: F) -> Result<T, MappingFailureCode>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(PROTOCOL_TIMEOUT, future)
        .await
        .map_err(|_| MappingFailureCode::Timeout)
}

async fn cleanup_failure_or(
    mapping: PortMapping,
    intended: MappingFailureCode,
) -> MappingFailureCode {
    match tokio::time::timeout(CLEANUP_TIMEOUT, mapping.try_drop()).await {
        Ok(Ok(())) => intended,
        Ok(Err(_)) | Err(_) => MappingFailureCode::ReleaseFailed,
    }
}

async fn upnp_cleanup_failure_or(
    gateway: &Gateway<Tokio>,
    external_port: u16,
    intended: MappingFailureCode,
) -> MappingFailureCode {
    match tokio::time::timeout(
        CLEANUP_TIMEOUT,
        gateway.remove_port(PortMappingProtocol::TCP, external_port),
    )
    .await
    {
        Ok(Ok(()) | Err(RemovePortError::NoSuchPortMapping)) => intended,
        Ok(Err(_)) | Err(_) => MappingFailureCode::ReleaseFailed,
    }
}

fn classify_pcp_failure(error: &pcp::Failure) -> MappingFailureCode {
    match error {
        pcp::Failure::Timeout => MappingFailureCode::Timeout,
        pcp::Failure::Socket(_) => MappingFailureCode::RouteUnavailable,
        pcp::Failure::Nonce | pcp::Failure::InvalidResponse(_) => {
            MappingFailureCode::InvalidResponse
        }
        pcp::Failure::ResultCode(pcp::ResultCode::NotAuthorized) => {
            MappingFailureCode::Unauthorized
        }
        pcp::Failure::ResultCode(
            pcp::ResultCode::UnsupportedVersion
            | pcp::ResultCode::UnsupportedOpcode
            | pcp::ResultCode::UnsupportedOption
            | pcp::ResultCode::UnsupportedProtocol,
        ) => MappingFailureCode::ProtocolUnavailable,
        pcp::Failure::ResultCode(_) => MappingFailureCode::InvalidResponse,
    }
}

fn classify_nat_pmp_failure(error: &natpmp::Failure) -> MappingFailureCode {
    match error {
        natpmp::Failure::Timeout => MappingFailureCode::Timeout,
        natpmp::Failure::Socket(_) => MappingFailureCode::RouteUnavailable,
        natpmp::Failure::ResultCode(natpmp::ResultCode::NotAuthorized) => {
            MappingFailureCode::Unauthorized
        }
        natpmp::Failure::ResultCode(
            natpmp::ResultCode::UnsupportedVersion | natpmp::ResultCode::UnsupportedOpcode,
        ) => MappingFailureCode::ProtocolUnavailable,
        natpmp::Failure::InvalidResponse(_) | natpmp::Failure::ResultCode(_) => {
            MappingFailureCode::InvalidResponse
        }
    }
}

fn classify_search_error(error: &SearchError) -> MappingFailureCode {
    match error {
        SearchError::NoResponseWithinTimeout => MappingFailureCode::Timeout,
        SearchError::InvalidResponse | SearchError::Utf8Error(_) | SearchError::XmlError(_) => {
            MappingFailureCode::InvalidResponse
        }
        _ => MappingFailureCode::ProtocolUnavailable,
    }
}

fn classify_add_port_error(error: &AddPortError) -> MappingFailureCode {
    match error {
        AddPortError::ActionNotAuthorized => MappingFailureCode::Unauthorized,
        AddPortError::OnlyPermanentLeasesSupported => MappingFailureCode::PermanentLeaseUnsupported,
        AddPortError::PortInUse | AddPortError::SamePortValuesRequired => {
            MappingFailureCode::ProtocolUnavailable
        }
        AddPortError::InternalPortZeroInvalid
        | AddPortError::ExternalPortZeroInvalid
        | AddPortError::DescriptionTooLong
        | AddPortError::RequestError(_) => MappingFailureCode::InvalidResponse,
    }
}

fn classify_add_any_error(error: &AddAnyPortError) -> MappingFailureCode {
    match error {
        AddAnyPortError::ActionNotAuthorized => MappingFailureCode::Unauthorized,
        AddAnyPortError::OnlyPermanentLeasesSupported => {
            MappingFailureCode::PermanentLeaseUnsupported
        }
        AddAnyPortError::NoPortsAvailable | AddAnyPortError::ExternalPortInUse => {
            MappingFailureCode::ProtocolUnavailable
        }
        AddAnyPortError::InternalPortZeroInvalid
        | AddAnyPortError::DescriptionTooLong
        | AddAnyPortError::RequestError(_) => MappingFailureCode::InvalidResponse,
    }
}

fn select_failure(failures: &[MappingFailureCode]) -> MappingFailureCode {
    for preferred in [
        MappingFailureCode::NonPublicAddress,
        MappingFailureCode::PermanentLeaseUnsupported,
        MappingFailureCode::Unauthorized,
        MappingFailureCode::OwnershipLost,
        MappingFailureCode::TopologyChanged,
        MappingFailureCode::Timeout,
        MappingFailureCode::InvalidResponse,
        MappingFailureCode::PrivateAddressUnavailable,
        MappingFailureCode::RouteUnavailable,
        MappingFailureCode::ProtocolUnavailable,
    ] {
        if failures.contains(&preferred) {
            return preferred;
        }
    }
    MappingFailureCode::ProtocolUnavailable
}

fn mapping_description(node_id: NodeId, revision: Revision) -> String {
    let mut token = [0_u8; 8];
    OsRng.fill_bytes(&mut token);
    mapping_description_with_token(node_id, revision, token)
}

fn mapping_description_with_token(node_id: NodeId, revision: Revision, token: [u8; 8]) -> String {
    let node = node_id.to_string();
    let token = u64::from_be_bytes(token);
    format!("FriendNode-{}-r{}-{token:016x}", &node[..8], revision.get())
}

fn random_pcp_nonce() -> pcp::Nonce {
    [OsRng.next_u32(), OsRng.next_u32(), OsRng.next_u32()]
}

fn nonce_to_bytes(nonce: pcp::Nonce) -> [u8; 12] {
    let mut bytes = [0_u8; 12];
    for (chunk, value) in bytes.chunks_exact_mut(4).zip(nonce) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn nonce_from_bytes(bytes: [u8; 12]) -> pcp::Nonce {
    let mut nonce = [0_u32; 3];
    for (value, chunk) in nonce.iter_mut().zip(bytes.chunks_exact(4)) {
        *value = u32::from_be_bytes(chunk.try_into().expect("nonce chunks are four bytes"));
    }
    nonce
}

fn nonzero(port: u16) -> Result<NonZeroU16, MappingFailureCode> {
    NonZeroU16::new(port).ok_or(MappingFailureCode::InvalidResponse)
}

const fn valid_finite_lifetime(seconds: u32) -> bool {
    seconds > 0 && seconds <= MAX_ACCEPTED_LEASE_SECONDS
}

fn is_private_router_address(address: Ipv4Addr) -> bool {
    address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_multicast()
}

fn is_publishable_external_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_publishable_ipv4(address),
        IpAddr::V6(_) => false,
    }
}

fn is_publishable_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_documentation()
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        && octets[0] != 0
        && octets[0] < 240
}

#[cfg(test)]
mod tests {
    use super::{
        is_private_router_address, is_publishable_external_address, mapping_description_with_token,
        nonce_from_bytes, nonce_to_bytes, topology_fingerprint,
    };
    use control_protocol::id::{NodeId, Revision};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn public_address_filter_rejects_non_internet_ranges() {
        for address in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(!is_publishable_external_address(IpAddr::V4(address)));
        }
        assert!(is_publishable_external_address(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!is_publishable_external_address(IpAddr::V6(
            "fd00::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_publishable_external_address(IpAddr::V6(
            "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
        )));
    }

    #[test]
    fn private_route_filter_accepts_only_lan_addresses() {
        assert!(is_private_router_address(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_router_address(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_private_router_address(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_router_address(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn pcp_nonce_round_trips_without_native_endian_state() {
        let nonce = [0x0102_0304, 0xa0b0_c0d0, 0xffff_0001];
        assert_eq!(nonce_from_bytes(nonce_to_bytes(nonce)), nonce);
    }

    #[test]
    fn upnp_description_is_bounded_and_revision_specific() {
        let node_id = NodeId::new();
        let first = mapping_description_with_token(node_id, Revision::new(42).unwrap(), [0xab; 8]);
        assert!(first.len() <= 64);
        assert!(first.contains("-r42-"));
        assert!(first.ends_with("abababababababab"));
    }

    #[test]
    fn topology_fingerprint_changes_with_the_gateway_identity() {
        let first = topology_fingerprint(
            4,
            "en0",
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 10),
            24,
            Some([1, 2, 3, 4, 5, 6]),
        );
        let same = topology_fingerprint(
            4,
            "en0",
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 10),
            24,
            Some([1, 2, 3, 4, 5, 6]),
        );
        let changed = topology_fingerprint(
            4,
            "en0",
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 10),
            24,
            Some([6, 5, 4, 3, 2, 1]),
        );
        assert_eq!(first, same);
        assert_ne!(first, changed);
    }
}
