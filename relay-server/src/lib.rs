//! Bounded raw TCP reverse relay.
//!
//! The relay authenticates one node-originated mTLS tunnel per opaque route and maps that route's
//! fixed public TCP listener to multiplexed logical streams. Payload bytes remain end-to-end
//! VLESS/REALITY ciphertext and are never parsed by this crate.

mod config;
mod error;
mod flow;
pub mod frame;
mod metrics;
mod node;
mod quota;
mod registry;
mod relay;
mod tls;

pub use config::{ManagedRoutesConfig, RelayConfig, RouteConfig, ServerConfig};
pub use error::{ErrorCode, RelayError, Result};
pub use metrics::Metrics;
pub use node::{ConnectorStatus, NodeConnectorConfig, RelayNodeConnector};
pub use relay::{RelayHandle, RelayServer};
