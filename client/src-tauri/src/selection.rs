//! Pure backend node-selection state machine with deterministic anti-oscillation rules.

use crate::error::ClientError;
use control_protocol::account::{ProfileDescriptor, SelectionHints};
use control_protocol::id::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const MAXIMUM_HOLD_SECONDS: u32 = 86_400;
const MAXIMUM_LATENCY_TOLERANCE_MILLISECONDS: u32 = 60_000;
const MAXIMUM_FAILURE_THRESHOLD: u16 = 100;

/// User-controlled selection behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "nodes")]
pub enum SelectionMode {
    /// Only an explicit node may be selected; health never triggers fallback.
    Manual(NodeId),
    /// Select from all healthy bundle nodes using signed policy hints.
    Automatic,
    /// Use only the configured order, failing over and later failing back with hold-down.
    PinnedFallback(Vec<NodeId>),
}

/// One endpoint probe result isolated to its node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Successful bounded probe latency.
    Healthy { latency: Duration },
    /// Endpoint-specific failure.
    Failed,
}

/// Stable explanation for a selection decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SelectionReason {
    /// Explicit manual request.
    Manual,
    /// Existing node retained during minimum hold-down.
    MinimumHold,
    /// Existing node remains within the latency tolerance.
    WithinTolerance,
    /// Initial automatic healthy candidate.
    AutomaticInitial,
    /// Better signed-priority or latency candidate after hold-down.
    AutomaticBetterCandidate,
    /// Active node reached its consecutive failure threshold.
    FailureThreshold,
    /// Initial pinned candidate.
    PinnedInitial,
    /// A higher pinned preference recovered after hold-down.
    PinnedRecovery,
    /// No eligible candidate exists.
    Unavailable,
}

/// Result of evaluating the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionDecision {
    /// Selected node, if any.
    pub node_id: Option<NodeId>,
    /// Whether the active node changed.
    pub changed: bool,
    /// Deterministic decision reason.
    pub reason: SelectionReason,
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    priority: u16,
}

#[derive(Debug, Clone, Copy, Default)]
struct Health {
    latency: Option<Duration>,
    consecutive_failures: u16,
}

/// Signed and bounded selection policy.
#[derive(Debug, Clone, Copy)]
struct SelectionPolicy {
    minimum_hold: Duration,
    latency_tolerance: Duration,
    failure_threshold: u16,
}

impl TryFrom<&SelectionHints> for SelectionPolicy {
    type Error = ClientError;

    fn try_from(hints: &SelectionHints) -> Result<Self, Self::Error> {
        if hints.minimum_hold_seconds > MAXIMUM_HOLD_SECONDS
            || hints.latency_tolerance_milliseconds > MAXIMUM_LATENCY_TOLERANCE_MILLISECONDS
            || !(1..=MAXIMUM_FAILURE_THRESHOLD).contains(&hints.failure_threshold)
        {
            return Err(selection_error("selection_hints_out_of_range"));
        }
        Ok(Self {
            minimum_hold: Duration::from_secs(u64::from(hints.minimum_hold_seconds)),
            latency_tolerance: Duration::from_millis(u64::from(
                hints.latency_tolerance_milliseconds,
            )),
            failure_threshold: hints.failure_threshold,
        })
    }
}

/// Deterministic selection machine. Time is supplied by callers for testability.
pub struct NodeSelector {
    mode: SelectionMode,
    policy: SelectionPolicy,
    candidates: BTreeMap<NodeId, Candidate>,
    health: BTreeMap<NodeId, Health>,
    active: Option<NodeId>,
    selected_at: Option<Duration>,
}

impl NodeSelector {
    /// Creates a selector from a verified bundle manifest.
    pub fn new(
        mode: SelectionMode,
        hints: &SelectionHints,
        profiles: &[ProfileDescriptor],
    ) -> Result<Self, ClientError> {
        validate_mode(&mode)?;
        Ok(Self {
            mode,
            policy: SelectionPolicy::try_from(hints)?,
            candidates: profiles
                .iter()
                .map(|profile| {
                    (
                        profile.node_id,
                        Candidate {
                            priority: profile.priority,
                        },
                    )
                })
                .collect(),
            health: BTreeMap::new(),
            active: None,
            selected_at: None,
        })
    }

    /// Changes user selection mode without making an implicit decision.
    pub fn set_mode(&mut self, mode: SelectionMode) -> Result<(), ClientError> {
        validate_mode(&mode)?;
        self.mode = mode;
        Ok(())
    }

    /// Reconciles a newly verified complete bundle without carrying health across removed nodes.
    pub fn reconcile_bundle(
        &mut self,
        hints: &SelectionHints,
        profiles: &[ProfileDescriptor],
    ) -> Result<(), ClientError> {
        self.policy = SelectionPolicy::try_from(hints)?;
        self.candidates = profiles
            .iter()
            .map(|profile| {
                (
                    profile.node_id,
                    Candidate {
                        priority: profile.priority,
                    },
                )
            })
            .collect();
        self.health
            .retain(|node_id, _| self.candidates.contains_key(node_id));
        if self
            .active
            .is_some_and(|node_id| !self.candidates.contains_key(&node_id))
        {
            self.active = None;
            self.selected_at = None;
        }
        Ok(())
    }

    /// Records one node-local probe result.
    pub fn observe(&mut self, node_id: NodeId, outcome: ProbeOutcome) {
        if !self.candidates.contains_key(&node_id) {
            return;
        }
        let health = self.health.entry(node_id).or_default();
        match outcome {
            ProbeOutcome::Healthy { latency } => {
                health.latency = Some(latency);
                health.consecutive_failures = 0;
            }
            ProbeOutcome::Failed => {
                health.consecutive_failures = health.consecutive_failures.saturating_add(1);
            }
        }
    }

    /// Evaluates selection at caller-supplied monotonic time.
    #[must_use]
    pub fn select(&mut self, now: Duration) -> SelectionDecision {
        match self.mode.clone() {
            SelectionMode::Manual(node_id) => self.select_manual(node_id, now),
            SelectionMode::Automatic => self.select_automatic(now),
            SelectionMode::PinnedFallback(order) => self.select_pinned(&order, now),
        }
    }

    /// Returns the current node without evaluating a transition.
    #[must_use]
    pub const fn active(&self) -> Option<NodeId> {
        self.active
    }

    /// Returns the user-controlled mode without evaluating a transition.
    #[must_use]
    pub const fn mode(&self) -> &SelectionMode {
        &self.mode
    }

    fn select_manual(&mut self, requested: NodeId, now: Duration) -> SelectionDecision {
        if !self.candidates.contains_key(&requested) {
            return self.clear(SelectionReason::Unavailable);
        }
        self.activate(requested, now, SelectionReason::Manual)
    }

    fn select_automatic(&mut self, now: Duration) -> SelectionDecision {
        let active_failed = self.active.is_some_and(|node_id| self.failed(node_id));
        let best = self.best_automatic();
        let Some(best) = best else {
            if active_failed || self.active.is_none() {
                return self.clear(SelectionReason::Unavailable);
            }
            return self.keep(SelectionReason::WithinTolerance);
        };
        let Some(active) = self.active else {
            return self.activate(best, now, SelectionReason::AutomaticInitial);
        };
        if active_failed {
            if best == active {
                return self.clear(SelectionReason::Unavailable);
            }
            return self.activate(best, now, SelectionReason::FailureThreshold);
        }
        if best == active {
            return self.keep(SelectionReason::WithinTolerance);
        }
        if self.holding(now) {
            return self.keep(SelectionReason::MinimumHold);
        }
        let active_candidate = self.candidates[&active];
        let best_candidate = self.candidates[&best];
        if best_candidate.priority < active_candidate.priority {
            return self.activate(best, now, SelectionReason::AutomaticBetterCandidate);
        }
        if best_candidate.priority == active_candidate.priority {
            let active_latency = self.health[&active].latency.unwrap_or(Duration::MAX);
            let best_latency = self.health[&best].latency.unwrap_or(Duration::MAX);
            if best_latency.saturating_add(self.policy.latency_tolerance) < active_latency {
                return self.activate(best, now, SelectionReason::AutomaticBetterCandidate);
            }
        }
        self.keep(SelectionReason::WithinTolerance)
    }

    fn select_pinned(&mut self, order: &[NodeId], now: Duration) -> SelectionDecision {
        let best = order.iter().copied().find(|node_id| self.healthy(*node_id));
        let Some(best) = best else {
            if self.active.is_none_or(|node_id| self.failed(node_id)) {
                return self.clear(SelectionReason::Unavailable);
            }
            return self.keep(SelectionReason::MinimumHold);
        };
        let Some(active) = self.active else {
            return self.activate(best, now, SelectionReason::PinnedInitial);
        };
        if self.failed(active) {
            return self.activate(best, now, SelectionReason::FailureThreshold);
        }
        if best == active || self.holding(now) {
            return self.keep(if best == active {
                SelectionReason::WithinTolerance
            } else {
                SelectionReason::MinimumHold
            });
        }
        let best_index = order.iter().position(|node_id| *node_id == best);
        let active_index = order.iter().position(|node_id| *node_id == active);
        if best_index < active_index {
            return self.activate(best, now, SelectionReason::PinnedRecovery);
        }
        self.keep(SelectionReason::WithinTolerance)
    }

    fn best_automatic(&self) -> Option<NodeId> {
        self.candidates
            .iter()
            .filter(|(node_id, _)| self.healthy(**node_id))
            .min_by_key(|(node_id, candidate)| {
                (
                    candidate.priority,
                    self.health[*node_id].latency.unwrap_or(Duration::MAX),
                    **node_id,
                )
            })
            .map(|(node_id, _)| *node_id)
    }

    fn healthy(&self, node_id: NodeId) -> bool {
        self.candidates.contains_key(&node_id)
            && self.health.get(&node_id).is_some_and(|health| {
                health.latency.is_some()
                    && health.consecutive_failures < self.policy.failure_threshold
            })
    }

    fn failed(&self, node_id: NodeId) -> bool {
        !self.candidates.contains_key(&node_id)
            || self
                .health
                .get(&node_id)
                .is_some_and(|health| health.consecutive_failures >= self.policy.failure_threshold)
    }

    fn holding(&self, now: Duration) -> bool {
        self.selected_at
            .is_some_and(|selected| now.saturating_sub(selected) < self.policy.minimum_hold)
    }

    fn activate(
        &mut self,
        node_id: NodeId,
        now: Duration,
        reason: SelectionReason,
    ) -> SelectionDecision {
        let changed = self.active != Some(node_id);
        if changed {
            self.active = Some(node_id);
            self.selected_at = Some(now);
        }
        SelectionDecision {
            node_id: Some(node_id),
            changed,
            reason,
        }
    }

    fn keep(&self, reason: SelectionReason) -> SelectionDecision {
        SelectionDecision {
            node_id: self.active,
            changed: false,
            reason,
        }
    }

    fn clear(&mut self, reason: SelectionReason) -> SelectionDecision {
        let changed = self.active.take().is_some();
        self.selected_at = None;
        SelectionDecision {
            node_id: None,
            changed,
            reason,
        }
    }
}

fn validate_mode(mode: &SelectionMode) -> Result<(), ClientError> {
    if let SelectionMode::PinnedFallback(order) = mode {
        if order.is_empty() || order.len() > 1_000 {
            return Err(selection_error("pinned_fallback_invalid"));
        }
        let unique: BTreeSet<_> = order.iter().copied().collect();
        if unique.len() != order.len() {
            return Err(selection_error("pinned_fallback_duplicate"));
        }
    }
    Ok(())
}

fn selection_error(code: &str) -> ClientError {
    ClientError::internal(code, "The node selection policy is invalid.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use control_protocol::crypto::Sha256Digest;
    use control_protocol::node::EndpointMode;

    fn descriptor(node_id: NodeId, priority: u16) -> ProfileDescriptor {
        ProfileDescriptor {
            node_id,
            display_name: node_id.to_string(),
            region: None,
            endpoint_mode: EndpointMode::Direct,
            encrypted_payload_digest: format!("sha256:{}", "0".repeat(64)).parse().unwrap(),
            priority,
        }
    }

    fn hints() -> SelectionHints {
        SelectionHints {
            minimum_hold_seconds: 60,
            latency_tolerance_milliseconds: 20,
            failure_threshold: 3,
        }
    }

    fn healthy(selector: &mut NodeSelector, node: NodeId, millis: u64) {
        selector.observe(
            node,
            ProbeOutcome::Healthy {
                latency: Duration::from_millis(millis),
            },
        );
    }

    #[test]
    fn manual_mode_never_falls_back_after_failures() {
        let selected = NodeId::new();
        let other = NodeId::new();
        let mut selector = NodeSelector::new(
            SelectionMode::Manual(selected),
            &hints(),
            &[descriptor(selected, 0), descriptor(other, 0)],
        )
        .unwrap();
        healthy(&mut selector, other, 5);
        assert_eq!(selector.select(Duration::ZERO).node_id, Some(selected));
        for _ in 0..10 {
            selector.observe(selected, ProbeOutcome::Failed);
        }
        assert_eq!(
            selector.select(Duration::from_secs(100)).node_id,
            Some(selected)
        );
    }

    #[test]
    fn automatic_mode_holds_and_uses_latency_tolerance() {
        let first = NodeId::new();
        let second = NodeId::new();
        let mut selector = NodeSelector::new(
            SelectionMode::Automatic,
            &hints(),
            &[descriptor(first, 0), descriptor(second, 0)],
        )
        .unwrap();
        healthy(&mut selector, first, 50);
        healthy(&mut selector, second, 100);
        assert_eq!(selector.select(Duration::ZERO).node_id, Some(first));

        healthy(&mut selector, second, 10);
        let held = selector.select(Duration::from_secs(30));
        assert_eq!(held.node_id, Some(first));
        assert_eq!(held.reason, SelectionReason::MinimumHold);
        let switched = selector.select(Duration::from_secs(61));
        assert_eq!(switched.node_id, Some(second));

        healthy(&mut selector, first, 1);
        let still_held = selector.select(Duration::from_secs(122));
        assert_eq!(still_held.node_id, Some(second));
        assert_eq!(still_held.reason, SelectionReason::WithinTolerance);
    }

    #[test]
    fn failure_threshold_prevents_rapid_failover() {
        let first = NodeId::new();
        let second = NodeId::new();
        let mut selector = NodeSelector::new(
            SelectionMode::Automatic,
            &hints(),
            &[descriptor(first, 0), descriptor(second, 1)],
        )
        .unwrap();
        healthy(&mut selector, first, 10);
        healthy(&mut selector, second, 20);
        let _ = selector.select(Duration::ZERO);

        selector.observe(first, ProbeOutcome::Failed);
        selector.observe(first, ProbeOutcome::Failed);
        assert_eq!(
            selector.select(Duration::from_secs(100)).node_id,
            Some(first)
        );
        selector.observe(first, ProbeOutcome::Failed);
        let fallback = selector.select(Duration::from_secs(101));
        assert_eq!(fallback.node_id, Some(second));
        assert_eq!(fallback.reason, SelectionReason::FailureThreshold);
    }

    #[test]
    fn pinned_fallback_is_ordered_and_failure_is_node_local() {
        let preferred = NodeId::new();
        let fallback = NodeId::new();
        let unrelated = NodeId::new();
        let mut selector = NodeSelector::new(
            SelectionMode::PinnedFallback(vec![preferred, fallback]),
            &hints(),
            &[
                descriptor(preferred, 0),
                descriptor(fallback, 0),
                descriptor(unrelated, 0),
            ],
        )
        .unwrap();
        healthy(&mut selector, preferred, 30);
        healthy(&mut selector, fallback, 40);
        healthy(&mut selector, unrelated, 1);
        assert_eq!(selector.select(Duration::ZERO).node_id, Some(preferred));
        for _ in 0..3 {
            selector.observe(preferred, ProbeOutcome::Failed);
        }
        assert_eq!(
            selector.select(Duration::from_secs(1)).node_id,
            Some(fallback)
        );
        for _ in 0..10 {
            selector.observe(unrelated, ProbeOutcome::Failed);
        }
        assert_eq!(
            selector.select(Duration::from_secs(2)).node_id,
            Some(fallback)
        );
    }

    #[test]
    fn rejects_unbounded_or_zero_threshold_hints() {
        let invalid = SelectionHints {
            minimum_hold_seconds: 1,
            latency_tolerance_milliseconds: 1,
            failure_threshold: 0,
        };
        assert!(NodeSelector::new(SelectionMode::Automatic, &invalid, &[]).is_err());
    }

    #[test]
    fn digest_type_is_available_for_descriptor_fixture() {
        let _: Sha256Digest = format!("sha256:{}", "0".repeat(64)).parse().unwrap();
    }
}
