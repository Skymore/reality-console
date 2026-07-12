# Xray traffic collection

Node Host collects only cumulative per-user upload and download counters from
the Xray Stats API. It does not inspect payloads, destinations, client IPs, or
access logs, and it does not estimate connection counts.

## Runtime boundary

- Each installed runtime receives one OS-selected API port persisted in the
  owner-only Node Host database.
- Generated Xray configuration exposes that port only on `127.0.0.1` through a
  dedicated `dokodemo-door` inbound and routes only that inbound to the special
  API outbound.
- `StatsService` is the only API service enabled. User byte counters are enabled
  at policy level `0`; system counters remain disabled.
- Node Host invokes the explicitly pinned Xray binary directly, with a cleared
  environment, fixed arguments, no shell, a four-second timeout, and one MiB
  bounds on each output stream. Queries never reset Xray counters.

## Delta and recovery rules

The last cumulative counter pair is stored per logical user together with the
durable Xray runtime generation. A successful sample updates counter baselines
and appends telemetry events in one SQLite `IMMEDIATE` transaction.

- The first sample establishes a baseline and emits no traffic.
- A same-generation increase emits only the exact byte delta.
- A changed runtime generation establishes a new baseline and emits
  `xray_stats_restarted`; no pre-restart bytes are repeated.
- A same-generation decrease establishes a new baseline for the affected user
  and emits `xray_stats_counter_reset`; no negative delta is possible.
- Query failures emit one deduplicated `xray_stats_unavailable` transition.
  Recovery emits the matching `recovered` event and includes bytes accumulated
  since the last successful same-generation sample.
- Unknown users or malformed counters are rejected as
  `xray_stats_invalid_output` without changing baselines.

`TrafficDelta.connectionCount` is always zero because the Stats API byte
counters do not provide an exact new-connection count. Node Host does not derive
that field from online sessions or traffic volume.
