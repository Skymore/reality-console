export const TCP_PROBE_SCHEMA_VERSION = 1;
export const MAX_TCP_PROBE_TARGETS = 6;
export const MIN_TCP_PROBE_TIMEOUT_MILLIS = 100;
export const MAX_TCP_PROBE_TIMEOUT_MILLIS = 10_000;

export interface TcpProbeRequest {
  schemaVersion: 1;
  requestId: string;
  targets: string[];
  port: number;
  timeoutMillis: number;
}

export type TcpProbeResult =
  | {
      status: "connected";
      resolvedAddress: string;
      latencyMillis: number;
    }
  | {
      status: "unreachable";
      latencyMillis: number;
    }
  | {
      status: "timedOut";
      latencyMillis: number;
    }
  | {
      status: "executorFailed";
    };

export interface TcpProbeResponse {
  schemaVersion: 1;
  requestId: string;
  result: TcpProbeResult;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REQUEST_KEYS = ["port", "requestId", "schemaVersion", "targets", "timeoutMillis"];

export function parseTcpProbeRequest(value: unknown): TcpProbeRequest | null {
  if (!isRecord(value) || !hasExactKeys(value, REQUEST_KEYS)) {
    return null;
  }
  if (
    value.schemaVersion !== TCP_PROBE_SCHEMA_VERSION ||
    typeof value.requestId !== "string" ||
    !UUID_PATTERN.test(value.requestId) ||
    !Array.isArray(value.targets) ||
    value.targets.length === 0 ||
    value.targets.length > MAX_TCP_PROBE_TARGETS ||
    !isIntegerInRange(value.port, 1, 65_535) ||
    value.port === 25 ||
    !isIntegerInRange(
      value.timeoutMillis,
      MIN_TCP_PROBE_TIMEOUT_MILLIS,
      MAX_TCP_PROBE_TIMEOUT_MILLIS,
    )
  ) {
    return null;
  }

  const targets: string[] = [];
  for (const target of value.targets) {
    if (typeof target !== "string" || !isPublicIpv4(target)) {
      return null;
    }
    targets.push(target);
  }
  if (new Set(targets).size !== targets.length) {
    return null;
  }

  return {
    schemaVersion: TCP_PROBE_SCHEMA_VERSION,
    requestId: value.requestId,
    targets,
    port: value.port,
    timeoutMillis: value.timeoutMillis,
  };
}

export function response(request: TcpProbeRequest, result: TcpProbeResult): TcpProbeResponse {
  return {
    schemaVersion: TCP_PROBE_SCHEMA_VERSION,
    requestId: request.requestId,
    result,
  };
}

export function isPublicIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) {
      return false;
    }
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet > 255) {
      return false;
    }
    octets.push(octet);
  }
  const [first, second, third, fourth] = octets as [number, number, number, number];
  if (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 192 && second === 0 && third === 0) ||
    (first === 192 && second === 0 && third === 2) ||
    (first === 198 && (second === 18 || second === 19)) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113) ||
    (first === 255 && second === 255 && third === 255 && fourth === 255)
  ) {
    return false;
  }
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function isIntegerInRange(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= minimum && value <= maximum;
}
