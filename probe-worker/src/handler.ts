import {
  parseTcpProbeRequest,
  response,
  type TcpProbeRequest,
  type TcpProbeResult,
} from "./protocol";

const ROUTE = "/v1/tcp-probe";
const MAX_BODY_BYTES = 4 * 1024;
const MIN_TOKEN_BYTES = 32;
const MAX_TOKEN_BYTES = 4 * 1024;

export interface ProbeEnv {
  PROBE_TOKEN?: string;
}

export interface TcpSocket {
  opened: Promise<unknown>;
  close(): Promise<void>;
}

export type TcpConnector = (
  address: { hostname: string; port: number },
  options: { secureTransport: "off"; allowHalfOpen: false },
) => TcpSocket;

interface SocketAttempt {
  target: string;
  socket: TcpSocket;
}

export async function handleRequest(
  request: Request,
  env: ProbeEnv,
  connector: TcpConnector,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== ROUTE || url.search !== "") {
    return emptyResponse(404);
  }
  if (request.method !== "POST") {
    return emptyResponse(405, { Allow: "POST" });
  }
  if (!(await isAuthorized(request.headers.get("authorization"), env.PROBE_TOKEN))) {
    return emptyResponse(401);
  }
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return emptyResponse(415);
  }

  const body = await readBoundedBody(request, MAX_BODY_BYTES);
  if (body === null) {
    return emptyResponse(413);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(body);
  } catch {
    return emptyResponse(400);
  }
  const probe = parseTcpProbeRequest(decoded);
  if (probe === null) {
    return emptyResponse(400);
  }

  const result = await executeProbe(probe, connector);
  return jsonResponse(response(probe, result));
}

async function executeProbe(
  request: TcpProbeRequest,
  connector: TcpConnector,
): Promise<TcpProbeResult> {
  const attempts: SocketAttempt[] = [];
  for (const target of request.targets) {
    try {
      attempts.push({
        target,
        socket: connector(
          { hostname: target, port: request.port },
          { secureTransport: "off", allowHalfOpen: false },
        ),
      });
    } catch {
      // A synchronous provider rejection is one failed target, never a reason
      // to expose provider diagnostics or the target in the HTTP response.
    }
  }
  if (attempts.length === 0) {
    return { status: "executorFailed" };
  }

  const started = performance.now();
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  const result = await Promise.race([
    firstConnectionOrAllFailed(attempts, started),
    new Promise<TcpProbeResult>((resolve) => {
      timeoutHandle = setTimeout(() => {
        resolve({
          status: "timedOut",
          latencyMillis: elapsedMillis(started),
        });
      }, request.timeoutMillis);
    }),
  ]);
  if (timeoutHandle !== undefined) {
    clearTimeout(timeoutHandle);
  }
  for (const { socket } of attempts) {
    void socket.close().catch(() => undefined);
  }
  return result;
}

function firstConnectionOrAllFailed(
  attempts: SocketAttempt[],
  started: number,
): Promise<TcpProbeResult> {
  return new Promise((resolve) => {
    let remaining = attempts.length;
    for (const { target, socket } of attempts) {
      socket.opened.then(
        () => {
          resolve({
            status: "connected",
            resolvedAddress: target,
            latencyMillis: elapsedMillis(started),
          });
        },
        () => {
          remaining -= 1;
          if (remaining === 0) {
            resolve({
              status: "unreachable",
              latencyMillis: elapsedMillis(started),
            });
          }
        },
      );
    }
  });
}

async function isAuthorized(header: string | null, expected: string | undefined): Promise<boolean> {
  if (
    typeof expected !== "string" ||
    expected.length < MIN_TOKEN_BYTES ||
    expected.length > MAX_TOKEN_BYTES ||
    header === null ||
    !header.startsWith("Bearer ") ||
    header.includes(",")
  ) {
    return false;
  }
  const candidate = header.slice("Bearer ".length);
  if (candidate.length < MIN_TOKEN_BYTES || candidate.length > MAX_TOKEN_BYTES) {
    return false;
  }
  const encoder = new TextEncoder();
  const [expectedDigest, candidateDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
    crypto.subtle.digest("SHA-256", encoder.encode(candidate)),
  ]);
  const left = new Uint8Array(expectedDigest);
  const right = new Uint8Array(candidateDigest);
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

async function readBoundedBody(request: Request, maximum: number): Promise<string | null> {
  if (request.body === null) {
    return null;
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    return null;
  }
}

function elapsedMillis(started: number): number {
  return Math.min(0xffff_ffff, Math.max(0, Math.round(performance.now() - started)));
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: securityHeaders({ "Content-Type": "application/json; charset=utf-8" }),
  });
}

function emptyResponse(status: number, headers: Record<string, string> = {}): Response {
  return new Response(null, { status, headers: securityHeaders(headers) });
}

function securityHeaders(headers: Record<string, string>): Headers {
  return new Headers({
    ...headers,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
}
