import { describe, expect, it, vi } from "vitest";
import {
  handleRequest,
  type ProbeEnv,
  type TcpConnector,
  type TcpSocket,
} from "../src/handler";

const TOKEN = "external-probe-token-with-at-least-32-bytes";
const ENV: ProbeEnv = { PROBE_TOKEN: TOKEN };

function body(): string {
  return JSON.stringify({
    schemaVersion: 1,
    requestId: "4ec1ade7-9d5a-4c1c-9c55-26fef8270e64",
    targets: ["8.8.8.8", "1.1.1.1"],
    port: 443,
    timeoutMillis: 5_000,
  });
}

function request(value = body(), token = TOKEN): Request {
  return new Request("https://probe.example/v1/tcp-probe", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: value,
  });
}

describe("handleRequest", () => {
  it("authenticates before parsing or connecting", async () => {
    const connector = vi.fn<TcpConnector>();
    const result = await handleRequest(request("{", `${TOKEN}-wrong`), ENV, connector);
    expect(result.status).toBe(401);
    expect(connector).not.toHaveBeenCalled();
    expect(result.headers.get("cache-control")).toBe("no-store");

    const missingSecret = await handleRequest(request(), {}, connector);
    expect(missingSecret.status).toBe(401);
    expect(connector).not.toHaveBeenCalled();
  });

  it("returns the first connected pinned address and closes every socket", async () => {
    const closeFirst = vi.fn(async () => undefined);
    const closeSecond = vi.fn(async () => undefined);
    let calls = 0;
    const connector = vi.fn<TcpConnector>(() => {
      calls += 1;
      if (calls === 1) {
        return {
          opened: new Promise((_, reject) => {
            setTimeout(() => reject(new Error("unreachable")), 0);
          }),
          close: closeFirst,
        } satisfies TcpSocket;
      }
      return { opened: Promise.resolve({}), close: closeSecond } satisfies TcpSocket;
    });

    const result = await handleRequest(request(), ENV, connector);
    expect(result.status).toBe(200);
    expect(await result.json()).toMatchObject({
      schemaVersion: 1,
      requestId: "4ec1ade7-9d5a-4c1c-9c55-26fef8270e64",
      result: { status: "connected", resolvedAddress: "1.1.1.1" },
    });
    expect(connector).toHaveBeenCalledTimes(2);
    expect(closeFirst).toHaveBeenCalledOnce();
    expect(closeSecond).toHaveBeenCalledOnce();
  });

  it("rejects oversized streaming bodies before connecting", async () => {
    const connector = vi.fn<TcpConnector>();
    const oversized = request("a".repeat(4 * 1024 + 1));
    const result = await handleRequest(oversized, ENV, connector);
    expect(result.status).toBe(413);
    expect(connector).not.toHaveBeenCalled();
  });

  it("returns at the deadline without waiting for socket cleanup", async () => {
    const close = vi.fn(() => new Promise<void>(() => undefined));
    const connector = vi.fn<TcpConnector>(() => ({
      opened: new Promise(() => undefined),
      close,
    }));
    const timeoutRequest = request(
      JSON.stringify({
        ...JSON.parse(body()),
        targets: ["8.8.8.8"],
        timeoutMillis: 100,
      }),
    );

    const started = performance.now();
    const result = await handleRequest(timeoutRequest, ENV, connector);
    const elapsed = performance.now() - started;
    expect(result.status).toBe(200);
    expect(await result.json()).toMatchObject({ result: { status: "timedOut" } });
    expect(close).toHaveBeenCalledOnce();
    expect(elapsed).toBeLessThan(1_000);
  });

  it("does not accept alternate paths or query strings", async () => {
    const connector = vi.fn<TcpConnector>();
    const alternate = request();
    const withQuery = new Request(`${alternate.url}?target=8.8.8.8`, alternate);
    const result = await handleRequest(withQuery, ENV, connector);
    expect(result.status).toBe(404);
    expect(connector).not.toHaveBeenCalled();
  });
});
