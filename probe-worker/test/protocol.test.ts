import { describe, expect, it } from "vitest";
import {
  isPublicIpv4,
  parseTcpProbeRequest,
  response,
  TCP_PROBE_SCHEMA_VERSION,
  type TcpProbeRequest,
} from "../src/protocol";

function validRequest(): TcpProbeRequest {
  return {
    schemaVersion: TCP_PROBE_SCHEMA_VERSION,
    requestId: "4ec1ade7-9d5a-4c1c-9c55-26fef8270e64",
    targets: ["8.8.8.8", "1.1.1.1"],
    port: 443,
    timeoutMillis: 5_000,
  };
}

describe("parseTcpProbeRequest", () => {
  it("accepts only the closed privacy-minimized shape", () => {
    expect(parseTcpProbeRequest(validRequest())).toEqual(validRequest());
    expect(parseTcpProbeRequest({ ...validRequest(), nodeId: "not-allowed" })).toBeNull();
    expect(parseTcpProbeRequest({ ...validRequest(), targets: ["8.8.8.8", "8.8.8.8"] })).toBeNull();
    expect(parseTcpProbeRequest({ ...validRequest(), port: 25 })).toBeNull();
  });

  it("rejects private, special, documentation, and non-canonical addresses", () => {
    for (const target of [
      "127.0.0.1",
      "10.0.0.1",
      "100.64.0.1",
      "169.254.1.1",
      "192.0.2.1",
      "198.18.0.1",
      "203.0.113.1",
      "224.0.0.1",
      "008.008.008.008",
      "8.8.8",
    ]) {
      expect(isPublicIpv4(target), target).toBe(false);
      expect(parseTcpProbeRequest({ ...validRequest(), targets: [target] })).toBeNull();
    }
    expect(isPublicIpv4("8.8.4.4")).toBe(true);
  });
});

describe("response", () => {
  it("echoes only correlation identity and secret-free evidence", () => {
    const request = validRequest();
    expect(
      response(request, {
        status: "connected",
        resolvedAddress: "8.8.8.8",
        latencyMillis: 9,
      }),
    ).toEqual({
      schemaVersion: 1,
      requestId: request.requestId,
      result: {
        status: "connected",
        resolvedAddress: "8.8.8.8",
        latencyMillis: 9,
      },
    });
  });
});
