import { invoke } from "@tauri-apps/api/core"

export type ClientPhase = "disconnected" | "starting" | "connected" | "stopping" | "failed"
export type ProxyMode = "manual" | "system"

export type ClientState = {
  phase: ClientPhase
  activeProfileId: string | null
  mode: ProxyMode | null
  endpoints: { socks: string; http: string }
  errorCode: string | null
  errorMessage: string | null
}

export type AccountSession = {
  phase: "signedOut" | "refreshRequired" | "active"
  binding: { networkId: string; userId: string; deviceId: string } | null
  account: { userId: string; displayName: string; status: "active" | "disabled" | "deleted" } | null
  accessExpiresAt: string | null
  refreshExpiresAt: string | null
  refreshRotation: number | null
}

export type SafeNode = {
  nodeId: string
  displayName: string
  region: string | null
  endpointMode: "direct" | "relay"
  priority: number
}

export type SelectionMode =
  | { kind: "automatic" }
  | { kind: "manual"; nodes: string }
  | { kind: "pinnedFallback"; nodes: string[] }

export type ConnectSnapshot = {
  session: AccountSession
  bundle: {
    generation: number
    refreshAfter: string
    offlineExpiresAt: string
    nodes: SafeNode[]
  } | null
  selectionMode: SelectionMode
  selectedNodeId: string | null
  selectionReason: string | null
  runtime: ClientState
}

export type SetupSession = {
  sessionId: string
  preview: { displayName: string; controllerOrigin: string; expiresAt: string }
}

export const getSnapshot = () => invoke<ConnectSnapshot | null>("connect_get_snapshot")
export const beginSetup = (input: string) => invoke<SetupSession>("connect_begin_setup", { input })
export const cancelSetup = (sessionId: string) => invoke<boolean>("connect_cancel_setup", { sessionId })
export const confirmSetup = (sessionId: string, deviceName: string) =>
  invoke<ConnectSnapshot>("connect_confirm_setup", { sessionId, deviceName })
export const refreshBundle = () => invoke<ConnectSnapshot>("connect_refresh_bundle")
export const probeNodes = () => invoke<ConnectSnapshot>("connect_probe_nodes")
export const setSelection = (selection: SelectionMode) =>
  invoke<ConnectSnapshot>("connect_set_selection", { selection })
export const connect = (mode: ProxyMode = "system") =>
  invoke<ConnectSnapshot>("connect_start", { mode })
export const disconnect = () => invoke<ConnectSnapshot>("connect_stop")
export const logout = () => invoke<ConnectSnapshot>("connect_logout")
