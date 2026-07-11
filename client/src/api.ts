import { invoke } from "@tauri-apps/api/core"

export type ClientPhase = "disconnected" | "starting" | "connected" | "stopping" | "failed"

export type ProxyMode = "manual" | "system"

export type LocalProxyEndpoints = {
  socks: string
  http: string
}

export type ClientState = {
  phase: ClientPhase
  activeProfileId?: string | null
  mode?: ProxyMode | null
  endpoints: LocalProxyEndpoints
  errorCode?: string | null
  errorMessage?: string | null
}

export type ClientError = {
  code: string
  message: string
  field?: string | null
}

export type InvitationPreview = {
  name: string
  serverAddress: string
  serverPort: number
  transport: "raw"
  security: "reality"
  flow: string
  serverName: string
  fingerprint: string
}

export function getClientState() {
  return invoke<ClientState>("client_get_state")
}

export function previewInvitation(invitation: string) {
  return invoke<InvitationPreview>("client_preview_invitation", { invitation })
}
