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

export type StoredProfile = {
  id: string
  name: string
  serverAddress: string
  serverPort: number
  serverName: string
  flow: string
  fingerprint: string
  createdAt: number
  credentialAvailable: boolean
}

export function getClientState() {
  return invoke<ClientState>("client_get_state")
}

export function startClient(profileId: string, mode: ProxyMode = "manual") {
  return invoke<ClientState>("client_start", { profileId, mode })
}

export function stopClient() {
  return invoke<ClientState>("client_stop")
}

export function previewInvitation(invitation: string) {
  return invoke<InvitationPreview>("client_preview_invitation", { invitation })
}

export function listProfiles() {
  return invoke<StoredProfile[]>("client_list_profiles")
}

export function importProfile(invitation: string, name?: string) {
  return invoke<StoredProfile>("client_import_profile", { invitation, name })
}

export function renameProfile(profileId: string, name: string) {
  return invoke<StoredProfile>("client_rename_profile", { profileId, name })
}

export function deleteProfile(profileId: string) {
  return invoke<void>("client_delete_profile", { profileId })
}

export function previewProfile(profileId: string) {
  return invoke<InvitationPreview>("client_preview_profile", { profileId })
}
