import { invoke } from "@tauri-apps/api/core"

export type Presence = "present" | "missing"

export type SystemPackageStatus = {
  platform: string
  agent: Presence
  serviceDefinition: Presence
  serviceRegistration: Presence
  stateDirectory: Presence
}

export type SetupPreview = {
  displayName: string
  controllerOrigin: string
  controllerFingerprint: string
  expiresAt: string
}

export type SetupSession = {
  sessionId: string
  preview: SetupPreview
}

export type WeeklyScheduleWindow = {
  weekday: number
  startMinute: number
  endMinute: number
}

export type ProviderPolicy = {
  schemaVersion: number
  paused: boolean
  weeklySchedule: WeeklyScheduleWindow[]
  monthlyTransferCapBytes: number | null
  maxConcurrentSessions: number
  bandwidthLimitBps: number | null
}

export type ProviderPolicyStatus = {
  policy: ProviderPolicy
  generation: number
  updatedAt: string
  availability: "available" | "providerPaused" | "outsideSchedule" | "transferCapReached"
  monthUsage: {
    utcMonth: string
    observedBytes: number
    capBytes: number | null
    remainingBytes: number | null
    coverage: string
    lastObservedAt: string | null
  }
  manualEndpoint: {
    configured: boolean
    current: boolean
    appliedRevision: number | null
    expiresAt: string | null
  }
}

export type SystemServiceStatus = {
  phase: "unpaired" | "enrolled" | "ready" | "needsAttention"
  packageVerified: boolean
  nodeId: string | null
  appliedRevision: number | null
  lastSyncAt: string | null
  providerPolicy: ProviderPolicyStatus | null
  serviceInstanceId: string | null
  runtimeState: string | null
  setupPhase: string | null
  directVerification: "pending" | "verified"
  relayVerification: "pending" | "verified"
  relayConnection: "notRegistered" | "registered"
}

export type ConfirmSetupInput = {
  authority: { acceptHostOwner: boolean; acceptExitIp: boolean }
  sharing: { acceptRouterMapping: boolean; acceptRelay: boolean }
  providerPolicy: ProviderPolicy
}

export const defaultPolicy = (): ProviderPolicy => ({
  schemaVersion: 1,
  paused: false,
  weeklySchedule: [],
  monthlyTransferCapBytes: 100 * 1024 ** 3,
  maxConcurrentSessions: 16,
  bandwidthLimitBps: 20_000_000,
})

export const getPackageStatus = () => invoke<SystemPackageStatus>("node_system_package_status")
export const getServiceStatus = () => invoke<SystemServiceStatus>("node_system_service_status")
export const beginSetup = (input: string) => invoke<SetupSession>("node_begin_setup", { input })
export const cancelSetup = (sessionId: string) => invoke<boolean>("node_cancel_setup", { sessionId })
export const confirmSetup = (sessionId: string, input: ConfirmSetupInput) =>
  invoke<SystemServiceStatus>("node_confirm_system_setup", { sessionId, input })
export const updatePolicy = (providerPolicy: ProviderPolicy) =>
  invoke<ProviderPolicyStatus>("node_update_provider_policy", { providerPolicy })
export const pauseProvider = () => invoke<ProviderPolicyStatus>("node_pause_provider")
export const resumeProvider = () => invoke<ProviderPolicyStatus>("node_resume_provider")
export const configureManualEndpoint = (endpoint: {
  address: string
  publicPort: number
  forwardedLocalPort: number
  ttlSeconds: number
}) => invoke<ProviderPolicyStatus["manualEndpoint"]>("node_configure_manual_endpoint", { endpoint })
export const clearManualEndpoint = () => invoke<void>("node_clear_manual_endpoint")
export const unpair = (confirmNodeId: string) =>
  invoke<SystemServiceStatus>("node_unpair", { confirmNodeId })
