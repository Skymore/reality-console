export type ManagedUser = {
  id: string
  label: string
  flow?: string | null
  note?: string | null
  createdAt?: number | null
  shareLink?: string | null
}

export type UserListResponse = {
  configPath?: string | null
  metadataPath?: string | null
  users: ManagedUser[]
}

export type UserMutationResult = {
  backupPath: string
  users: ManagedUser[]
}

export type CreateUserInput = {
  label?: string
  note?: string
}

export type UserTraffic = {
  userId?: string | null
  email: string
  uplink: number
  downlink: number
}

export type TrafficResponse = {
  available: boolean
  apiPort?: number | null
  users: UserTraffic[]
  error?: string | null
}

export type ConnectionLog = {
  id: number
  userId: string
  userEmail: string
  timestamp: string
  clientIp: string
  destination: string
  network: string
}

export type UserQuota = {
  userId: string
  monthlyQuotaBytes: number
  usedThisMonth: number
  lastResetMonth: string
}

export type TrafficRefreshResponse = {
  traffic: TrafficResponse
  quotas: UserQuota[]
}

export type UserAnalyticsRange = "24h" | "7d" | "30d" | "90d" | "custom"

export type UserAnalytics = {
  nodeId: string
  userId: string
  from: number
  to: number
  uplinkBytes: number
  downlinkBytes: number
  connectionCount: number
  uniqueClientIps: number
  firstSeenAt?: number | null
  lastSeenAt?: number | null
  activeDays: number
  recentlyActive: boolean
  quota?: UserQuota | null
  daily: Array<{
    day: string
    uplinkBytes: number
    downlinkBytes: number
    connectionCount: number
    uniqueClientIps: number
  }>
  topClientIps: Array<{ value: string; count: number; lastSeenAt?: number | null }>
  topDestinations: Array<{ value: string; count: number; lastSeenAt?: number | null }>
  recentConnections: ConnectionLog[]
  lastTrafficSampleAt?: number | null
  lastLogImportAt?: number | null
}
