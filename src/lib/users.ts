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
  userEmail: string
  timestamp: string
  clientIp: string
  destination: string
}

export type UserQuota = {
  userId: string
  monthlyQuotaBytes: number
  usedThisMonth: number
  lastResetMonth: string
}
