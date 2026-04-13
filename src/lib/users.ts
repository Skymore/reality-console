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
