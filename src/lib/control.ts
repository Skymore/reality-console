export type ControlNetwork = {
  networkId: string
  displayName: string
  status: string
  lastRevision: number
  controllerEpoch: string
  createdAt: string
  updatedAt: string
}

export type ControlNode = {
  nodeId: string
  networkId: string
  displayName: string
  status: "pending" | "active" | "disabled" | "revoked" | string
  platform: string
  agentVersion: string
  xrayVersion?: string | null
  publicMaterialReady: boolean
  onboardingState: string
  capabilities: string[]
  lastSeenAt?: string | null
  runtimeState?: string | null
  providerPaused: boolean
  revisions: {
    desiredRevision?: number | null
    receivedRevision?: number | null
    validatedRevision?: number | null
    appliedRevision?: number | null
  }
  lastFailure?: { code?: string; message?: string } | null
  createdAt: string
  updatedAt: string
}

export type AccountAssignment = {
  assignmentId: string
  nodeId: string
  status: string
  provisioningState: string
}

export type ControlAccount = {
  account: {
    userId: string
    displayName: string
    status: "active" | "disabled" | "deleted" | string
  }
  assignments: AccountAssignment[]
  createdAt: string
  updatedAt: string
}

export type ControlSnapshot = {
  installed: boolean
  healthy: boolean
  localOrigin?: string | null
  publicOrigin?: string | null
  network?: ControlNetwork | null
  nodes: ControlNode[]
  accounts: ControlAccount[]
  error?: string | null
}

export type SetupDelivery = {
  displayName: string
  expiresAt: number
  setupCode: string
  setupLink: string
}
