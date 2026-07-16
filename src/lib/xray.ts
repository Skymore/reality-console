export type XraySnapshot = {
  installed: boolean
  binaryPath?: string | null
  version?: string | null
  serviceManageable: boolean
  serviceManager?: string | null
  running: boolean
  pid?: number | null
  configPath?: string | null
  publicIpv4?: string | null
  lanIp?: string | null
  listenPort?: number | null
  userCount?: number | null
  realityTarget?: string | null
  serverName?: string | null
  notes: string[]
}
