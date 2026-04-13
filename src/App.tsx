import { invoke } from "@tauri-apps/api/core"
import { startTransition, useEffect, useMemo, useState } from "react"
import type { LucideIcon } from "lucide-react"
import {
  Archive,
  ArrowUpRight,
  FileText,
  Globe,
  LayoutDashboard,
  RefreshCcw,
  Server,
  Settings2,
  Shield,
  Sparkles,
  Stethoscope,
  Users,
} from "lucide-react"

import { UsersPage } from "@/components/users-page"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { CreateUserInput, UserListResponse, UserMutationResult } from "@/lib/users"
import type { XraySnapshot } from "@/lib/xray"
import { cn } from "@/lib/utils"

type PageId =
  | "dashboard"
  | "users"
  | "config"
  | "diagnostics"
  | "logs"
  | "backups"
  | "settings"

type NavItem = {
  id: PageId
  label: string
  hint: string
  icon: LucideIcon
}

const navItems: NavItem[] = [
  { id: "dashboard", label: "Dashboard", hint: "Live overview", icon: LayoutDashboard },
  { id: "users", label: "Users", hint: "UUIDs and sharing", icon: Users },
  { id: "config", label: "Config", hint: "REALITY parameters", icon: Shield },
  { id: "diagnostics", label: "Diagnostics", hint: "Network and service checks", icon: Stethoscope },
  { id: "logs", label: "Logs", hint: "Runtime events", icon: FileText },
  { id: "backups", label: "Backups", hint: "Restore points", icon: Archive },
  { id: "settings", label: "Settings", hint: "Local preferences", icon: Settings2 },
]

const fallbackSnapshot: XraySnapshot = {
  installed: false,
  running: false,
  notes: [],
}

function App() {
  const [activePage, setActivePage] = useState<PageId>("dashboard")
  const [snapshot, setSnapshot] = useState<XraySnapshot | null>(null)
  const [usersResponse, setUsersResponse] = useState<UserListResponse | null>(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [snapshotError, setSnapshotError] = useState<string | null>(null)
  const [usersError, setUsersError] = useState<string | null>(null)
  const [mutationNotice, setMutationNotice] = useState<string | null>(null)

  const activeNavItem = useMemo(
    () => navItems.find((item) => item.id === activePage) ?? navItems[0],
    [activePage],
  )

  const currentSnapshot = snapshot ?? fallbackSnapshot
  const currentUsers = usersResponse?.users ?? []
  const serviceLabel = getServiceLabel(currentSnapshot)
  const endpointLabel =
    currentSnapshot.publicIpv4 && currentSnapshot.listenPort
      ? `${currentSnapshot.publicIpv4}:${currentSnapshot.listenPort}`
      : currentSnapshot.listenPort
        ? `Port ${currentSnapshot.listenPort}`
        : "Not detected"
  const userLabel =
    currentUsers.length > 0
      ? `${currentUsers.length} UUIDs`
      : currentSnapshot.userCount !== undefined && currentSnapshot.userCount !== null
        ? `${currentSnapshot.userCount} UUIDs`
        : "Unknown"

  async function loadSnapshot() {
    return invoke<XraySnapshot>("get_xray_snapshot")
  }

  async function loadUsers() {
    return invoke<UserListResponse>("get_vless_users")
  }

  async function refreshAll() {
    try {
      setIsRefreshing(true)
      const [nextSnapshot, nextUsers] = await Promise.allSettled([loadSnapshot(), loadUsers()])

      startTransition(() => {
        if (nextSnapshot.status === "fulfilled") {
          setSnapshot(nextSnapshot.value)
          setSnapshotError(null)
        } else {
          setSnapshotError(toErrorMessage(nextSnapshot.reason, "Snapshot request failed."))
        }

        if (nextUsers.status === "fulfilled") {
          setUsersResponse(nextUsers.value)
          setUsersError(null)
        } else {
          setUsersError(toErrorMessage(nextUsers.reason, "User list request failed."))
        }
      })
    } finally {
      setIsRefreshing(false)
    }
  }

  async function refreshSnapshotOnly() {
    const nextSnapshot = await loadSnapshot()
    startTransition(() => {
      setSnapshot(nextSnapshot)
      setSnapshotError(null)
    })
  }

  async function handleCreateUser(input: CreateUserInput) {
    try {
      const result = await invoke<UserMutationResult>("create_vless_user", { input })
      startTransition(() => {
        setUsersResponse((current) => ({
          configPath: current?.configPath ?? currentSnapshot.configPath ?? null,
          metadataPath: current?.metadataPath ?? null,
          users: result.users,
        }))
        setMutationNotice(`User saved. Backup created at ${result.backupPath}.`)
        setUsersError(null)
      })
      await refreshSnapshotOnly()
    } catch (error) {
      const message = toErrorMessage(error, "Failed to create user.")
      setUsersError(message)
      throw new Error(message)
    }
  }

  async function handleDeleteUser(userId: string) {
    try {
      const result = await invoke<UserMutationResult>("delete_vless_user", { userId })
      startTransition(() => {
        setUsersResponse((current) => ({
          configPath: current?.configPath ?? currentSnapshot.configPath ?? null,
          metadataPath: current?.metadataPath ?? null,
          users: result.users,
        }))
        setMutationNotice(`User deleted. Backup created at ${result.backupPath}.`)
        setUsersError(null)
      })
      await refreshSnapshotOnly()
    } catch (error) {
      const message = toErrorMessage(error, "Failed to delete user.")
      setUsersError(message)
      throw new Error(message)
    }
  }

  useEffect(() => {
    void refreshAll()
  }, [])

  return (
    <TooltipProvider delayDuration={120}>
      <div className="relative min-h-screen overflow-hidden text-foreground">
        <div className="pointer-events-none absolute inset-x-0 top-0 h-72 bg-[radial-gradient(circle_at_top,_rgb(201_100_66_/_0.15),_transparent_56%)]" />
        <div className="relative flex min-h-screen">
          <aside className="hidden w-80 border-r border-border/60 bg-panel/75 px-5 py-5 shadow-panel backdrop-blur-xl lg:flex">
            <ScrollArea className="flex-1">
              <div className="flex h-full flex-col gap-6 pr-4">
                <div className="rounded-3xl border border-border/60 bg-background/70 p-5 shadow-float">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                        Reality Console
                      </p>
                      <h1 className="mt-3 font-heading text-3xl leading-none">
                        Warm control for a very technical box.
                      </h1>
                    </div>
                    <Badge className="rounded-full bg-primary/12 px-3 py-1 text-primary hover:bg-primary/12">
                      macOS first
                    </Badge>
                  </div>

                  <div className="mt-6 grid gap-3">
                    <InfoStrip
                      label="Current node"
                      value={currentSnapshot.binaryPath ? "Local xray detected" : "Waiting for probe"}
                    />
                    <InfoStrip label="Live users" value={userLabel} />
                    <InfoStrip label="Inbound" value={endpointLabel} />
                  </div>
                </div>

                <div className="space-y-2">
                  <p className="px-2 text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                    Workspace
                  </p>
                  {navItems.map((item) => {
                    const Icon = item.icon
                    const active = item.id === activePage

                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setActivePage(item.id)}
                        className={cn(
                          "group flex w-full items-center gap-3 rounded-2xl border px-3 py-3 text-left transition-colors",
                          active
                            ? "border-primary/20 bg-primary/10 text-foreground shadow-[0_12px_40px_rgb(201_100_66_/_0.09)]"
                            : "border-transparent bg-transparent text-muted-foreground hover:border-border/70 hover:bg-background/70 hover:text-foreground",
                        )}
                      >
                        <div
                          className={cn(
                            "flex size-10 items-center justify-center rounded-2xl border transition-colors",
                            active
                              ? "border-primary/20 bg-primary/12 text-primary"
                              : "border-border/70 bg-panel/80 text-muted-foreground group-hover:text-foreground",
                          )}
                        >
                          <Icon className="size-4.5" />
                        </div>
                        <div className="min-w-0">
                          <div className="font-medium">{item.label}</div>
                          <div className="truncate text-xs text-muted-foreground">{item.hint}</div>
                        </div>
                      </button>
                    )
                  })}
                </div>

                <Card className="border-border/70 bg-secondary/70 shadow-none">
                  <CardHeader className="pb-3">
                    <CardTitle className="font-heading text-xl">Snapshot notes</CardTitle>
                    <CardDescription>
                      The backend now probes local process state, config shape, and network basics.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    {snapshotError ? (
                      <MilestoneRow label={snapshotError} tone="danger" />
                    ) : currentSnapshot.notes.length > 0 ? (
                      currentSnapshot.notes.slice(0, 4).map((note) => (
                        <MilestoneRow key={note} label={note} tone="warning" />
                      ))
                    ) : (
                      <>
                        <MilestoneRow done label="Local probe completed" />
                        <MilestoneRow done={currentSnapshot.installed} label="xray binary detected" />
                        <MilestoneRow done={currentSnapshot.running} label="Service running" />
                      </>
                    )}
                  </CardContent>
                </Card>
              </div>
            </ScrollArea>
          </aside>

          <main className="flex-1 px-4 py-4 sm:px-6 lg:px-8 lg:py-6">
            <div className="mx-auto flex min-h-[calc(100vh-2rem)] max-w-7xl flex-col rounded-[2rem] border border-border/60 bg-background/70 shadow-panel backdrop-blur-xl">
              <header className="flex flex-col gap-5 border-b border-border/60 px-5 py-5 sm:px-8 lg:px-10 lg:py-6">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="space-y-3">
                    <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">
                      <Sparkles className="size-3.5 text-primary" />
                      Phase 6 user management MVP
                    </div>
                    <div>
                      <h2 className="font-heading text-4xl leading-[0.95] sm:text-5xl">
                        {activeNavItem.label}
                      </h2>
                      <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground sm:text-base">
                        {activeNavItem.hint}. The shell now includes config-backed user listing, safe
                        add/delete flows, local metadata notes, and real VLESS share links.
                      </p>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      className="rounded-full px-4"
                      onClick={() => void refreshAll()}
                      disabled={isRefreshing}
                    >
                      <RefreshCcw className={cn("size-4", isRefreshing && "animate-spin")} />
                      {isRefreshing ? "Refreshing..." : "Refresh data"}
                    </Button>
                    <Button className="rounded-full px-4" onClick={() => setActivePage("diagnostics")}>
                      Open diagnostics
                      <ArrowUpRight className="size-4" />
                    </Button>
                  </div>
                </div>

                <div className="grid gap-3 md:grid-cols-3">
                  <StatusChip
                    icon={Server}
                    label="Xray state"
                    value={serviceLabel}
                    hint={currentSnapshot.version ?? "Version not detected"}
                  />
                  <StatusChip
                    icon={Globe}
                    label="Public endpoint"
                    value={endpointLabel}
                    hint={currentSnapshot.lanIp ? `LAN ${currentSnapshot.lanIp}` : "LAN IP unknown"}
                  />
                  <StatusChip
                    icon={Users}
                    label="Friend slots"
                    value={userLabel}
                    hint={usersResponse?.configPath ?? currentSnapshot.configPath ?? "Config path unknown"}
                  />
                </div>
              </header>

              <ScrollArea className="flex-1">
                <div className="px-5 py-5 sm:px-8 lg:px-10 lg:py-8">
                  {renderPage({
                    activePage,
                    snapshot: currentSnapshot,
                    snapshotError,
                    usersResponse,
                    usersError,
                    mutationNotice,
                    isRefreshing,
                    onRefreshUsers: refreshAll,
                    onCreateUser: handleCreateUser,
                    onDeleteUser: handleDeleteUser,
                  })}
                </div>
              </ScrollArea>
            </div>
          </main>
        </div>
      </div>
    </TooltipProvider>
  )
}

function renderPage({
  activePage,
  snapshot,
  snapshotError,
  usersResponse,
  usersError,
  mutationNotice,
  isRefreshing,
  onRefreshUsers,
  onCreateUser,
  onDeleteUser,
}: {
  activePage: PageId
  snapshot: XraySnapshot
  snapshotError: string | null
  usersResponse: UserListResponse | null
  usersError: string | null
  mutationNotice: string | null
  isRefreshing: boolean
  onRefreshUsers: () => Promise<void>
  onCreateUser: (input: CreateUserInput) => Promise<void>
  onDeleteUser: (userId: string) => Promise<void>
}) {
  switch (activePage) {
    case "dashboard":
      return <DashboardPage snapshot={snapshot} loadError={snapshotError} />
    case "users":
      return (
        <UsersPage
          users={usersResponse?.users ?? []}
          configPath={usersResponse?.configPath}
          metadataPath={usersResponse?.metadataPath}
          isLoading={isRefreshing}
          error={usersError}
          mutationNotice={mutationNotice}
          onRefresh={onRefreshUsers}
          onCreateUser={onCreateUser}
          onDeleteUser={onDeleteUser}
        />
      )
    case "config":
      return <ConfigPage snapshot={snapshot} />
    case "diagnostics":
      return <DiagnosticsPage snapshot={snapshot} loadError={snapshotError ?? usersError} />
    case "logs":
      return <LogsPage />
    case "backups":
      return <BackupsPage />
    case "settings":
      return <SettingsPage />
  }
}

function DashboardPage({
  snapshot,
  loadError,
}: {
  snapshot: XraySnapshot
  loadError: string | null
}) {
  return (
    <div className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-[1.4fr_0.9fr]">
        <Card className="overflow-hidden border-border/60 bg-panel/80 shadow-panel">
          <CardContent className="p-0">
            <div className="relative overflow-hidden px-6 py-7 sm:px-7">
              <div className="absolute inset-y-0 right-0 w-1/2 bg-[radial-gradient(circle_at_top_right,_rgb(201_100_66_/_0.15),_transparent_58%)]" />
              <div className="relative max-w-2xl">
                <Badge className="rounded-full bg-primary/12 px-3 py-1 text-primary hover:bg-primary/12">
                  Local-first operator view
                </Badge>
                <h3 className="mt-4 max-w-xl font-heading text-3xl leading-[1.02] sm:text-4xl">
                  The app should answer one question instantly: is this node safe to share right now?
                </h3>
                <p className="mt-4 max-w-xl text-sm leading-6 text-muted-foreground sm:text-base">
                  The backend is already reporting the real binary path, process state, config location,
                  listen port, public IPv4, and REALITY target. User management now writes the live config
                  with backup and validation before restart-sensitive changes.
                </p>

                {loadError ? (
                  <div className="mt-5 rounded-3xl border border-destructive/25 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                    {loadError}
                  </div>
                ) : null}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/60 bg-secondary/75 shadow-none">
          <CardHeader>
            <CardTitle className="font-heading text-2xl">Live probe coverage</CardTitle>
            <CardDescription>What the app already knows from your local machine.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <ChecklistRow
              title="Install state"
              detail={snapshot.binaryPath ?? "Binary path not detected yet."}
            />
            <ChecklistRow
              title="Config source"
              detail={snapshot.configPath ?? "No config path detected in known locations."}
            />
            <ChecklistRow
              title="Network basics"
              detail={
                snapshot.publicIpv4
                  ? `Public IPv4 ${snapshot.publicIpv4}${snapshot.lanIp ? ` · LAN ${snapshot.lanIp}` : ""}`
                  : "Public IPv4 is currently unavailable."
              }
            />
            <ChecklistRow
              title="REALITY surface"
              detail={
                snapshot.realityTarget
                  ? `${snapshot.realityTarget}${snapshot.serverName ? ` · ${snapshot.serverName}` : ""}`
                  : "REALITY target not parsed from current config."
              }
            />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Process"
          value={snapshot.pid ? `PID ${snapshot.pid}` : snapshot.running ? "Running" : "Offline"}
          detail={snapshot.version ?? "Version unavailable"}
        />
        <MetricCard
          label="Share links"
          value={
            snapshot.userCount !== undefined && snapshot.userCount !== null
              ? String(snapshot.userCount)
              : "Unknown"
          }
          detail="One UUID per friend"
        />
        <MetricCard
          label="REALITY target"
          value={snapshot.serverName ?? "Unknown"}
          detail={snapshot.realityTarget ?? "Target not parsed"}
        />
        <MetricCard
          label="Listen port"
          value={snapshot.listenPort ? String(snapshot.listenPort) : "Unknown"}
          detail="Parsed from current config"
        />
      </div>
    </div>
  )
}

function ConfigPage({ snapshot }: { snapshot: XraySnapshot }) {
  return (
    <div className="grid gap-6 xl:grid-cols-3">
      <ConfigBlock
        title="Inbound"
        description="The local listener and its exposure model."
        lines={[
          "Protocol: VLESS",
          `Port: ${snapshot.listenPort ?? "Unknown"}`,
          `Users: ${snapshot.userCount ?? "Unknown"}`,
        ]}
      />
      <ConfigBlock
        title="REALITY"
        description="Parameters that must stay aligned with client import data."
        lines={[
          `Target: ${snapshot.realityTarget ?? "Unknown"}`,
          `SNI: ${snapshot.serverName ?? "Unknown"}`,
          `Config path: ${snapshot.configPath ?? "Unknown"}`,
        ]}
      />
      <ConfigBlock
        title="Config safety"
        description="Every write should be previewed, validated, backed up, and only then restarted."
        lines={["Create backup", "Run xray -test", "Replace config atomically"]}
      />
    </div>
  )
}

function DiagnosticsPage({
  snapshot,
  loadError,
}: {
  snapshot: XraySnapshot
  loadError: string | null
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
      <Card className="border-border/60 bg-panel/80 shadow-panel">
        <CardHeader>
          <CardTitle className="font-heading text-3xl">Machine snapshot</CardTitle>
          <CardDescription>
            The diagnostics page now starts from observed local state instead of manual assumptions.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <DiagnosticHint
            title="Binary"
            detail={snapshot.installed ? snapshot.binaryPath ?? "Installed" : "xray not found in PATH."}
          />
          <DiagnosticHint
            title="Service"
            detail={snapshot.running ? `Running${snapshot.pid ? ` as PID ${snapshot.pid}` : ""}` : "Not running"}
          />
          <DiagnosticHint
            title="Endpoint"
            detail={
              snapshot.publicIpv4
                ? `${snapshot.publicIpv4}${snapshot.listenPort ? `:${snapshot.listenPort}` : ""}`
                : "Public IPv4 unavailable"
            }
          />
          <DiagnosticHint
            title="Config"
            detail={snapshot.configPath ?? "No config file detected in standard locations."}
          />
        </CardContent>
      </Card>

      <Card className="border-border/60 bg-secondary/75 shadow-none">
        <CardHeader>
          <CardTitle className="font-heading text-2xl">Follow-up probes</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          {loadError ? <ChecklistRow title="Backend error" detail={loadError} /> : null}
          {snapshot.notes.length > 0 ? (
            snapshot.notes.map((note) => <ChecklistRow key={note} title="Probe note" detail={note} />)
          ) : (
            <>
              <ChecklistRow title="Installed?" detail="Detected from PATH and version output." />
              <ChecklistRow title="Running?" detail="Read from brew services or process table." />
              <ChecklistRow title="Config path?" detail="Read from standard local locations." />
              <ChecklistRow title="Network basics?" detail="Public IPv4 and LAN IP are probed separately." />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function LogsPage() {
  return (
    <PlaceholderPanel
      eyebrow="Runtime traces"
      title="Logs will be grouped by service, config writes, and share actions."
      description="The first implementation should surface only the recent, high-signal lines instead of dumping raw terminal output without structure."
    />
  )
}

function BackupsPage() {
  return (
    <PlaceholderPanel
      eyebrow="Safety rails"
      title="Backups become meaningful once config writes are part of the UI."
      description="Every save flow should create a timestamped restore point and record which operation produced it."
    />
  )
}

function SettingsPage() {
  return (
    <PlaceholderPanel
      eyebrow="Operator preferences"
      title="Settings should stay local and sparse."
      description="This app is not a hosted control panel. Preferences should mostly cover file paths, shell commands, and presentation details."
    />
  )
}

function StatusChip({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: LucideIcon
  label: string
  value: string
  hint: string
}) {
  return (
    <Card className="border-border/60 bg-panel/70 shadow-none">
      <CardContent className="flex items-center gap-4 p-4">
        <div className="flex size-11 items-center justify-center rounded-2xl bg-primary/12 text-primary">
          <Icon className="size-5" />
        </div>
        <div className="min-w-0">
          <div className="text-xs font-medium uppercase tracking-[0.16em] text-muted-foreground">{label}</div>
          <div className="truncate text-base font-medium">{value}</div>
          <div className="truncate text-sm text-muted-foreground">{hint}</div>
        </div>
      </CardContent>
    </Card>
  )
}

function MetricCard({
  label,
  value,
  detail,
}: {
  label: string
  value: string
  detail: string
}) {
  return (
    <Card className="border-border/60 bg-panel/80 shadow-none">
      <CardHeader className="pb-2">
        <CardDescription>{label}</CardDescription>
        <CardTitle className="font-heading text-3xl">{value}</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">{detail}</CardContent>
    </Card>
  )
}

function ConfigBlock({
  title,
  description,
  lines,
}: {
  title: string
  description: string
  lines: string[]
}) {
  return (
    <Card className="border-border/60 bg-panel/80 shadow-panel">
      <CardHeader>
        <CardTitle className="font-heading text-2xl">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {lines.map((line) => (
          <div key={line} className="rounded-2xl border border-border/60 bg-background/80 px-3 py-3">
            {line}
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

function DiagnosticHint({
  title,
  detail,
}: {
  title: string
  detail: string
}) {
  return (
    <div className="rounded-3xl border border-border/60 bg-background/80 p-4">
      <div className="font-medium">{title}</div>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{detail}</p>
    </div>
  )
}

function PlaceholderPanel({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description: string
}) {
  return (
    <Card className="border-border/60 bg-panel/80 shadow-panel">
      <CardContent className="px-6 py-8 sm:px-8">
        <Badge className="rounded-full bg-primary/12 px-3 py-1 text-primary hover:bg-primary/12">
          {eyebrow}
        </Badge>
        <h3 className="mt-5 max-w-3xl font-heading text-4xl leading-tight">{title}</h3>
        <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  )
}

function InfoStrip({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-2xl border border-border/60 bg-panel/80 px-3 py-3">
      <span className="text-xs uppercase tracking-[0.16em] text-muted-foreground">{label}</span>
      <span className="text-sm font-medium">{value}</span>
    </div>
  )
}

function ChecklistRow({
  title,
  detail,
}: {
  title: string
  detail: string
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="mt-1 size-2.5 rounded-full bg-primary" />
      <div>
        <div className="font-medium">{title}</div>
        <p className="mt-1 leading-6 text-muted-foreground">{detail}</p>
      </div>
    </div>
  )
}

function MilestoneRow({
  label,
  done = false,
  tone = "neutral",
}: {
  label: string
  done?: boolean
  tone?: "neutral" | "warning" | "danger"
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-2xl bg-background/80 px-3 py-2.5">
      <span className="text-sm">{label}</span>
      <Badge
        variant="secondary"
        className={cn(
          "rounded-full",
          done && "bg-primary/12 text-primary",
          tone === "warning" && "bg-secondary text-secondary-foreground",
          tone === "danger" && "bg-destructive/12 text-destructive",
        )}
      >
        {done ? "Done" : tone === "danger" ? "Error" : tone === "warning" ? "Note" : "Queued"}
      </Badge>
    </div>
  )
}

function getServiceLabel(snapshot: XraySnapshot) {
  if (!snapshot.installed) {
    return "Missing"
  }

  return snapshot.running ? "Running" : "Stopped"
}

function toErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback
}

export default App
