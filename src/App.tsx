import { invoke } from "@tauri-apps/api/core"
import { startTransition, useCallback, useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import type { LucideIcon } from "lucide-react"
import {
  Archive,
  Check,
  FileText,
  Languages,
  LayoutDashboard,
  Play,
  RefreshCcw,
  RotateCcw,
  Settings2,
  Shield,
  Square,
  Stethoscope,
  Users,
} from "lucide-react"

import { UsersPage } from "@/components/users-page"
import { Banner } from "@/components/banner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import type { CreateUserInput, TrafficResponse, UserListResponse, UserMutationResult } from "@/lib/users"
import type { XraySnapshot } from "@/lib/xray"
import { cn } from "@/lib/utils"

/* ─── Types ─── */

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
  labelKey: string
  icon: LucideIcon
}

const navItems: NavItem[] = [
  { id: "dashboard", labelKey: "nav.dashboard", icon: LayoutDashboard },
  { id: "users", labelKey: "nav.users", icon: Users },
  { id: "config", labelKey: "nav.config", icon: Shield },
  { id: "diagnostics", labelKey: "nav.diagnostics", icon: Stethoscope },
  { id: "logs", labelKey: "nav.logs", icon: FileText },
  { id: "backups", labelKey: "nav.backups", icon: Archive },
  { id: "settings", labelKey: "nav.settings", icon: Settings2 },
]

const fallbackSnapshot: XraySnapshot = {
  installed: false,
  running: false,
  notes: [],
}

/* ─── App ─── */

function App() {
  const { t, i18n } = useTranslation()
  const [activePage, setActivePage] = useState<PageId>("dashboard")
  const [snapshot, setSnapshot] = useState<XraySnapshot | null>(null)
  const [usersResponse, setUsersResponse] = useState<UserListResponse | null>(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [snapshotError, setSnapshotError] = useState<string | null>(null)
  const [usersError, setUsersError] = useState<string | null>(null)
  const [mutationNotice, setMutationNotice] = useState<string | null>(null)
  const [trafficResponse, setTrafficResponse] = useState<TrafficResponse | null>(null)
  const [needsRestart, setNeedsRestart] = useState(false)
  const [isRestarting, setIsRestarting] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const toastTimer = useRef<ReturnType<typeof setTimeout>>(null)

  const currentSnapshot = snapshot ?? fallbackSnapshot
  const currentNav = navItems.find((item) => item.id === activePage) ?? navItems[0]

  const showToast = useCallback((msg: string) => {
    setToast(msg)
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(null), 2500)
  }, [])

  function toggleLocale() {
    const next = i18n.language === "zh" ? "en" : "zh"
    i18n.changeLanguage(next)
    localStorage.setItem("locale", next)
  }

  async function handleServiceAction(action: "start" | "stop" | "restart") {
    try {
      setIsRestarting(true)
      await invoke<string>("service_action", { action })
      if (action === "restart") setNeedsRestart(false)
      const msgKey = action === "restart" ? "action.restarted" : action === "start" ? "action.started" : "action.stopped"
      showToast(t(msgKey))
      await refreshAll()
    } catch (error) {
      showToast(toErrorMessage(error, t("action.serviceFailed")))
    } finally {
      setIsRestarting(false)
    }
  }

  async function loadSnapshot() {
    return invoke<XraySnapshot>("get_xray_snapshot")
  }

  async function loadUsers() {
    return invoke<UserListResponse>("get_vless_users")
  }

  async function loadTraffic() {
    return invoke<TrafficResponse>("get_user_traffic")
  }

  async function refreshAll() {
    try {
      setIsRefreshing(true)
      const [nextSnapshot, nextUsers, nextTraffic] = await Promise.allSettled([
        loadSnapshot(),
        loadUsers(),
        loadTraffic(),
      ])

      startTransition(() => {
        if (nextSnapshot.status === "fulfilled") {
          setSnapshot(nextSnapshot.value)
          setSnapshotError(null)
        } else {
          setSnapshotError(toErrorMessage(nextSnapshot.reason, t("error.snapshotFailed")))
        }

        if (nextUsers.status === "fulfilled") {
          setUsersResponse(nextUsers.value)
          setUsersError(null)
        } else {
          setUsersError(toErrorMessage(nextUsers.reason, t("error.userListFailed")))
        }

        if (nextTraffic.status === "fulfilled") {
          setTrafficResponse(nextTraffic.value)
        }
      })
      showToast(t("action.refreshed"))
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
        setMutationNotice(t("users.saved", { path: result.backupPath }))
        setUsersError(null)
        setNeedsRestart(true)
      })
      await refreshSnapshotOnly()
    } catch (error) {
      const message = toErrorMessage(error, t("users.createFailed"))
      setUsersError(message)
      throw new Error(message)
    }
  }

  async function handleUpdateLabel(userId: string, newLabel: string) {
    try {
      const result = await invoke<UserMutationResult>("update_user_label", { userId, newLabel })
      startTransition(() => {
        setUsersResponse((current) => ({
          configPath: current?.configPath ?? currentSnapshot.configPath ?? null,
          metadataPath: current?.metadataPath ?? null,
          users: result.users,
        }))
        setNeedsRestart(true)
      })
      showToast(t("action.refreshed"))
    } catch (error) {
      setUsersError(toErrorMessage(error, t("users.createFailed")))
      throw new Error(toErrorMessage(error, t("users.createFailed")))
    }
  }

  async function handleUpdateNote(userId: string, newNote: string) {
    try {
      const result = await invoke<UserMutationResult>("update_user_note", { userId, newNote })
      startTransition(() => {
        setUsersResponse((current) => ({
          configPath: current?.configPath ?? currentSnapshot.configPath ?? null,
          metadataPath: current?.metadataPath ?? null,
          users: result.users,
        }))
      })
      showToast(t("action.refreshed"))
    } catch (error) {
      setUsersError(toErrorMessage(error, t("users.createFailed")))
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
        setMutationNotice(t("users.deleted", { path: result.backupPath }))
        setUsersError(null)
        setNeedsRestart(true)
      })
      await refreshSnapshotOnly()
    } catch (error) {
      const message = toErrorMessage(error, t("users.deleteFailed"))
      setUsersError(message)
      throw new Error(message)
    }
  }

  useEffect(() => {
    void refreshAll()
  }, [])

  return (
    <TooltipProvider delayDuration={120}>
      <div className="flex h-screen text-foreground">
        {/* ── Sidebar ── */}
        <aside className="flex w-[220px] shrink-0 flex-col border-r border-border/60 bg-panel/75 px-3 pb-3 backdrop-blur-xl">
          <div data-tauri-drag-region className="flex items-center justify-between px-2 pb-1 pt-3" style={{ paddingTop: "env(titlebar-area-height, 40px)" }}>
            <div className="flex items-center gap-2">
              <div
                className={cn(
                  "size-2 rounded-full",
                  currentSnapshot.running
                    ? "bg-green-500"
                    : currentSnapshot.installed
                      ? "bg-yellow-500"
                      : "bg-muted-foreground/40",
                )}
              />
              <span className="font-heading text-sm font-medium">Xray✈️</span>
            </div>
            <div className="flex gap-0.5">
              {currentSnapshot.running ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon-xs" onClick={() => void handleServiceAction("stop")} disabled={isRestarting}>
                      <Square className="size-3" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t("action.stop")}</TooltipContent>
                </Tooltip>
              ) : (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon-xs" onClick={() => void handleServiceAction("start")} disabled={isRestarting}>
                      <Play className="size-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t("action.start")}</TooltipContent>
                </Tooltip>
              )}
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="icon-xs" onClick={() => void handleServiceAction("restart")} disabled={isRestarting}>
                    <RotateCcw className={cn("size-3.5", isRestarting && "animate-spin")} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{t("action.restart")}</TooltipContent>
              </Tooltip>
            </div>
          </div>

          <nav className="mt-4 flex flex-1 flex-col gap-0.5">
            {navItems.map((item) => {
              const Icon = item.icon
              const active = item.id === activePage
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActivePage(item.id)}
                  className={cn(
                    "flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm transition-colors",
                    active
                      ? "bg-primary/10 font-medium text-foreground"
                      : "text-muted-foreground hover:bg-secondary hover:text-foreground",
                  )}
                >
                  <Icon className="size-4 shrink-0" />
                  <span>{t(item.labelKey)}</span>
                </button>
              )
            })}
          </nav>

          <button
            type="button"
            onClick={toggleLocale}
            className="flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
          >
            <Languages className="size-4 shrink-0" />
            <span>{i18n.language === "zh" ? "English" : "中文"}</span>
          </button>
        </aside>

        {/* ── Main ── */}
        <main className="relative flex flex-1 flex-col overflow-hidden">
          <header data-tauri-drag-region className="flex shrink-0 items-center justify-between gap-3 border-b border-border/60 px-5 pb-3" style={{ paddingTop: "env(titlebar-area-height, 40px)" }}>
            <h2 className="font-heading text-2xl leading-none">{t(currentNav.labelKey)}</h2>
            <Button
              variant="outline"
              size="sm"
              className="rounded-full"
              onClick={() => void refreshAll()}
              disabled={isRefreshing}
            >
              <RefreshCcw className={cn("size-3.5", isRefreshing && "animate-spin")} />
              {t("action.refresh")}
            </Button>
          </header>

          {needsRestart ? (
            <div className="flex items-center justify-between gap-3 border-b border-primary/20 bg-primary/5 px-5 py-2 text-sm text-primary">
              <span>{t("action.needsRestart")}</span>
              <Button
                size="xs"
                onClick={() => void handleServiceAction("restart")}
                disabled={isRestarting}
              >
                {isRestarting ? t("action.restarting") : t("action.restart")}
              </Button>
            </div>
          ) : null}

          {toast ? (
            <div className="pointer-events-none absolute right-5 top-14 z-50 flex items-center gap-2 rounded-lg bg-foreground px-3 py-1.5 text-xs text-background shadow-float">
              <Check className="size-3.5" />
              {toast}
            </div>
          ) : null}

          <ScrollArea className="flex-1">
            <div className="px-5 py-4">
              {renderPage({
                activePage,
                snapshot: currentSnapshot,
                snapshotError,
                usersResponse,
                usersError,
                mutationNotice,
                trafficResponse,
                isRefreshing,
                showToast,
                onRefreshUsers: refreshAll,
                onCreateUser: handleCreateUser,
                onUpdateLabel: handleUpdateLabel,
                onUpdateNote: handleUpdateNote,
                onDeleteUser: handleDeleteUser,
              })}
            </div>
          </ScrollArea>
        </main>
      </div>
    </TooltipProvider>
  )
}

/* ─── Page router ─── */

function renderPage({
  activePage,
  snapshot,
  snapshotError,
  usersResponse,
  usersError,
  mutationNotice,
  trafficResponse,
  isRefreshing,
  onRefreshUsers,
  showToast,
  onCreateUser,
  onUpdateLabel,
  onUpdateNote,
  onDeleteUser,
}: {
  activePage: PageId
  snapshot: XraySnapshot
  snapshotError: string | null
  usersResponse: UserListResponse | null
  usersError: string | null
  mutationNotice: string | null
  trafficResponse: TrafficResponse | null
  isRefreshing: boolean
  showToast: (msg: string) => void
  onRefreshUsers: () => Promise<void>
  onCreateUser: (input: CreateUserInput) => Promise<void>
  onUpdateLabel: (userId: string, newLabel: string) => Promise<void>
  onUpdateNote: (userId: string, newNote: string) => Promise<void>
  onDeleteUser: (userId: string) => Promise<void>
}) {
  switch (activePage) {
    case "dashboard":
      return <DashboardPage snapshot={snapshot} loadError={snapshotError} trafficResponse={trafficResponse} />
    case "users":
      return (
        <UsersPage
          users={usersResponse?.users ?? []}
          configPath={usersResponse?.configPath}
          trafficResponse={trafficResponse}
          isLoading={isRefreshing}
          error={usersError}
          mutationNotice={mutationNotice}
          showToast={showToast}
          onRefresh={onRefreshUsers}
          onCreateUser={onCreateUser}
          onUpdateLabel={onUpdateLabel}
          onUpdateNote={onUpdateNote}
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

/* ─── Dashboard ─── */

function DashboardPage({
  snapshot,
  loadError,
  trafficResponse,
}: {
  snapshot: XraySnapshot
  loadError: string | null
  trafficResponse: TrafficResponse | null
}) {
  const { t } = useTranslation()

  const serviceValue = snapshot.running
    ? `${t("dashboard.running")}${snapshot.pid ? ` · PID ${snapshot.pid}` : ""}${snapshot.version ? ` · ${snapshot.version}` : ""}`
    : snapshot.installed
      ? t("dashboard.stopped")
      : t("dashboard.notInstalled")

  const endpointValue =
    snapshot.publicIpv4 && snapshot.listenPort
      ? `${snapshot.publicIpv4}:${snapshot.listenPort}`
      : snapshot.publicIpv4
        ? snapshot.publicIpv4
        : t("dashboard.notDetected")

  const realityValue =
    snapshot.realityTarget
      ? `${snapshot.realityTarget}${snapshot.serverName ? ` · SNI ${snapshot.serverName}` : ""}`
      : t("dashboard.notConfigured")

  return (
    <div className="space-y-4">
      {loadError ? <Banner tone="danger" text={loadError} /> : null}
      {snapshot.notes.map((note) => (
        <Banner key={note} tone="warning" text={note} />
      ))}

      <Card className="border-border/60 bg-panel/80 shadow-panel">
        <CardContent className="p-0">
          <table className="w-full text-sm">
            <tbody className="divide-y divide-border/60">
              <StatusRow label={t("dashboard.service")} value={serviceValue} />
              <StatusRow label={t("dashboard.endpoint")} value={endpointValue} />
              <StatusRow label={t("dashboard.reality")} value={realityValue} />
              <StatusRow label={t("dashboard.users")} value={snapshot.userCount != null ? String(snapshot.userCount) : t("dashboard.unknown")} />
              <StatusRow label={t("dashboard.config")} value={snapshot.configPath ?? t("dashboard.notDetected")} mono />
              <StatusRow label={t("dashboard.binary")} value={snapshot.binaryPath ?? t("dashboard.notDetected")} mono />
              {trafficResponse?.available ? (
                <StatusRow
                  label={t("dashboard.traffic")}
                  value={(() => {
                    const total = trafficResponse.users.reduce(
                      (acc, u) => ({ up: acc.up + u.uplink, down: acc.down + u.downlink }),
                      { up: 0, down: 0 },
                    )
                    return `↑ ${formatBytes(total.up)}  ↓ ${formatBytes(total.down)}`
                  })()}
                />
              ) : null}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}

/* ─── Config ─── */

function ConfigPage({ snapshot }: { snapshot: XraySnapshot }) {
  const { t } = useTranslation()
  return (
    <Card className="border-border/60 bg-panel/80 shadow-panel">
      <CardContent className="p-0">
        <table className="w-full text-sm">
          <tbody className="divide-y divide-border/60">
            <StatusRow label={t("config.protocol")} value="VLESS" />
            <StatusRow label={t("config.port")} value={snapshot.listenPort ? String(snapshot.listenPort) : t("dashboard.unknown")} />
            <StatusRow label={t("config.users")} value={snapshot.userCount != null ? String(snapshot.userCount) : t("dashboard.unknown")} />
            <StatusRow label={t("config.realityTarget")} value={snapshot.realityTarget ?? t("dashboard.unknown")} />
            <StatusRow label={t("config.sni")} value={snapshot.serverName ?? t("dashboard.unknown")} />
            <StatusRow label={t("config.configPath")} value={snapshot.configPath ?? t("dashboard.unknown")} mono />
          </tbody>
        </table>
      </CardContent>
    </Card>
  )
}

/* ─── Diagnostics ─── */

function DiagnosticsPage({
  snapshot,
  loadError,
}: {
  snapshot: XraySnapshot
  loadError: string | null
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      {loadError ? <Banner tone="danger" text={loadError} /> : null}

      <div className="grid grid-cols-2 gap-3">
        <DiagnosticHint
          title={t("diag.binary")}
          detail={snapshot.installed ? snapshot.binaryPath ?? "Installed" : t("diag.notFound")}
        />
        <DiagnosticHint
          title={t("diag.service")}
          detail={snapshot.running ? `${t("dashboard.running")}${snapshot.pid ? ` · PID ${snapshot.pid}` : ""}` : t("diag.notRunning")}
        />
        <DiagnosticHint
          title={t("diag.endpoint")}
          detail={
            snapshot.publicIpv4
              ? `${snapshot.publicIpv4}${snapshot.listenPort ? `:${snapshot.listenPort}` : ""}`
              : t("diag.ipUnavailable")
          }
        />
        <DiagnosticHint
          title={t("diag.config")}
          detail={snapshot.configPath ?? t("diag.noConfig")}
        />
      </div>

      {snapshot.notes.length > 0 ? (
        <Card className="border-border/60 bg-secondary/75 shadow-none">
          <CardHeader className="pb-2">
            <CardTitle className="font-heading text-lg">{t("diag.notes")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {snapshot.notes.map((note) => (
              <Banner key={note} tone="warning" text={note} />
            ))}
          </CardContent>
        </Card>
      ) : (
        <div className="rounded-xl border border-border/60 bg-background/80 px-4 py-3 text-sm text-muted-foreground">
          {t("diag.allPassed")}
        </div>
      )}
    </div>
  )
}

/* ─── Placeholder pages ─── */

function LogsPage() {
  const { t } = useTranslation()
  return <PlaceholderPanel eyebrow={t("placeholder.comingSoon")} title={t("logs.title")} description={t("logs.desc")} />
}

function BackupsPage() {
  const { t } = useTranslation()
  return <PlaceholderPanel eyebrow={t("placeholder.comingSoon")} title={t("backups.title")} description={t("backups.desc")} />
}

function SettingsPage() {
  const { t } = useTranslation()
  return <PlaceholderPanel eyebrow={t("placeholder.comingSoon")} title={t("settings.title")} description={t("settings.desc")} />
}

/* ─── Shared components ─── */

function StatusRow({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <tr>
      <td className="whitespace-nowrap px-4 py-2.5 text-muted-foreground">{label}</td>
      <td className={cn("px-4 py-2.5 text-right font-medium", mono && "font-mono text-xs")}>
        {value}
      </td>
    </tr>
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
    <div className="rounded-xl border border-border/60 bg-background/80 p-4">
      <div className="font-medium">{title}</div>
      <p className="mt-1 text-sm leading-6 text-muted-foreground">{detail}</p>
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
      <CardContent className="px-5 py-6">
        <Badge className="rounded-full bg-primary/12 px-3 py-1 text-primary hover:bg-primary/12">
          {eyebrow}
        </Badge>
        <h3 className="mt-4 max-w-3xl font-heading text-2xl leading-tight">{title}</h3>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  )
}

/* ─── Helpers ─── */

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B"
  const units = ["B", "KB", "MB", "GB", "TB"]
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  const value = bytes / Math.pow(1024, i)
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function toErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback
}

export default App
