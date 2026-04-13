import { useMemo, useState } from "react"
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

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { TooltipProvider } from "@/components/ui/tooltip"
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

const currentState = {
  profile: "Home Mac",
  serviceStatus: "Running",
  publicIp: "73.225.148.112",
  port: "443",
  users: 5,
}

function App() {
  const [activePage, setActivePage] = useState<PageId>("dashboard")

  const activeNavItem = useMemo(
    () => navItems.find((item) => item.id === activePage) ?? navItems[0],
    [activePage],
  )

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
                    <InfoStrip label="Current node" value={currentState.profile} />
                    <InfoStrip label="Live users" value={`${currentState.users} seats`} />
                    <InfoStrip label="Inbound" value={`${currentState.publicIp}:${currentState.port}`} />
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
                    <CardTitle className="font-heading text-xl">V1 delivery rhythm</CardTitle>
                    <CardDescription>
                      Build the shell first, then wire service inspection, then user management.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    <MilestoneRow done label="Docs locked" />
                    <MilestoneRow done label="Tauri scaffold" />
                    <MilestoneRow done label="Tokens and UI foundation" />
                    <MilestoneRow label="Application shell" />
                    <MilestoneRow label="Local Xray inspection" />
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
                      Phase 4 application shell
                    </div>
                    <div>
                      <h2 className="font-heading text-4xl leading-[0.95] sm:text-5xl">
                        {activeNavItem.label}
                      </h2>
                      <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground sm:text-base">
                        {activeNavItem.hint}. The current shell is static by design, but shaped around
                        the real workflows we already know this app needs.
                      </p>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" className="rounded-full px-4">
                      <RefreshCcw className="size-4" />
                      Refresh snapshot
                    </Button>
                    <Button className="rounded-full px-4">
                      Run diagnostics
                      <ArrowUpRight className="size-4" />
                    </Button>
                  </div>
                </div>

                <div className="grid gap-3 md:grid-cols-3">
                  <StatusChip
                    icon={Server}
                    label="Xray state"
                    value={currentState.serviceStatus}
                    hint="brew service healthy"
                  />
                  <StatusChip
                    icon={Globe}
                    label="Public endpoint"
                    value={`${currentState.publicIp}:${currentState.port}`}
                    hint="IPv4 reachable path"
                  />
                  <StatusChip
                    icon={Users}
                    label="Friend slots"
                    value={`${currentState.users} active UUIDs`}
                    hint="one UUID per person"
                  />
                </div>
              </header>

              <ScrollArea className="flex-1">
                <div className="px-5 py-5 sm:px-8 lg:px-10 lg:py-8">{renderPage(activePage)}</div>
              </ScrollArea>
            </div>
          </main>
        </div>
      </div>
    </TooltipProvider>
  )
}

function renderPage(activePage: PageId) {
  switch (activePage) {
    case "dashboard":
      return <DashboardPage />
    case "users":
      return <UsersPage />
    case "config":
      return <ConfigPage />
    case "diagnostics":
      return <DiagnosticsPage />
    case "logs":
      return <LogsPage />
    case "backups":
      return <BackupsPage />
    case "settings":
      return <SettingsPage />
  }
}

function DashboardPage() {
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
                  The first release puts status, user links, REALITY parameters, and failure hints in one
                  place so you stop bouncing between JSON, router settings, and terminal output.
                </p>

                <div className="mt-6 flex flex-wrap gap-2">
                  <Button className="rounded-full px-4">Inspect current config</Button>
                  <Button variant="outline" className="rounded-full px-4">
                    Preview user links
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/60 bg-secondary/75 shadow-none">
          <CardHeader>
            <CardTitle className="font-heading text-2xl">First build scope</CardTitle>
            <CardDescription>
              Keep the first usable version narrow enough to trust.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <ChecklistRow title="Read local config" detail="No manual JSON edits for common changes." />
            <ChecklistRow title="Show runtime state" detail="Installed, running, port, IP, config path." />
            <ChecklistRow title="Manage users" detail="Add, remove, label, and share individual UUIDs." />
            <ChecklistRow title="Validate before save" detail="Fail fast with `xray -test` before restart." />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Profile" value="Home Mac" detail="Single local node" />
        <MetricCard label="Share links" value="5" detail="One per friend" />
        <MetricCard label="Reality target" value="Microsoft" detail="SNI aligned" />
        <MetricCard label="Restore points" value="Planned" detail="Before every write" />
      </div>
    </div>
  )
}

function UsersPage() {
  const previewUsers = [
    { name: "friend-1", note: "Primary test account", state: "Healthy" },
    { name: "friend-2", note: "Mobile only", state: "Needs note" },
    { name: "friend-3", note: "Shadowrocket import", state: "Healthy" },
  ]

  return (
    <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
      <Card className="border-border/60 bg-panel/80 shadow-panel">
        <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <CardTitle className="font-heading text-3xl">User roster</CardTitle>
            <CardDescription>
              Individual UUIDs are the minimum viable control boundary for a small private node.
            </CardDescription>
          </div>
          <Button className="rounded-full px-4">Add user</Button>
        </CardHeader>
        <CardContent className="space-y-3">
          {previewUsers.map((user) => (
            <div
              key={user.name}
              className="flex flex-col gap-4 rounded-3xl border border-border/60 bg-background/80 p-4 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{user.name}</span>
                  <Badge variant="secondary" className="rounded-full">
                    {user.state}
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground">{user.note}</p>
              </div>

              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" className="rounded-full px-3">
                  Copy link
                </Button>
                <Button variant="outline" size="sm" className="rounded-full px-3">
                  Show QR
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card className="border-border/60 bg-secondary/75 shadow-none">
        <CardHeader>
          <CardTitle className="font-heading text-2xl">User management intent</CardTitle>
          <CardDescription>The page will eventually own the full share flow.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <ChecklistRow title="Generate UUID" detail="Use xray tooling or local generator." />
          <ChecklistRow title="Attach note" detail="Human-readable labels should not depend on raw config only." />
          <ChecklistRow title="Build link + QR" detail="Export exactly the parameters the client needs." />
          <ChecklistRow title="Disable safely" detail="Single-user revocation without touching others." />
        </CardContent>
      </Card>
    </div>
  )
}

function ConfigPage() {
  return (
    <div className="grid gap-6 xl:grid-cols-3">
      <ConfigBlock
        title="Inbound"
        description="The local listener and its exposure model."
        lines={["Protocol: VLESS", "Port: 443", "Flow: xtls-rprx-vision"]}
      />
      <ConfigBlock
        title="REALITY"
        description="Parameters that must stay aligned with client import data."
        lines={["Target: www.microsoft.com:443", "SNI: www.microsoft.com", "shortId: 753bd0a1"]}
      />
      <ConfigBlock
        title="Config safety"
        description="Every write should be previewed, validated, backed up, and only then restarted."
        lines={["Create backup", "Run xray -test", "Restart service if valid"]}
      />
    </div>
  )
}

function DiagnosticsPage() {
  return (
    <div className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
      <Card className="border-border/60 bg-panel/80 shadow-panel">
        <CardHeader>
          <CardTitle className="font-heading text-3xl">Failure map</CardTitle>
          <CardDescription>
            Diagnostics should shorten the path from “it doesn&apos;t work” to the actual cause.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <DiagnosticHint title="Import type mismatch" detail="The client is treating a VLESS link as JSON." />
          <DiagnosticHint title="Port forwarding missing" detail="Router not sending 443 to the local machine." />
          <DiagnosticHint title="SNI mismatch" detail="Client `sni` does not match server `serverNames`." />
          <DiagnosticHint title="Outdated client" detail="No support for REALITY + Vision on the device." />
        </CardContent>
      </Card>

      <Card className="border-border/60 bg-secondary/75 shadow-none">
        <CardHeader>
          <CardTitle className="font-heading text-2xl">Checks to automate</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <ChecklistRow title="Installed?" detail="Detect `xray` binary and version." />
          <ChecklistRow title="Listening?" detail="Verify the configured local port is open." />
          <ChecklistRow title="Reachable?" detail="Compare public IP, WAN IP, and forwardability." />
          <ChecklistRow title="Valid config?" detail="Surface `xray -test` output cleanly." />
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
}: {
  label: string
  done?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-2xl bg-background/80 px-3 py-2.5">
      <span>{label}</span>
      <Badge
        variant="secondary"
        className={cn("rounded-full", done ? "bg-primary/12 text-primary" : "text-muted-foreground")}
      >
        {done ? "Done" : "Queued"}
      </Badge>
    </div>
  )
}

export default App
