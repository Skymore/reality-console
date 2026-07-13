import { invoke } from "@tauri-apps/api/core"
import { getCurrentWindow } from "@tauri-apps/api/window"
import { startTransition, useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import {
  Check,
  ChevronRight,
  CircleAlert,
  Copy,
  Languages,
  Laptop,
  Link2,
  Network,
  Pause,
  Play,
  Plus,
  RefreshCcw,
  RotateCcw,
  Server,
  Settings2,
  ShieldCheck,
  Square,
  UserRoundPlus,
  Users,
  Wifi,
} from "lucide-react"

import { Banner } from "@/components/banner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import type {
  ControlAccount,
  ControlNode,
  ControlSnapshot,
  SetupDelivery,
} from "@/lib/control"
import type { UserListResponse } from "@/lib/users"
import type { XraySnapshot } from "@/lib/xray"
import { cn } from "@/lib/utils"

type PageId = "network" | "nodes" | "friends" | "local" | "settings"

const fallbackLocal: XraySnapshot = {
  installed: false,
  running: false,
  notes: [],
}

const emptyControl: ControlSnapshot = {
  installed: false,
  healthy: false,
  nodes: [],
  accounts: [],
}

const navItems = [
  { id: "network" as const, icon: Network },
  { id: "nodes" as const, icon: Server },
  { id: "friends" as const, icon: Users },
  { id: "local" as const, icon: Laptop },
  { id: "settings" as const, icon: Settings2 },
]

const copy = {
  zh: {
    nav: { network: "网络", nodes: "节点", friends: "朋友", local: "这台 Mac", settings: "设置" },
    page: {
      network: ["网络总览", "所有节点、朋友与连接入口的实时状态。"],
      nodes: ["节点", "管理出口设备，或生成一个邀请码让新设备加入。"],
      friends: ["朋友", "一个账号自动同步被分配的全部节点，无需分享多条链接。"],
      local: ["这台 Mac", "本机 Xray、兼容账号与 Vultr 中继状态。"],
      settings: ["部署设置", "控制面、本机数据面和中继的实际运行边界。"],
    },
    refresh: "刷新",
    addNode: "添加节点",
    addFriend: "添加朋友",
    online: "正常",
    attention: "需处理",
    copy: "复制",
    copied: "已复制",
    cancel: "取消",
    create: "创建",
    save: "保存",
    close: "关闭",
    active: "已启用",
    disabled: "已禁用",
    deleted: "已删除",
    never: "从未",
  },
  en: {
    nav: { network: "Network", nodes: "Nodes", friends: "Friends", local: "This Mac", settings: "Settings" },
    page: {
      network: ["Network overview", "Live state for every node, friend, and connection path."],
      nodes: ["Nodes", "Manage exit devices or create one code to add a new device."],
      friends: ["Friends", "One account automatically syncs every assigned node without sharing multiple links."],
      local: ["This Mac", "Local Xray, compatibility users, and the Vultr relay path."],
      settings: ["Deployment settings", "The actual boundaries of Control, the local data plane, and the relay."],
    },
    refresh: "Refresh",
    addNode: "Add node",
    addFriend: "Add friend",
    online: "Healthy",
    attention: "Attention",
    copy: "Copy",
    copied: "Copied",
    cancel: "Cancel",
    create: "Create",
    save: "Save",
    close: "Close",
    active: "Active",
    disabled: "Disabled",
    deleted: "Deleted",
    never: "Never",
  },
}

function App() {
  const { i18n } = useTranslation()
  const language = i18n.language.startsWith("zh") ? "zh" : "en"
  const t = copy[language]
  const [page, setPage] = useState<PageId>("network")
  const [control, setControl] = useState<ControlSnapshot>(emptyControl)
  const [local, setLocal] = useState<XraySnapshot>(fallbackLocal)
  const [localUsers, setLocalUsers] = useState<UserListResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const refreshPromise = useRef<Promise<void> | null>(null)

  const [friendDialogOpen, setFriendDialogOpen] = useState(false)
  const [friendName, setFriendName] = useState("")
  const [friendNodeIds, setFriendNodeIds] = useState<string[]>([])
  const [nodeDialogOpen, setNodeDialogOpen] = useState(false)
  const [nodeName, setNodeName] = useState("")
  const [editingAccount, setEditingAccount] = useState<ControlAccount | null>(null)
  const [editingNodeIds, setEditingNodeIds] = useState<string[]>([])
  const [delivery, setDelivery] = useState<SetupDelivery | null>(null)
  const [deliveryKind, setDeliveryKind] = useState<"connect" | "node">("connect")
  const [mutating, setMutating] = useState(false)

  const activeNodes = control.nodes.filter((node) => node.status === "active")
  const visibleAccounts = control.accounts.filter((account) => account.account.status !== "deleted")
  const pageCopy = t.page[page]

  function refresh(): Promise<void> {
    if (refreshPromise.current) return refreshPromise.current
    const request = (async () => {
      setLoading(true)
      const [nextControl, nextLocal, nextUsers] = await Promise.allSettled([
        invoke<ControlSnapshot>("get_control_snapshot"),
        invoke<XraySnapshot>("get_xray_snapshot"),
        invoke<UserListResponse>("get_vless_users"),
      ])
      startTransition(() => {
        if (nextControl.status === "fulfilled") setControl(nextControl.value)
        if (nextLocal.status === "fulfilled") setLocal(nextLocal.value)
        if (nextUsers.status === "fulfilled") setLocalUsers(nextUsers.value)
        const failure = [nextControl, nextLocal]
          .find((result) => result.status === "rejected")
        setError(failure?.status === "rejected" ? errorMessage(failure.reason) : null)
        setLoading(false)
      })
    })()
    refreshPromise.current = request
    void request.finally(() => {
      refreshPromise.current = null
    })
    return request
  }

  useEffect(() => {
    void refresh()
    const interval = window.setInterval(() => void refresh(), 30_000)
    return () => window.clearInterval(interval)
  }, [])

  function toggleLanguage() {
    const next = language === "zh" ? "en" : "zh"
    void i18n.changeLanguage(next)
    localStorage.setItem("locale", next)
  }

  async function mutate<T>(operation: () => Promise<T>, success: string): Promise<T | null> {
    setMutating(true)
    setError(null)
    try {
      const result = await operation()
      setNotice(success)
      await refresh()
      return result
    } catch (reason) {
      setError(errorMessage(reason))
      return null
    } finally {
      setMutating(false)
    }
  }

  async function createFriend() {
    const name = friendName.trim()
    if (!name) return
    const account = await mutate(
      () => invoke<ControlAccount>("create_control_account", { input: { displayName: name } }),
      language === "zh" ? "朋友账号已创建" : "Friend account created",
    )
    if (!account) return
    if (friendNodeIds.length > 0) {
      await mutate(
        () => invoke("update_control_account_nodes", {
          input: { userId: account.account.userId, nodeIds: friendNodeIds },
        }),
        language === "zh" ? "节点已分配" : "Nodes assigned",
      )
    }
    setFriendDialogOpen(false)
    setFriendName("")
    setFriendNodeIds([])
  }

  async function createNode() {
    const name = nodeName.trim()
    if (!name) return
    const result = await mutate(
      () => invoke<SetupDelivery>("create_node_setup", {
        input: {
          displayName: name,
          listenPort: 10443,
          publicPort: 443,
          serverName: "dl.google.com",
          target: "dl.google.com:443",
          expiresInSeconds: 3600,
        },
      }),
      language === "zh" ? "节点邀请码已创建" : "Node invitation created",
    )
    if (!result) return
    setNodeDialogOpen(false)
    setNodeName("")
    setDeliveryKind("node")
    setDelivery(result)
  }

  async function saveAccountNodes() {
    if (!editingAccount) return
    const result = await mutate(
      () => invoke("update_control_account_nodes", {
        input: { userId: editingAccount.account.userId, nodeIds: editingNodeIds },
      }),
      language === "zh" ? "账号节点已更新" : "Account nodes updated",
    )
    if (result !== null) setEditingAccount(null)
  }

  async function createConnectCode(account: ControlAccount) {
    const result = await mutate(
      () => invoke<SetupDelivery>("create_connect_setup", {
        input: { userId: account.account.userId, expiresInSeconds: 900 },
      }),
      language === "zh" ? "客户端登录码已创建" : "Connect setup code created",
    )
    if (!result) return
    setDeliveryKind("connect")
    setDelivery(result)
  }

  async function setAccountStatus(account: ControlAccount, status: "active" | "disabled" | "deleted") {
    if (status === "deleted") {
      const confirmed = window.confirm(
        language === "zh"
          ? `永久删除 ${account.account.displayName}？所有节点上的访问会被撤销。`
          : `Permanently delete ${account.account.displayName}? Access will be revoked from every node.`,
      )
      if (!confirmed) return
    }
    await mutate(
      () => invoke("set_control_account_status", {
        input: { userId: account.account.userId, status },
      }),
      language === "zh" ? "账号状态已更新" : "Account status updated",
    )
  }

  async function runNodeAction(node: ControlNode, action: "approve" | "disable" | "revoke") {
    if (action === "revoke") {
      const confirmed = window.confirm(
        language === "zh"
          ? `永久撤销节点 ${node.displayName}？它必须重新加入网络才能恢复。`
          : `Permanently revoke ${node.displayName}? It must join again to recover.`,
      )
      if (!confirmed) return
    }
    await mutate(
      () => invoke("control_node_action", { input: { nodeId: node.nodeId, action } }),
      language === "zh" ? "节点状态已更新" : "Node state updated",
    )
  }

  async function serviceAction(action: "start" | "stop" | "restart") {
    await mutate(
      () => invoke("service_action", { action }),
      language === "zh" ? "本机 Xray 状态已更新" : "Local Xray state updated",
    )
  }

  function openAccountEditor(account: ControlAccount) {
    setEditingAccount(account)
    setEditingNodeIds(
      account.assignments
        .filter((assignment) => assignment.status !== "deleted")
        .map((assignment) => assignment.nodeId),
    )
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-background text-foreground">
      <div className="pointer-events-none fixed inset-0 opacity-45 [background-image:linear-gradient(to_right,rgb(39_38_34/0.035)_1px,transparent_1px),linear-gradient(to_bottom,rgb(39_38_34/0.035)_1px,transparent_1px)] [background-size:28px_28px]" />
      <div className="relative flex min-h-screen flex-col lg:flex-row">
        <aside className="flex shrink-0 flex-col border-b border-border/70 bg-sidebar/86 backdrop-blur-xl lg:w-56 lg:border-r lg:border-b-0">
          <div
            className="flex h-20 items-center gap-3 px-5 select-none"
            onMouseDown={(event) => {
              if (event.button !== 0 || event.detail !== 1 || (event.target as HTMLElement).closest("button")) return
              event.preventDefault()
              void getCurrentWindow().startDragging()
            }}
            onDoubleClick={(event) => {
              if ((event.target as HTMLElement).closest("button")) return
              void getCurrentWindow().toggleMaximize()
            }}
          >
            <div className="grid size-10 place-items-center rounded-2xl bg-foreground text-background shadow-float">
              <Network className="size-5" />
            </div>
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold tracking-tight">Private Network</p>
              <p className="mt-0.5 text-[11px] text-muted-foreground">Control</p>
            </div>
          </div>

          <nav className="flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-col lg:pb-0">
            {navItems.map((item) => {
              const Icon = item.icon
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setPage(item.id)}
                  className={cn(
                    "flex min-w-max items-center gap-2 rounded-xl px-3 py-2 text-sm transition-colors lg:w-full",
                    page === item.id
                      ? "bg-foreground text-background shadow-sm"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground",
                  )}
                >
                  <Icon className="size-4" />
                  {t.nav[item.id]}
                </button>
              )
            })}
          </nav>

          <div className="mt-auto hidden p-4 lg:block">
            <div className="rounded-2xl border border-border/70 bg-background/70 p-3">
              <div className="flex items-center gap-2 text-xs font-medium">
                <span className={cn("size-2 rounded-full", control.healthy ? "bg-emerald-500" : "bg-amber-500")} />
                {control.healthy ? t.online : t.attention}
              </div>
              <p className="mt-2 truncate text-[11px] text-muted-foreground">
                {control.network?.displayName ?? "Control Service"}
              </p>
            </div>
          </div>
        </aside>

        <main className="min-w-0 flex-1">
          <header
            className="flex min-h-24 items-center justify-between border-b border-border/60 px-5 py-5 select-none lg:px-8"
            onMouseDown={(event) => {
              if (event.button !== 0 || event.detail !== 1 || (event.target as HTMLElement).closest("button,input")) return
              event.preventDefault()
              void getCurrentWindow().startDragging()
            }}
            onDoubleClick={(event) => {
              if ((event.target as HTMLElement).closest("button,input")) return
              void getCurrentWindow().toggleMaximize()
            }}
          >
            <div>
              <p className="text-[11px] font-semibold tracking-[0.18em] text-primary uppercase">
                {control.network?.displayName ?? "Private Network"}
              </p>
              <h1 className="mt-1 font-heading text-3xl leading-none lg:text-4xl">{pageCopy[0]}</h1>
              <p className="mt-2 max-w-2xl text-sm text-muted-foreground">{pageCopy[1]}</p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="icon" onClick={toggleLanguage} aria-label="Toggle language">
                <Languages />
              </Button>
              <Button variant="outline" onClick={() => void refresh()} disabled={loading}>
                <RefreshCcw className={cn(loading && "animate-spin")} />
                <span className="hidden sm:inline">{t.refresh}</span>
              </Button>
              {page === "nodes" ? (
                <Button onClick={() => setNodeDialogOpen(true)}><Plus />{t.addNode}</Button>
              ) : null}
              {page === "friends" ? (
                <Button onClick={() => setFriendDialogOpen(true)}><UserRoundPlus />{t.addFriend}</Button>
              ) : null}
            </div>
          </header>

          <ScrollArea className="h-[calc(100vh-6rem)]">
            <div className="mx-auto max-w-6xl space-y-4 p-5 pb-12 lg:p-8">
              {error ? <Banner tone="danger" text={error} /> : null}
              {control.error && !error ? <Banner tone="warning" text={control.error} /> : null}
              {notice ? <Banner tone="neutral" text={notice} /> : null}

              {page === "network" ? (
                <NetworkPage control={control} local={local} language={language} onNavigate={setPage} />
              ) : null}
              {page === "nodes" ? (
                <NodesPage nodes={control.nodes} language={language} onAction={runNodeAction} onAdd={() => setNodeDialogOpen(true)} />
              ) : null}
              {page === "friends" ? (
                <FriendsPage
                  accounts={visibleAccounts}
                  language={language}
                  onAdd={() => setFriendDialogOpen(true)}
                  onEdit={openAccountEditor}
                  onSetup={createConnectCode}
                  onStatus={setAccountStatus}
                />
              ) : null}
              {page === "local" ? (
                <LocalPage
                  snapshot={local}
                  users={localUsers}
                  language={language}
                  onServiceAction={serviceAction}
                  onCopy={(value) => void copyText(value, setNotice, t.copied)}
                />
              ) : null}
              {page === "settings" ? <SettingsPage control={control} local={local} language={language} /> : null}
            </div>
          </ScrollArea>
        </main>
      </div>

      <Dialog open={friendDialogOpen} onOpenChange={setFriendDialogOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{language === "zh" ? "添加朋友" : "Add a friend"}</DialogTitle>
            <DialogDescription>
              {language === "zh" ? "创建一个账号，并选择这个账号可以使用的节点。" : "Create one account and choose the nodes it can use."}
            </DialogDescription>
          </DialogHeader>
          <Input autoFocus value={friendName} onChange={(event) => setFriendName(event.target.value)} placeholder={language === "zh" ? "例如：小王" : "For example: Alex"} />
          <NodeChecklist nodes={activeNodes} selected={friendNodeIds} onChange={setFriendNodeIds} language={language} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setFriendDialogOpen(false)}>{t.cancel}</Button>
            <Button onClick={() => void createFriend()} disabled={!friendName.trim() || mutating}>{t.create}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={nodeDialogOpen} onOpenChange={setNodeDialogOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{language === "zh" ? "添加一个节点" : "Add a node"}</DialogTitle>
            <DialogDescription>
              {language === "zh" ? "对方只需要安装 Node Host 并粘贴一次邀请码。" : "The owner only installs Node Host and pastes one setup code."}
            </DialogDescription>
          </DialogHeader>
          <Input autoFocus value={nodeName} onChange={(event) => setNodeName(event.target.value)} placeholder={language === "zh" ? "例如：湾区 Mac mini" : "For example: Bay Area Mac mini"} />
          <div className="rounded-xl border border-border/70 bg-muted/40 p-3 text-xs leading-5 text-muted-foreground">
            VLESS + REALITY · TCP 443 · SNI dl.google.com · {language === "zh" ? "默认使用中继回退" : "relay fallback ready"}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNodeDialogOpen(false)}>{t.cancel}</Button>
            <Button onClick={() => void createNode()} disabled={!nodeName.trim() || mutating}>{t.create}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(editingAccount)} onOpenChange={(open) => !open && setEditingAccount(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{editingAccount?.account.displayName}</DialogTitle>
            <DialogDescription>{language === "zh" ? "选择这个账号自动同步的完整节点列表。" : "Choose the complete node list this account should sync."}</DialogDescription>
          </DialogHeader>
          <NodeChecklist nodes={activeNodes} selected={editingNodeIds} onChange={setEditingNodeIds} language={language} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingAccount(null)}>{t.cancel}</Button>
            <Button onClick={() => void saveAccountNodes()} disabled={mutating}>{t.save}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(delivery)} onOpenChange={(open) => !open && setDelivery(null)}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>
              {deliveryKind === "node"
                ? language === "zh" ? "节点邀请码" : "Node setup code"
                : language === "zh" ? "朋友登录码" : "Friend setup code"}
            </DialogTitle>
            <DialogDescription>
              {language === "zh" ? "这是一次性短期凭据，只发给对应的人。" : "This is a short-lived, single-use credential. Send it only to the intended person."}
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-2xl border border-border bg-foreground p-4 text-background">
            <p className="text-[11px] tracking-[0.16em] uppercase opacity-60">{delivery?.displayName}</p>
            <p className="mt-3 break-all font-mono text-xs leading-5">{delivery?.setupCode}</p>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Button variant="outline" onClick={() => delivery && void copyText(delivery.setupCode, setNotice, t.copied)}><Copy />{t.copy}</Button>
            <Button variant="outline" onClick={() => delivery && void copyText(delivery.setupLink, setNotice, t.copied)}><Link2 />{language === "zh" ? "复制链接" : "Copy link"}</Button>
          </div>
          <DialogFooter><Button onClick={() => setDelivery(null)}>{t.close}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function NetworkPage({
  control,
  local,
  language,
  onNavigate,
}: {
  control: ControlSnapshot
  local: XraySnapshot
  language: "zh" | "en"
  onNavigate: (page: PageId) => void
}) {
  const liveNodes = control.nodes.filter((node) => node.status === "active" && node.runtimeState === "serving").length
  const activeAccounts = control.accounts.filter((account) => account.account.status === "active").length
  const readyAssignments = control.accounts.flatMap((account) => account.assignments).filter((assignment) => assignment.provisioningState === "applied").length
  const remoteReady = control.publicOrigin?.startsWith("https://") ?? false
  const publicEndpoint = local.publicIpv4
    ? `${local.publicIpv4}:${local.listenPort ?? 443}`
    : language === "zh" ? "尚未检测" : "Not detected"
  return (
    <>
      {!remoteReady ? (
        <Banner tone="warning" text={language === "zh" ? "控制服务目前只有本机地址。节点和朋友客户端在其他电脑上还不能使用邀请码。" : "Control currently has only a local origin. Setup codes cannot be consumed from another computer yet."} />
      ) : null}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={Server} label={language === "zh" ? "在线节点" : "Live nodes"} value={`${liveNodes}/${control.nodes.filter((node) => node.status !== "revoked").length}`} tone="green" />
        <MetricCard icon={Users} label={language === "zh" ? "启用朋友" : "Active friends"} value={String(activeAccounts)} tone="orange" />
        <MetricCard icon={ShieldCheck} label={language === "zh" ? "已下发访问" : "Applied access"} value={String(readyAssignments)} tone="ink" />
        <MetricCard icon={Wifi} label={language === "zh" ? "公网入口" : "Public endpoint"} value={publicEndpoint} tone="blue" compact />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.25fr_.75fr]">
        <Card className="overflow-hidden border-border/70 bg-panel/86 shadow-panel">
          <CardContent className="p-0">
            <div className="flex items-start justify-between border-b border-border/60 p-5">
              <div>
                <p className="text-xs font-semibold tracking-[0.14em] text-primary uppercase">{language === "zh" ? "服务路径" : "Service path"}</p>
                <h2 className="mt-2 font-heading text-2xl">{language === "zh" ? "一次登录，自动获得所有节点" : "One login, every assigned node"}</h2>
              </div>
              <Badge variant="outline" className="rounded-full">{control.network?.status ?? "offline"}</Badge>
            </div>
            <div className="grid gap-px bg-border/50 sm:grid-cols-3">
              <FlowStep index="01" title="Control" detail={control.healthy ? (language === "zh" ? "账号与节点同步正常" : "Accounts and nodes are syncing") : (language === "zh" ? "控制服务不可用" : "Control unavailable")} />
              <FlowStep index="02" title={language === "zh" ? "公网中继" : "Public relay"} detail={publicEndpoint} />
              <FlowStep index="03" title={language === "zh" ? "家庭出口" : "Home exit"} detail={local.running ? `Xray · ${local.serverName ?? "REALITY"}` : "Xray offline"} />
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/70 bg-foreground text-background shadow-panel">
          <CardContent className="p-5">
            <p className="text-xs tracking-[0.14em] uppercase opacity-55">{language === "zh" ? "当前网络" : "Current network"}</p>
            <h3 className="mt-4 font-heading text-3xl leading-tight">{control.network?.displayName ?? "Private Network"}</h3>
            <div className="mt-6 space-y-3 text-sm">
              <InlineStatus label="Control" ok={control.healthy} />
              <InlineStatus label="Xray" ok={local.running} />
              <InlineStatus label={language === "zh" ? "公网入口" : "Public endpoint"} ok={Boolean(local.publicIpv4)} />
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <SummaryList title={language === "zh" ? "最近节点" : "Recent nodes"} items={control.nodes.slice(-3).reverse().map((node) => ({ title: node.displayName, meta: `${node.runtimeState ?? node.onboardingState} · ${relativeTime(node.lastSeenAt, language)}`, status: node.status }))} empty={language === "zh" ? "还没有节点" : "No nodes yet"} onOpen={() => onNavigate("nodes")} />
        <SummaryList title={language === "zh" ? "朋友账号" : "Friend accounts"} items={control.accounts.filter((account) => account.account.status !== "deleted").slice(-3).reverse().map((account) => ({ title: account.account.displayName, meta: language === "zh" ? `${account.assignments.length} 个节点` : `${account.assignments.length} nodes`, status: account.account.status }))} empty={language === "zh" ? "还没有朋友账号" : "No friend accounts yet"} onOpen={() => onNavigate("friends")} />
      </section>
    </>
  )
}

function NodesPage({ nodes, language, onAction, onAdd }: { nodes: ControlNode[]; language: "zh" | "en"; onAction: (node: ControlNode, action: "approve" | "disable" | "revoke") => void; onAdd: () => void }) {
  const visible = nodes.filter((node) => node.status !== "revoked")
  if (visible.length === 0) return <EmptyState icon={Server} title={language === "zh" ? "添加第一个节点" : "Add your first node"} body={language === "zh" ? "生成邀请码后，对方不需要配置端口、证书或 JSON。" : "The owner will not configure ports, certificates, or JSON."} action={language === "zh" ? "添加节点" : "Add node"} onAction={onAdd} />
  return <div className="grid gap-4 xl:grid-cols-2">{visible.map((node) => <NodeCard key={node.nodeId} node={node} language={language} onAction={onAction} />)}</div>
}

function NodeCard({ node, language, onAction }: { node: ControlNode; language: "zh" | "en"; onAction: (node: ControlNode, action: "approve" | "disable" | "revoke") => void }) {
  const synced = node.revisions.desiredRevision != null && node.revisions.desiredRevision === node.revisions.appliedRevision
  const online = node.status === "active" && node.runtimeState === "serving" && !node.providerPaused
  return (
    <Card className="border-border/70 bg-panel/86 shadow-panel">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <div className={cn("grid size-11 shrink-0 place-items-center rounded-2xl", online ? "bg-emerald-100 text-emerald-700" : "bg-muted text-muted-foreground")}><Server className="size-5" /></div>
            <div className="min-w-0"><h3 className="truncate font-heading text-xl">{node.displayName}</h3><p className="mt-1 truncate text-xs text-muted-foreground">{node.platform} · {node.xrayVersion ?? "Xray pending"}</p></div>
          </div>
          <StatusBadge status={online ? "online" : node.status} language={language} />
        </div>
        <div className="mt-5 grid grid-cols-3 gap-2">
          <TinyMetric label={language === "zh" ? "运行" : "Runtime"} value={node.providerPaused ? (language === "zh" ? "已暂停" : "Paused") : node.runtimeState ?? "—"} />
          <TinyMetric label={language === "zh" ? "配置" : "Revision"} value={node.revisions.appliedRevision != null ? `r${node.revisions.appliedRevision}` : "—"} />
          <TinyMetric label={language === "zh" ? "同步" : "Sync"} value={synced ? (language === "zh" ? "完成" : "Ready") : (language === "zh" ? "等待" : "Pending")} />
        </div>
        <div className="mt-4 flex items-center justify-between border-t border-border/60 pt-4">
          <p className="text-xs text-muted-foreground">{language === "zh" ? "最后在线" : "Last seen"} · {relativeTime(node.lastSeenAt, language)}</p>
          <div className="flex gap-1">
            {node.status === "pending" ? <Button size="sm" onClick={() => onAction(node, "approve")}><Check />{language === "zh" ? "批准" : "Approve"}</Button> : null}
            {node.status === "active" ? <Button variant="outline" size="sm" onClick={() => onAction(node, "disable")}><Pause />{language === "zh" ? "禁用" : "Disable"}</Button> : null}
            {node.status === "disabled" ? <Button variant="outline" size="sm" onClick={() => onAction(node, "approve")}><Play />{language === "zh" ? "启用" : "Enable"}</Button> : null}
            <Button variant="destructive" size="sm" onClick={() => onAction(node, "revoke")}>{language === "zh" ? "撤销" : "Revoke"}</Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function FriendsPage({ accounts, language, onAdd, onEdit, onSetup, onStatus }: { accounts: ControlAccount[]; language: "zh" | "en"; onAdd: () => void; onEdit: (account: ControlAccount) => void; onSetup: (account: ControlAccount) => void; onStatus: (account: ControlAccount, status: "active" | "disabled" | "deleted") => void }) {
  if (accounts.length === 0) return <EmptyState icon={Users} title={language === "zh" ? "添加第一个朋友" : "Add your first friend"} body={language === "zh" ? "朋友只需要一个登录码，之后节点列表会自动同步。" : "Your friend needs one setup code; their node list syncs automatically."} action={language === "zh" ? "添加朋友" : "Add friend"} onAction={onAdd} />
  return <div className="space-y-3">{accounts.map((account) => {
    const assigned = account.assignments.filter((assignment) => assignment.status !== "deleted")
    const applied = assigned.filter((assignment) => assignment.provisioningState === "applied").length
    return <Card key={account.account.userId} className="border-border/70 bg-panel/86 shadow-sm"><CardContent className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center">
      <div className="flex min-w-0 flex-1 items-center gap-3"><div className="grid size-10 place-items-center rounded-2xl bg-primary/12 text-primary"><Users className="size-4" /></div><div className="min-w-0"><h3 className="truncate font-medium">{account.account.displayName}</h3><p className="mt-1 text-xs text-muted-foreground">{language === "zh" ? `${assigned.length} 个节点 · ${applied} 个已就绪` : `${assigned.length} nodes · ${applied} ready`}</p></div></div>
      <div className="flex flex-wrap items-center gap-2"><StatusBadge status={account.account.status} language={language} /><Button variant="outline" size="sm" onClick={() => onEdit(account)}>{language === "zh" ? "分配节点" : "Assign nodes"}</Button><Button size="sm" onClick={() => onSetup(account)} disabled={account.account.status !== "active"}><Link2 />{language === "zh" ? "登录码" : "Setup code"}</Button>{account.account.status === "active" ? <Button variant="ghost" size="sm" onClick={() => onStatus(account, "disabled")}>{language === "zh" ? "禁用" : "Disable"}</Button> : <Button variant="ghost" size="sm" onClick={() => onStatus(account, "active")}>{language === "zh" ? "启用" : "Enable"}</Button>}<Button variant="destructive" size="sm" onClick={() => onStatus(account, "deleted")}>{language === "zh" ? "删除" : "Delete"}</Button></div>
    </CardContent></Card>
  })}</div>
}

function LocalPage({ snapshot, users, language, onServiceAction, onCopy }: { snapshot: XraySnapshot; users: UserListResponse | null; language: "zh" | "en"; onServiceAction: (action: "start" | "stop" | "restart") => void; onCopy: (value: string) => void }) {
  return <div className="space-y-4">
    <Card className="border-border/70 bg-panel/86 shadow-panel"><CardContent className="p-5"><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center"><div className="flex items-center gap-3"><div className={cn("grid size-11 place-items-center rounded-2xl", snapshot.running ? "bg-emerald-100 text-emerald-700" : "bg-muted text-muted-foreground")}><Laptop className="size-5" /></div><div><h2 className="font-heading text-2xl">{language === "zh" ? "家庭出口节点" : "Home exit node"}</h2><p className="mt-1 text-xs text-muted-foreground">{snapshot.version ?? "Xray"}</p></div></div><div className="flex gap-2">{snapshot.running ? <><Button variant="outline" onClick={() => onServiceAction("restart")}><RotateCcw />{language === "zh" ? "重启" : "Restart"}</Button><Button variant="outline" onClick={() => onServiceAction("stop")}><Square />{language === "zh" ? "停止" : "Stop"}</Button></> : <Button onClick={() => onServiceAction("start")}><Play />{language === "zh" ? "启动" : "Start"}</Button>}</div></div><div className="mt-5 grid gap-2 sm:grid-cols-3"><TinyMetric label={language === "zh" ? "公网入口" : "Public endpoint"} value={snapshot.publicIpv4 ? `${snapshot.publicIpv4}:${snapshot.listenPort ?? 443}` : "—"} /><TinyMetric label="REALITY" value={snapshot.serverName ?? "—"} /><TinyMetric label={language === "zh" ? "兼容账号" : "Compatibility users"} value={String(snapshot.userCount ?? 0)} /></div></CardContent></Card>
    <div><div className="mb-3 flex items-center justify-between"><div><h3 className="font-heading text-xl">{language === "zh" ? "兼容连接" : "Compatibility connections"}</h3><p className="mt-1 text-xs text-muted-foreground">{language === "zh" ? "仅供旧客户端使用；新朋友应使用账号登录。" : "For legacy clients only. New friends should use account setup."}</p></div><Badge variant="outline">Advanced</Badge></div><div className="space-y-2">{users?.users.map((user) => <div key={user.id} className="flex items-center gap-3 rounded-2xl border border-border/70 bg-panel/75 p-3"><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{user.label}</p><p className="mt-1 truncate font-mono text-[10px] text-muted-foreground">{user.id}</p></div><Button variant="outline" size="sm" disabled={!user.shareLink} onClick={() => user.shareLink && onCopy(user.shareLink)}><Copy />{language === "zh" ? "复制链接" : "Copy link"}</Button></div>)}</div></div>
  </div>
}

function SettingsPage({ control, local, language }: { control: ControlSnapshot; local: XraySnapshot; language: "zh" | "en" }) {
  const rows = [
    ["Control local", control.localOrigin ?? "—"],
    ["Control public", control.publicOrigin ?? "—"],
    [language === "zh" ? "朋友数据入口" : "Member data endpoint", local.publicIpv4 ? `${local.publicIpv4}:${local.listenPort ?? 443}` : "—"],
    ["REALITY target", local.realityTarget ?? "—"],
    ["Xray config", local.configPath ?? "—"],
    ["Xray binary", local.binaryPath ?? "—"],
  ]
  return <div className="grid gap-4 xl:grid-cols-[1fr_.7fr]"><Card className="border-border/70 bg-panel/86 shadow-panel"><CardContent className="p-0">{rows.map(([label, value]) => <div key={label} className="grid gap-1 border-b border-border/60 px-5 py-3 last:border-0 sm:grid-cols-[10rem_1fr]"><p className="text-xs text-muted-foreground">{label}</p><p className="break-all font-mono text-xs sm:text-right">{value}</p></div>)}</CardContent></Card><Card className="border-border/70 bg-muted/65"><CardContent className="p-5"><CircleAlert className="size-5 text-primary" /><h3 className="mt-4 font-heading text-xl">{language === "zh" ? "当前发布状态" : "Current release state"}</h3><p className="mt-2 text-sm leading-6 text-muted-foreground">{language === "zh" ? "Apple Silicon 本机开发包已安装。生产发布仍需要 Apple 签名、公证，以及 Windows 和 Intel Mac 的实机验收。" : "The Apple Silicon development build is installed. Production still requires Apple signing, notarization, and real Windows and Intel Mac acceptance."}</p></CardContent></Card></div>
}

function NodeChecklist({ nodes, selected, onChange, language }: { nodes: ControlNode[]; selected: string[]; onChange: (ids: string[]) => void; language: "zh" | "en" }) {
  if (nodes.length === 0) return <Banner tone="warning" text={language === "zh" ? "目前没有可分配的启用节点。" : "There are no active nodes to assign."} />
  return <div className="max-h-56 space-y-2 overflow-auto">{nodes.map((node) => {
    const checked = selected.includes(node.nodeId)
    return <button key={node.nodeId} type="button" onClick={() => onChange(checked ? selected.filter((id) => id !== node.nodeId) : [...selected, node.nodeId])} className={cn("flex w-full items-center gap-3 rounded-xl border p-3 text-left transition-colors", checked ? "border-primary/45 bg-primary/8" : "border-border hover:bg-muted")}><span className={cn("grid size-5 place-items-center rounded-md border", checked ? "border-primary bg-primary text-primary-foreground" : "border-border")}>{checked ? <Check className="size-3" /> : null}</span><span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{node.displayName}</span><span className="mt-0.5 block text-xs text-muted-foreground">{node.runtimeState ?? node.onboardingState}</span></span></button>
  })}</div>
}

function MetricCard({ icon: Icon, label, value, tone, compact = false }: { icon: typeof Server; label: string; value: string; tone: "green" | "orange" | "ink" | "blue"; compact?: boolean }) {
  const tones = { green: "bg-emerald-100 text-emerald-700", orange: "bg-orange-100 text-orange-700", ink: "bg-foreground text-background", blue: "bg-sky-100 text-sky-700" }
  return <Card className="border-border/70 bg-panel/86 shadow-sm"><CardContent className="p-4"><div className={cn("grid size-9 place-items-center rounded-xl", tones[tone])}><Icon className="size-4" /></div><p className="mt-5 text-xs text-muted-foreground">{label}</p><p className={cn("mt-1 font-heading text-3xl", compact && "truncate font-sans text-lg font-semibold")}>{value}</p></CardContent></Card>
}

function FlowStep({ index, title, detail }: { index: string; title: string; detail: string }) {
  return <div className="bg-panel p-5"><p className="font-mono text-[10px] text-primary">{index}</p><p className="mt-4 text-sm font-semibold">{title}</p><p className="mt-1 text-xs leading-5 text-muted-foreground">{detail}</p></div>
}

function InlineStatus({ label, ok }: { label: string; ok: boolean }) {
  return <div className="flex items-center justify-between"><span className="opacity-70">{label}</span><span className="flex items-center gap-2"><span className={cn("size-2 rounded-full", ok ? "bg-emerald-400" : "bg-amber-400")} />{ok ? "Online" : "Attention"}</span></div>
}

function SummaryList({ title, items, empty, onOpen }: { title: string; items: Array<{ title: string; meta: string; status: string }>; empty: string; onOpen: () => void }) {
  return <Card className="border-border/70 bg-panel/86 shadow-sm"><CardContent className="p-0"><button type="button" className="flex w-full items-center justify-between border-b border-border/60 px-5 py-4 text-left" onClick={onOpen}><h3 className="font-heading text-xl">{title}</h3><ChevronRight className="size-4 text-muted-foreground" /></button>{items.length === 0 ? <p className="p-5 text-sm text-muted-foreground">{empty}</p> : items.map((item) => <div key={`${item.title}-${item.meta}`} className="flex items-center gap-3 border-b border-border/50 px-5 py-3 last:border-0"><span className={cn("size-2 rounded-full", item.status === "active" ? "bg-emerald-500" : "bg-amber-500")} /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{item.title}</p><p className="mt-1 truncate text-xs text-muted-foreground">{item.meta}</p></div></div>)}</CardContent></Card>
}

function TinyMetric({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0 rounded-xl bg-muted/65 p-3"><p className="text-[10px] tracking-[0.12em] text-muted-foreground uppercase">{label}</p><p className="mt-2 truncate text-sm font-medium">{value}</p></div>
}

function StatusBadge({ status, language }: { status: string; language: "zh" | "en" }) {
  const good = status === "active" || status === "online"
  const text = language === "zh" ? ({ active: "已启用", online: "在线", disabled: "已禁用", pending: "等待批准", revoked: "已撤销" }[status] ?? status) : status
  return <Badge variant="outline" className={cn("rounded-full", good ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-amber-200 bg-amber-50 text-amber-700")}>{text}</Badge>
}

function EmptyState({ icon: Icon, title, body, action, onAction }: { icon: typeof Server; title: string; body: string; action: string; onAction: () => void }) {
  return <Card className="border-dashed border-border bg-panel/65"><CardContent className="grid min-h-80 place-items-center p-8 text-center"><div><div className="mx-auto grid size-14 place-items-center rounded-3xl bg-foreground text-background"><Icon className="size-6" /></div><h2 className="mt-5 font-heading text-3xl">{title}</h2><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-muted-foreground">{body}</p><Button className="mt-5" onClick={onAction}><Plus />{action}</Button></div></CardContent></Card>
}

async function copyText(value: string, setNotice: (value: string) => void, success: string) {
  try { await navigator.clipboard.writeText(value); setNotice(success) } catch { setNotice("Copy failed") }
}

function relativeTime(value: string | null | undefined, language: "zh" | "en") {
  if (!value) return language === "zh" ? "从未" : "never"
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000))
  if (seconds < 60) return language === "zh" ? "刚刚" : "just now"
  if (seconds < 3600) return language === "zh" ? `${Math.floor(seconds / 60)} 分钟前` : `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86_400) return language === "zh" ? `${Math.floor(seconds / 3600)} 小时前` : `${Math.floor(seconds / 3600)}h ago`
  return language === "zh" ? `${Math.floor(seconds / 86_400)} 天前` : `${Math.floor(seconds / 86_400)}d ago`
}

function errorMessage(reason: unknown) {
  return reason instanceof Error ? reason.message : String(reason)
}

export default App
