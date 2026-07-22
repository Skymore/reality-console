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
import { InfoTip } from "@/components/info-tip"
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
  serviceManageable: false,
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

const helpCopy = {
  zh: {
    page: {
      network: "查看整个私人网络是否可用。这里汇总 Control、节点、朋友账号、配置下发和公网入口，不会修改任何配置。",
      nodes: "节点是提供出口网络的设备。只有已启用且最近持续心跳的节点才算在线；离线节点仍保留身份和配置记录。",
      friends: "每位朋友使用一个独立账号。账号会自动同步所有已启用的节点分配，不需要手工维护多条 VLESS 链接。",
      local: "管理这台 Mac 上旧版兼容 Xray。它与新的账号化 Node Host 是两套入口，通常只用于迁移旧客户端。",
      settings: "显示 Control、本机 Xray 和 REALITY 的实际地址与文件路径，主要用于部署检查和排障。",
    },
    controlHealth: "表示本机 Control Service 是否能读取网络、节点和账号数据。它运行在后台，关闭管理窗口不会停止服务。",
    network: {
      liveNodes: "最近 2 分钟内有心跳、状态已启用、运行状态为 serving 且未暂停的节点数量。",
      activeFriends: "当前可以生成登录码并同步节点列表的朋友账号数量。",
      appliedAccess: "已启用的账号到节点分配中，凭据已经进入节点配置并确认应用的数量。",
      publicEndpoint: "旧版兼容 Xray 当前对外提供 VLESS + REALITY 的公网 IP 和端口，不等同于 Control 管理地址。",
      servicePath: "朋友客户端先从 Control 同步可用节点，再经公网入口连接对应出口节点。中继只在直连不可用时作为回退。",
      control: "Control 保存账号、节点清单和配置版本，并向客户端与节点提供同步 API。",
      relay: "公网中继提供稳定可达的控制或数据路径；它不替代节点身份，也不会解密 REALITY 流量。",
      exit: "最终代理流量从家庭节点的公网 IP 访问互联网。",
      currentNetwork: "三项都正常时，账号同步、代理进程和公网入口才构成完整可用链路。",
      recentNodes: "显示最近创建的节点记录。点击右侧箭头进入完整节点管理。",
      friendAccounts: "显示最近创建且未删除的朋友账号，以及每个账号当前启用的节点数量。",
    },
    node: {
      status: "在线要求节点已启用、未暂停、runtime 为 serving，并且最近 2 分钟内有心跳。仅显示“已启用”不代表设备当前在线。",
      runtime: "节点进程报告的数据面状态。serving 表示 Xray 正在接受连接；idle 表示尚未提供流量。",
      revision: "节点最后成功应用的配置版本。每次账号、凭据或入口变化都会产生新的 revision。",
      sync: "Control 的期望版本与节点已应用版本相同才算完成。等待通常表示节点离线，或仍在下载、验证和应用新配置。",
      lastSeen: "Control 最后一次收到该节点认证心跳的时间。超过 2 分钟会在 UI 中视为离线。",
      actions: "禁用会保留节点身份，之后可重新启用；撤销是永久操作，该设备必须使用新的邀请码重新加入。",
      selection: "勾选表示账号将获得该节点的访问权限。取消勾选会停用该分配。节点状态只说明设备是否在线，修改要点击“保存”才生效。",
    },
    friend: {
      summary: "“节点”只统计 enabled 分配；“已就绪”表示对应凭据已经被节点写入当前配置。",
      actions: "分配节点决定账号可见的出口；登录码用于新设备首次登录；禁用可恢复；删除会永久撤销所有节点访问。",
      setupCode: "登录码有效期短且只能使用一次。朋友粘贴后，Connect 会保存设备会话并自动同步节点列表。",
    },
    local: {
      service: "这是这台 Mac 上旧版单机 Xray 服务，不是当前账号化的 Managed Home Node System。",
      publicEndpoint: "路由器或中继对外暴露的地址。客户端必须能访问这个 IP 和端口。",
      reality: "REALITY 伪装目标使用的 SNI。它参与 TLS 握手外观，不是流量最终访问的网站。",
      compatibilityUsers: "直接写在本机 Xray 配置里的旧 VLESS UUID 数量。新朋友应使用“朋友”账号。",
      actions: "重启会短暂断开现有连接；停止会关闭旧版兼容入口，但不会停止 Control Service 或新的 Node Host。",
      compatibility: "这些链接绕过账号同步与多节点管理，只保留给已配置的旧客户端。",
    },
    settings: {
      controlLocal: "管理 App 在本机访问 Control Service 的回环地址，其他设备无法使用。",
      controlPublic: "节点和朋友客户端从外部访问 Control 的 HTTPS 地址。必须公网可达并使用受信任证书。",
      memberEndpoint: "旧版兼容客户端连接本机 Xray 的公网入口。",
      realityTarget: "REALITY 服务器模拟握手时使用的目标站点和 443 端口。",
      xrayConfig: "本机旧版 Xray 当前读取的配置文件。账号化节点配置由 Node Host 单独管理。",
      xrayBinary: "本机旧版 Xray 可执行文件路径。",
      release: "本机开发签名只适合当前 Mac 验收；给朋友分发仍需要 Developer ID、公证和对应平台安装包。",
    },
    dialog: {
      addFriend: "先创建账号，再选择它可访问的节点。创建后可以单独生成一次性登录码。",
      addNode: "这里只生成一次性节点邀请码；节点拥有者仍需在目标设备安装 Node Host 并完成确认。",
      delivery: "代码和链接包含同一份短期秘密。发送其中一种即可，不要截图公开或重复分享。",
    },
  },
  en: {
    page: {
      network: "Read-only health for the whole private network: Control, nodes, friend accounts, applied access, and public entry points.",
      nodes: "Nodes are devices that provide exit connectivity. A node is online only when enabled and sending recent heartbeats.",
      friends: "Each friend gets a separate account that automatically syncs every enabled node assignment.",
      local: "Manage the legacy Xray service on this Mac. It is separate from the account-based Node Host and is mainly for migration.",
      settings: "Inspect the effective Control, local Xray, and REALITY addresses and paths for deployment and diagnostics.",
    },
    controlHealth: "Shows whether the local Control Service can read network, node, and account data. Closing this window does not stop it.",
    network: {
      liveNodes: "Nodes that are enabled, serving, not paused, and have sent a heartbeat within the last two minutes.",
      activeFriends: "Friend accounts that can receive setup codes and synchronize node lists.",
      appliedAccess: "Enabled account-to-node assignments whose credentials are confirmed in the node's applied configuration.",
      publicEndpoint: "The public VLESS + REALITY endpoint of the legacy local Xray service, not the Control management address.",
      servicePath: "Connect syncs nodes from Control, then reaches the selected exit directly or through relay fallback.",
      control: "Control stores accounts, node inventory, and configuration revisions.",
      relay: "The public relay provides fallback reachability without replacing node identity or decrypting REALITY traffic.",
      exit: "Internet traffic ultimately exits through the home node's public IP.",
      currentNetwork: "All three layers must be healthy for account sync and proxy traffic to work end to end.",
      recentNodes: "Recently created node records. Use the arrow to open full node management.",
      friendAccounts: "Recently created friend accounts and their currently enabled node counts.",
    },
    node: {
      status: "Online requires an enabled, unpaused, serving node with a heartbeat in the last two minutes.",
      runtime: "The data-plane state reported by the node. serving means Xray is accepting connections.",
      revision: "The last configuration revision successfully applied by the node.",
      sync: "Sync is complete only when Control's desired revision equals the node's applied revision.",
      lastSeen: "The last authenticated node heartbeat received by Control. The UI treats nodes older than two minutes as offline.",
      actions: "Disable preserves identity and can be reversed. Revoke is permanent and requires a new invitation.",
      selection: "Checked nodes are available to this account. Unchecking disables that assignment. Changes apply only after Save.",
    },
    friend: {
      summary: "Nodes counts enabled assignments; ready means the credential is confirmed in the node configuration.",
      actions: "Assign nodes controls available exits; setup code signs in a new device; disable is reversible; delete is permanent.",
      setupCode: "The setup code is short-lived and single-use. Connect stores a device session and then syncs nodes automatically.",
    },
    local: {
      service: "This is the legacy standalone Xray service on this Mac, not Managed Home Node System.",
      publicEndpoint: "The public IP and port that compatibility clients must reach.",
      reality: "The SNI used for REALITY's TLS appearance, not the final website requested by proxy traffic.",
      compatibilityUsers: "Legacy VLESS UUIDs written directly into the local Xray configuration.",
      actions: "Restart briefly disconnects sessions. Stop affects only the legacy entry point, not Control or Node Host.",
      compatibility: "These links bypass account sync and multi-node management and should be kept only for existing clients.",
    },
    settings: {
      controlLocal: "The loopback address used by this app. Other devices cannot reach it.",
      controlPublic: "The public HTTPS origin used by nodes and Connect clients.",
      memberEndpoint: "The public endpoint for legacy compatibility clients.",
      realityTarget: "The target host and port used to shape the REALITY handshake.",
      xrayConfig: "The active legacy Xray config. Node Host manages its own configuration separately.",
      xrayBinary: "The legacy local Xray executable path.",
      release: "Local development signing is for this Mac only. Friend distribution still needs Developer ID signing and notarization.",
    },
    dialog: {
      addFriend: "Create an account, choose its available nodes, then issue a separate single-use setup code.",
      addNode: "This creates a one-time node invitation. The owner still installs Node Host and confirms setup.",
      delivery: "The code and link contain the same temporary secret. Send one, and never publish or reuse it.",
    },
  },
}

const NODE_ONLINE_GRACE_MS = 2 * 60 * 1000

function App() {
  const { i18n } = useTranslation()
  const language = i18n.language.startsWith("zh") ? "zh" : "en"
  const t = copy[language]
  const h = helpCopy[language]
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
  const [nodePendingRevoke, setNodePendingRevoke] = useState<ControlNode | null>(null)
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

  async function performNodeAction(node: ControlNode, action: "approve" | "disable" | "revoke") {
    const result = await mutate(
      () => invoke("control_node_action", { input: { nodeId: node.nodeId, action } }),
      language === "zh" ? "节点状态已更新" : "Node state updated",
    )
    if (result !== null && action === "revoke") setNodePendingRevoke(null)
  }

  function runNodeAction(node: ControlNode, action: "approve" | "disable" | "revoke") {
    if (action === "revoke") {
      setNodePendingRevoke(node)
      return
    }
    void performNodeAction(node, action)
  }

  async function serviceAction(action: "start" | "stop" | "restart") {
    const result = await mutate(
      () => invoke("service_action", { action }),
      language === "zh" ? "本机 Xray 状态已更新" : "Local Xray state updated",
    )
    if (result !== null) {
      setNotice(
        language === "zh"
          ? action === "stop" ? "兼容 Xray 已停止" : action === "restart" ? "兼容 Xray 已重启" : "兼容 Xray 已启动"
          : action === "stop" ? "Compatibility Xray stopped" : action === "restart" ? "Compatibility Xray restarted" : "Compatibility Xray started",
      )
    }
  }

  function openAccountEditor(account: ControlAccount) {
    setEditingAccount(account)
    setEditingNodeIds(
      account.assignments
        .filter((assignment) => assignment.status === "enabled")
        .map((assignment) => assignment.nodeId),
    )
  }

  return (
    <div className="relative h-screen min-h-0 overflow-hidden bg-background text-foreground">
      <div className="pointer-events-none fixed inset-0 opacity-45 [background-image:linear-gradient(to_right,rgb(39_38_34/0.035)_1px,transparent_1px),linear-gradient(to_bottom,rgb(39_38_34/0.035)_1px,transparent_1px)] [background-size:28px_28px]" />
      <div className="relative flex h-full min-h-0">
        <aside className="flex h-full w-56 shrink-0 flex-col border-r border-border/70 bg-sidebar/86 backdrop-blur-xl">
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

          <nav className="flex min-h-0 flex-col gap-1 overflow-y-auto px-3 pb-3">
            {navItems.map((item) => {
              const Icon = item.icon
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setPage(item.id)}
                  className={cn(
                    "flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm transition-colors",
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

          <div className="mt-auto p-4">
            <div className="rounded-2xl border border-border/70 bg-background/70 p-3">
              <div className="flex items-center gap-2 text-xs font-medium">
                <span className={cn("size-2 rounded-full", control.healthy ? "bg-emerald-500" : "bg-amber-500")} />
                {control.healthy ? t.online : t.attention}
                <InfoTip
                  label={language === "zh" ? "说明 Control 状态" : "Explain Control status"}
                  className="ml-auto"
                  side="right"
                >
                  {h.controlHealth}
                </InfoTip>
              </div>
              <p className="mt-2 truncate text-[11px] text-muted-foreground">
                {control.network?.displayName ?? "Control Service"}
              </p>
            </div>
          </div>
        </aside>

        <main className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          <header
            className="flex h-24 shrink-0 items-center justify-between gap-6 border-b border-border/60 px-8 py-5 select-none"
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
            <div className="min-w-0">
              <p className="text-[11px] font-semibold tracking-[0.18em] text-primary uppercase">
                {control.network?.displayName ?? "Private Network"}
              </p>
              <div className="mt-1 flex items-center gap-2">
                <h1 className="font-heading text-3xl leading-none lg:text-4xl">{pageCopy[0]}</h1>
                <InfoTip
                  label={language === "zh" ? `说明${pageCopy[0]}` : `Explain ${pageCopy[0]}`}
                  side="bottom"
                >
                  {h.page[page]}
                </InfoTip>
              </div>
              <p className="mt-2 max-w-2xl text-sm text-muted-foreground">{pageCopy[1]}</p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Button
                variant="outline"
                onClick={toggleLanguage}
                aria-label={language === "zh" ? "Switch to English" : "切换到中文"}
                title={language === "zh" ? "Switch to English" : "切换到中文"}
              >
                <Languages />
                <span>{language === "zh" ? "EN" : "中文"}</span>
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

          <ScrollArea className="min-h-0 flex-1 overscroll-contain">
            <div className="mx-auto max-w-6xl space-y-4 p-8 pb-12">
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
                  busy={mutating}
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
            <DialogTitle className="flex items-center gap-2">
              {language === "zh" ? "添加朋友" : "Add a friend"}
              <InfoTip label={language === "zh" ? "说明朋友账号" : "Explain friend accounts"}>
                {h.dialog.addFriend}
              </InfoTip>
            </DialogTitle>
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
            <DialogTitle className="flex items-center gap-2">
              {language === "zh" ? "添加一个节点" : "Add a node"}
              <InfoTip label={language === "zh" ? "说明节点邀请码" : "Explain node invitations"}>
                {h.dialog.addNode}
              </InfoTip>
            </DialogTitle>
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
            <DialogTitle className="flex items-center gap-2">
              {editingAccount?.account.displayName}
              <InfoTip label={language === "zh" ? "说明节点分配" : "Explain node assignment"}>
                {h.node.selection}
              </InfoTip>
            </DialogTitle>
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
            <DialogTitle className="flex items-center gap-2">
              {deliveryKind === "node"
                ? language === "zh" ? "节点邀请码" : "Node setup code"
                : language === "zh" ? "朋友登录码" : "Friend setup code"}
              <InfoTip label={language === "zh" ? "说明一次性代码" : "Explain one-time codes"}>
                {h.dialog.delivery}
              </InfoTip>
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

      <Dialog
        open={Boolean(nodePendingRevoke)}
        onOpenChange={(open) => {
          if (!open && !mutating) setNodePendingRevoke(null)
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{language === "zh" ? "永久撤销这个节点？" : "Permanently revoke this node?"}</DialogTitle>
            <DialogDescription>
              {language === "zh"
                ? `${nodePendingRevoke?.displayName ?? "该节点"} 将立即失去控制面和所有朋友账号的访问权限。此操作无法撤销；这台设备必须使用新的节点邀请码重新加入。`
                : `${nodePendingRevoke?.displayName ?? "This node"} will immediately lose Control and all friend-account access. This cannot be undone; the device must join again with a new node setup code.`}
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-xl border border-destructive/25 bg-destructive/5 p-3 text-sm">
            <p className="font-medium">{nodePendingRevoke?.displayName}</p>
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{nodePendingRevoke?.nodeId}</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNodePendingRevoke(null)} disabled={mutating}>{t.cancel}</Button>
            <Button
              variant="destructive"
              onClick={() => nodePendingRevoke && void performNodeAction(nodePendingRevoke, "revoke")}
              disabled={!nodePendingRevoke || mutating}
            >
              {language === "zh" ? "永久撤销" : "Revoke permanently"}
            </Button>
          </DialogFooter>
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
  const h = helpCopy[language]
  const liveNodes = control.nodes.filter(isNodeOnline).length
  const activeAccounts = control.accounts.filter((account) => account.account.status === "active").length
  const readyAssignments = control.accounts
    .flatMap((account) => account.assignments)
    .filter((assignment) => assignment.status === "enabled" && assignment.provisioningState === "applied")
    .length
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
        <MetricCard icon={Server} label={language === "zh" ? "在线节点" : "Live nodes"} value={`${liveNodes}/${control.nodes.filter((node) => node.status !== "revoked").length}`} tone="green" help={h.network.liveNodes} language={language} />
        <MetricCard icon={Users} label={language === "zh" ? "启用朋友" : "Active friends"} value={String(activeAccounts)} tone="orange" help={h.network.activeFriends} language={language} />
        <MetricCard icon={ShieldCheck} label={language === "zh" ? "已下发访问" : "Applied access"} value={String(readyAssignments)} tone="ink" help={h.network.appliedAccess} language={language} />
        <MetricCard icon={Wifi} label={language === "zh" ? "公网入口" : "Public endpoint"} value={publicEndpoint} tone="blue" compact help={h.network.publicEndpoint} language={language} />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.25fr_.75fr]">
        <Card className="overflow-hidden border-border/70 bg-panel/86 shadow-panel">
          <CardContent className="p-0">
            <div className="flex items-start justify-between border-b border-border/60 p-5">
              <div>
                <div className="flex items-center gap-1.5">
                  <p className="text-xs font-semibold tracking-[0.14em] text-primary uppercase">{language === "zh" ? "服务路径" : "Service path"}</p>
                  <InfoTip label={language === "zh" ? "说明服务路径" : "Explain service path"}>
                    {h.network.servicePath}
                  </InfoTip>
                </div>
                <h2 className="mt-2 font-heading text-2xl">{language === "zh" ? "一次登录，自动获得所有节点" : "One login, every assigned node"}</h2>
              </div>
              <Badge variant="outline" className="rounded-full">{control.network?.status ?? "offline"}</Badge>
            </div>
            <div className="grid gap-px bg-border/50 sm:grid-cols-3">
              <FlowStep index="01" title="Control" detail={control.healthy ? (language === "zh" ? "账号与节点同步正常" : "Accounts and nodes are syncing") : (language === "zh" ? "控制服务不可用" : "Control unavailable")} help={h.network.control} language={language} />
              <FlowStep index="02" title={language === "zh" ? "公网中继" : "Public relay"} detail={publicEndpoint} help={h.network.relay} language={language} />
              <FlowStep index="03" title={language === "zh" ? "家庭出口" : "Home exit"} detail={local.running ? `Xray · ${local.serverName ?? "REALITY"}` : "Xray offline"} help={h.network.exit} language={language} />
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/70 bg-foreground text-background shadow-panel">
          <CardContent className="p-5">
            <div className="flex items-center gap-1.5">
              <p className="text-xs tracking-[0.14em] uppercase opacity-55">{language === "zh" ? "当前网络" : "Current network"}</p>
              <InfoTip label={language === "zh" ? "说明当前网络" : "Explain current network"} className="text-background/65 hover:bg-background/10 hover:text-background">
                {h.network.currentNetwork}
              </InfoTip>
            </div>
            <h3 className="mt-4 font-heading text-3xl leading-tight">{control.network?.displayName ?? "Private Network"}</h3>
            <div className="mt-6 space-y-3 text-sm">
              <InlineStatus label="Control" ok={control.healthy} help={h.network.control} language={language} />
              <InlineStatus label="Xray" ok={local.running} help={h.local.service} language={language} />
              <InlineStatus label={language === "zh" ? "公网入口" : "Public endpoint"} ok={Boolean(local.publicIpv4)} help={h.network.publicEndpoint} language={language} />
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <SummaryList title={language === "zh" ? "最近节点" : "Recent nodes"} help={h.network.recentNodes} language={language} items={control.nodes.slice(-3).reverse().map((node) => ({ title: node.displayName, meta: `${nodeAvailabilityLabel(node, language)} · ${relativeTime(node.lastSeenAt, language)}`, status: isNodeOnline(node) ? "online" : node.status }))} empty={language === "zh" ? "还没有节点" : "No nodes yet"} onOpen={() => onNavigate("nodes")} />
        <SummaryList title={language === "zh" ? "朋友账号" : "Friend accounts"} help={h.network.friendAccounts} language={language} items={control.accounts.filter((account) => account.account.status !== "deleted").slice(-3).reverse().map((account) => {
          const enabled = account.assignments.filter((assignment) => assignment.status === "enabled").length
          return { title: account.account.displayName, meta: language === "zh" ? `${enabled} 个节点` : `${enabled} nodes`, status: account.account.status }
        })} empty={language === "zh" ? "还没有朋友账号" : "No friend accounts yet"} onOpen={() => onNavigate("friends")} />
      </section>
    </>
  )
}

function NodesPage({ nodes, language, onAction, onAdd }: { nodes: ControlNode[]; language: "zh" | "en"; onAction: (node: ControlNode, action: "approve" | "disable" | "revoke") => void; onAdd: () => void }) {
  const visible = nodes.filter((node) => node.status !== "revoked")
  if (visible.length === 0) return <EmptyState icon={Server} title={language === "zh" ? "添加第一个节点" : "Add your first node"} body={language === "zh" ? "生成邀请码后，对方不需要配置端口、证书或 JSON。" : "The owner will not configure ports, certificates, or JSON."} action={language === "zh" ? "添加节点" : "Add node"} onAction={onAdd} />
  const stale = visible.filter((node) => node.status === "active" && !isNodeOnline(node))
  return (
    <div className="space-y-4">
      {stale.length > 0 ? (
        <Banner
          tone="warning"
          text={language === "zh"
            ? `${stale.length} 个已启用节点超过 2 分钟没有心跳，当前不能使用。确认是旧设备后可以禁用或撤销。`
            : `${stale.length} enabled node(s) have not sent a heartbeat for over two minutes and are currently unavailable.`}
        />
      ) : null}
      <div className="grid gap-4 xl:grid-cols-2">
        {visible.map((node) => <NodeCard key={node.nodeId} node={node} language={language} onAction={onAction} />)}
      </div>
    </div>
  )
}

function NodeCard({ node, language, onAction }: { node: ControlNode; language: "zh" | "en"; onAction: (node: ControlNode, action: "approve" | "disable" | "revoke") => void }) {
  const h = helpCopy[language]
  const desiredRevision = node.revisions.desiredRevision
  const appliedRevision = node.revisions.appliedRevision
  const synced = desiredRevision != null && desiredRevision === appliedRevision
  const online = isNodeOnline(node)
  const syncValue = desiredRevision == null
    ? "—"
    : synced
      ? language === "zh" ? "完成" : "Ready"
      : language === "zh" ? `等待 r${desiredRevision}` : `Waiting for r${desiredRevision}`
  const badgeStatus = node.status === "active" ? (online ? "online" : "offline") : node.status
  return (
    <Card className="border-border/70 bg-panel/86 shadow-panel">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <div className={cn("grid size-11 shrink-0 place-items-center rounded-2xl", online ? "bg-emerald-100 text-emerald-700" : "bg-muted text-muted-foreground")}><Server className="size-5" /></div>
            <div className="min-w-0"><h3 className="truncate font-heading text-xl">{node.displayName}</h3><p className="mt-1 truncate text-xs text-muted-foreground">{node.platform} · {node.xrayVersion ?? "Xray pending"}</p></div>
          </div>
          <div className="flex items-center gap-1">
            <StatusBadge status={badgeStatus} language={language} />
            <InfoTip label={language === "zh" ? "说明节点状态" : "Explain node status"}>
              {h.node.status}
            </InfoTip>
          </div>
        </div>
        <div className="mt-5 grid grid-cols-3 gap-2">
          <TinyMetric label={language === "zh" ? "运行" : "Runtime"} value={node.providerPaused ? (language === "zh" ? "已暂停" : "Paused") : nodeAvailabilityLabel(node, language)} help={h.node.runtime} language={language} />
          <TinyMetric label={language === "zh" ? "配置" : "Revision"} value={appliedRevision != null ? `r${appliedRevision}` : "—"} help={h.node.revision} language={language} />
          <TinyMetric label={language === "zh" ? "同步" : "Sync"} value={syncValue} help={nodeSyncHelp(node, language)} language={language} />
        </div>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border/60 pt-4">
          <div className="flex items-center gap-1">
            <p className="text-xs text-muted-foreground">{language === "zh" ? "最后在线" : "Last seen"} · {relativeTime(node.lastSeenAt, language)}</p>
            <InfoTip label={language === "zh" ? "说明最后在线" : "Explain last seen"}>
              {h.node.lastSeen}
            </InfoTip>
          </div>
          <div className="ml-auto flex flex-wrap justify-end gap-1">
            <InfoTip label={language === "zh" ? "说明节点操作" : "Explain node actions"} side="left">
              {h.node.actions}
            </InfoTip>
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
  const h = helpCopy[language]
  return <div className="space-y-3">{accounts.map((account) => {
    const assigned = account.assignments.filter((assignment) => assignment.status === "enabled")
    const applied = assigned.filter((assignment) => assignment.provisioningState === "applied").length
    return (
      <Card key={account.account.userId} className="border-border/70 bg-panel/86 shadow-sm">
        <CardContent className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <div className="grid size-10 place-items-center rounded-2xl bg-primary/12 text-primary"><Users className="size-4" /></div>
            <div className="min-w-0">
              <h3 className="truncate font-medium">{account.account.displayName}</h3>
              <div className="mt-1 flex items-center gap-1">
                <p className="text-xs text-muted-foreground">
                  {language === "zh" ? `${assigned.length} 个节点 · ${applied} 个已就绪` : `${assigned.length} nodes · ${applied} ready`}
                </p>
                <InfoTip label={language === "zh" ? "说明账号节点状态" : "Explain account node state"}>
                  {h.friend.summary}
                </InfoTip>
              </div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={account.account.status} language={language} />
            <InfoTip label={language === "zh" ? "说明账号操作" : "Explain account actions"} side="left">
              {h.friend.actions}
            </InfoTip>
            <Button variant="outline" size="sm" onClick={() => onEdit(account)}>{language === "zh" ? "分配节点" : "Assign nodes"}</Button>
            <Button size="sm" onClick={() => onSetup(account)} disabled={account.account.status !== "active"}><Link2 />{language === "zh" ? "登录码" : "Setup code"}</Button>
            {account.account.status === "active"
              ? <Button variant="ghost" size="sm" onClick={() => onStatus(account, "disabled")}>{language === "zh" ? "禁用" : "Disable"}</Button>
              : <Button variant="ghost" size="sm" onClick={() => onStatus(account, "active")}>{language === "zh" ? "启用" : "Enable"}</Button>}
            <Button variant="destructive" size="sm" onClick={() => onStatus(account, "deleted")}>{language === "zh" ? "删除" : "Delete"}</Button>
          </div>
        </CardContent>
      </Card>
    )
  })}</div>
}

function LocalPage({ snapshot, users, language, busy, onServiceAction, onCopy }: { snapshot: XraySnapshot; users: UserListResponse | null; language: "zh" | "en"; busy: boolean; onServiceAction: (action: "start" | "stop" | "restart") => void; onCopy: (value: string) => void }) {
  const h = helpCopy[language]
  const actionUnavailable = busy || !snapshot.serviceManageable
  return (
    <div className="space-y-4">
      <Card className="border-border/70 bg-panel/86 shadow-panel">
        <CardContent className="p-5">
          <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
            <div className="flex items-center gap-3">
              <div className={cn("grid size-11 place-items-center rounded-2xl", snapshot.running ? "bg-emerald-100 text-emerald-700" : "bg-muted text-muted-foreground")}><Laptop className="size-5" /></div>
              <div>
                <div className="flex items-center gap-1.5">
                  <h2 className="font-heading text-2xl">{language === "zh" ? "旧版兼容 Xray" : "Legacy compatibility Xray"}</h2>
                  <InfoTip label={language === "zh" ? "说明本机出口" : "Explain local exit"}>
                    {h.local.service}
                  </InfoTip>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{snapshot.version ?? "Xray"}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <InfoTip label={language === "zh" ? "说明服务操作" : "Explain service actions"} side="left">
                {h.local.actions}
              </InfoTip>
              {snapshot.running ? (
                <>
                  <Button variant="outline" disabled={actionUnavailable} onClick={() => onServiceAction("restart")}>
                    <RotateCcw className={cn(busy && "animate-spin")} />{busy ? language === "zh" ? "处理中" : "Working" : language === "zh" ? "重启" : "Restart"}
                  </Button>
                  <Button variant="outline" disabled={actionUnavailable} onClick={() => onServiceAction("stop")}><Square />{language === "zh" ? "停止" : "Stop"}</Button>
                </>
              ) : (
                <Button disabled={actionUnavailable} onClick={() => onServiceAction("start")}>
                  <Play />{busy ? language === "zh" ? "处理中" : "Working" : language === "zh" ? "启动" : "Start"}
                </Button>
              )}
            </div>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <Badge variant="outline">
              {snapshot.running
                ? language === "zh" ? `运行中${snapshot.pid ? ` · PID ${snapshot.pid}` : ""}` : `Running${snapshot.pid ? ` · PID ${snapshot.pid}` : ""}`
                : language === "zh" ? "已停止" : "Stopped"}
            </Badge>
            <span>
              {snapshot.serviceManageable
                ? language === "zh" ? `由 ${snapshot.serviceManager ?? "Homebrew services"} 管理` : `Managed by ${snapshot.serviceManager ?? "Homebrew services"}`
                : language === "zh" ? "未检测到可管理的 Homebrew Xray 服务" : "No manageable Homebrew Xray service detected"}
            </span>
          </div>
          <div className="mt-5 grid gap-2 sm:grid-cols-3">
            <TinyMetric label={language === "zh" ? "公网入口" : "Public endpoint"} value={snapshot.publicIpv4 ? `${snapshot.publicIpv4}:${snapshot.listenPort ?? 443}` : "—"} help={h.local.publicEndpoint} language={language} />
            <TinyMetric label="REALITY" value={snapshot.serverName ?? "—"} help={h.local.reality} language={language} />
            <TinyMetric label={language === "zh" ? "兼容账号" : "Compatibility users"} value={String(snapshot.userCount ?? 0)} help={h.local.compatibilityUsers} language={language} />
          </div>
        </CardContent>
      </Card>
      <div>
        <div className="mb-3 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-1.5">
              <h3 className="font-heading text-xl">{language === "zh" ? "兼容连接" : "Compatibility connections"}</h3>
              <InfoTip label={language === "zh" ? "说明兼容连接" : "Explain compatibility connections"}>
                {h.local.compatibility}
              </InfoTip>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{language === "zh" ? "仅供旧客户端使用；新朋友应使用账号登录。" : "For legacy clients only. New friends should use account setup."}</p>
          </div>
          <Badge variant="outline">Advanced</Badge>
        </div>
        <div className="space-y-2">
          {users?.users.map((user) => (
            <div key={user.id} className="flex items-center gap-3 rounded-2xl border border-border/70 bg-panel/75 p-3">
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{user.label}</p>
                <p className="mt-1 truncate font-mono text-[10px] text-muted-foreground">{user.id}</p>
              </div>
              <Button variant="outline" size="sm" disabled={!user.shareLink} onClick={() => user.shareLink && onCopy(user.shareLink)}>
                <Copy />{language === "zh" ? "复制链接" : "Copy link"}
              </Button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function SettingsPage({ control, local, language }: { control: ControlSnapshot; local: XraySnapshot; language: "zh" | "en" }) {
  const h = helpCopy[language]
  const rows = [
    { label: "Control local", value: control.localOrigin ?? "—", help: h.settings.controlLocal },
    { label: "Control public", value: control.publicOrigin ?? "—", help: h.settings.controlPublic },
    { label: language === "zh" ? "朋友数据入口" : "Member data endpoint", value: local.publicIpv4 ? `${local.publicIpv4}:${local.listenPort ?? 443}` : "—", help: h.settings.memberEndpoint },
    { label: "REALITY target", value: local.realityTarget ?? "—", help: h.settings.realityTarget },
    { label: "Xray config", value: local.configPath ?? "—", help: h.settings.xrayConfig },
    { label: "Xray binary", value: local.binaryPath ?? "—", help: h.settings.xrayBinary },
  ]
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_.7fr]">
      <Card className="border-border/70 bg-panel/86 shadow-panel">
        <CardContent className="p-0">
          {rows.map((row) => (
            <div key={row.label} className="grid gap-1 border-b border-border/60 px-5 py-3 last:border-0 sm:grid-cols-[10rem_1fr]">
              <div className="flex items-center gap-1">
                <p className="text-xs text-muted-foreground">{row.label}</p>
                <InfoTip label={language === "zh" ? `说明 ${row.label}` : `Explain ${row.label}`}>
                  {row.help}
                </InfoTip>
              </div>
              <p className="break-all font-mono text-xs sm:text-right">{row.value}</p>
            </div>
          ))}
        </CardContent>
      </Card>
      <Card className="border-border/70 bg-muted/65">
        <CardContent className="p-5">
          <CircleAlert className="size-5 text-primary" />
          <div className="mt-4 flex items-center gap-1.5">
            <h3 className="font-heading text-xl">{language === "zh" ? "当前发布状态" : "Current release state"}</h3>
            <InfoTip label={language === "zh" ? "说明发布状态" : "Explain release state"}>
              {h.settings.release}
            </InfoTip>
          </div>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">{language === "zh" ? "Apple Silicon 本机开发包已安装。生产发布仍需要 Apple 签名、公证，以及 Windows 和 Intel Mac 的实机验收。" : "The Apple Silicon development build is installed. Production still requires Apple signing, notarization, and real Windows and Intel Mac acceptance."}</p>
        </CardContent>
      </Card>
    </div>
  )
}

function NodeChecklist({ nodes, selected, onChange, language }: { nodes: ControlNode[]; selected: string[]; onChange: (ids: string[]) => void; language: "zh" | "en" }) {
  if (nodes.length === 0) return <Banner tone="warning" text={language === "zh" ? "目前没有可分配的启用节点。" : "There are no active nodes to assign."} />
  const h = helpCopy[language]
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between rounded-xl border border-border/60 bg-muted/35 px-3 py-2">
        <p className="text-xs text-muted-foreground">
          {language === "zh" ? `已选择 ${selected.length} / ${nodes.length} 个节点` : `${selected.length} of ${nodes.length} nodes selected`}
        </p>
        <InfoTip label={language === "zh" ? "说明如何分配节点" : "Explain node assignment"} side="left">
          {h.node.selection}
        </InfoTip>
      </div>
      <div className="max-h-56 space-y-2 overflow-auto pr-1">
        {nodes.map((node) => {
          const checked = selected.includes(node.nodeId)
          const online = isNodeOnline(node)
          return (
            <button
              key={node.nodeId}
              type="button"
              onClick={() => onChange(checked ? selected.filter((id) => id !== node.nodeId) : [...selected, node.nodeId])}
              className={cn(
                "flex w-full cursor-pointer items-center gap-3 rounded-xl border p-3 text-left transition-colors",
                checked ? "border-primary/45 bg-primary/8" : "border-border hover:bg-muted",
              )}
            >
              <span className={cn("grid size-5 place-items-center rounded-md border", checked ? "border-primary bg-primary text-primary-foreground" : "border-border")}>
                {checked ? <Check className="size-3" /> : null}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium">{node.displayName}</span>
                <span className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
                  <span className={cn("size-1.5 rounded-full", online ? "bg-emerald-500" : "bg-amber-500")} />
                  {nodeAvailabilityLabel(node, language)} · {relativeTime(node.lastSeenAt, language)}
                </span>
              </span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function MetricCard({ icon: Icon, label, value, tone, compact = false, help, language }: { icon: typeof Server; label: string; value: string; tone: "green" | "orange" | "ink" | "blue"; compact?: boolean; help: string; language: "zh" | "en" }) {
  const tones = { green: "bg-emerald-100 text-emerald-700", orange: "bg-orange-100 text-orange-700", ink: "bg-foreground text-background", blue: "bg-sky-100 text-sky-700" }
  return <Card className="border-border/70 bg-panel/86 shadow-sm"><CardContent className="p-4"><div className={cn("grid size-9 place-items-center rounded-xl", tones[tone])}><Icon className="size-4" /></div><div className="mt-5 flex items-center gap-1"><p className="text-xs text-muted-foreground">{label}</p><InfoTip label={language === "zh" ? `说明${label}` : `Explain ${label}`}>{help}</InfoTip></div><p className={cn("mt-1 font-heading text-3xl", compact && "truncate font-sans text-lg font-semibold")}>{value}</p></CardContent></Card>
}

function FlowStep({ index, title, detail, help, language }: { index: string; title: string; detail: string; help: string; language: "zh" | "en" }) {
  return <div className="bg-panel p-5"><p className="font-mono text-[10px] text-primary">{index}</p><div className="mt-4 flex items-center gap-1"><p className="text-sm font-semibold">{title}</p><InfoTip label={language === "zh" ? `说明${title}` : `Explain ${title}`}>{help}</InfoTip></div><p className="mt-1 text-xs leading-5 text-muted-foreground">{detail}</p></div>
}

function InlineStatus({ label, ok, help, language }: { label: string; ok: boolean; help: string; language: "zh" | "en" }) {
  return <div className="flex items-center justify-between"><span className="flex items-center gap-1 opacity-70">{label}<InfoTip label={language === "zh" ? `说明${label}` : `Explain ${label}`} className="text-background/65 hover:bg-background/10 hover:text-background">{help}</InfoTip></span><span className="flex items-center gap-2"><span className={cn("size-2 rounded-full", ok ? "bg-emerald-400" : "bg-amber-400")} />{ok ? (language === "zh" ? "正常" : "Online") : (language === "zh" ? "需处理" : "Attention")}</span></div>
}

function SummaryList({ title, help, language, items, empty, onOpen }: { title: string; help: string; language: "zh" | "en"; items: Array<{ title: string; meta: string; status: string }>; empty: string; onOpen: () => void }) {
  return <Card className="border-border/70 bg-panel/86 shadow-sm"><CardContent className="p-0"><div className="flex items-center justify-between border-b border-border/60 px-5 py-4"><div className="flex items-center gap-1.5"><h3 className="font-heading text-xl">{title}</h3><InfoTip label={language === "zh" ? `说明${title}` : `Explain ${title}`}>{help}</InfoTip></div><button type="button" className="grid size-7 cursor-pointer place-items-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground" onClick={onOpen} aria-label={language === "zh" ? `打开${title}` : `Open ${title}`}><ChevronRight className="size-4" /></button></div>{items.length === 0 ? <p className="p-5 text-sm text-muted-foreground">{empty}</p> : items.map((item) => <div key={`${item.title}-${item.meta}`} className="flex items-center gap-3 border-b border-border/50 px-5 py-3 last:border-0"><span className={cn("size-2 rounded-full", item.status === "active" || item.status === "online" ? "bg-emerald-500" : "bg-amber-500")} /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{item.title}</p><p className="mt-1 truncate text-xs text-muted-foreground">{item.meta}</p></div></div>)}</CardContent></Card>
}

function TinyMetric({ label, value, help, language }: { label: string; value: string; help: string; language: "zh" | "en" }) {
  return <div className="min-w-0 rounded-xl bg-muted/65 p-3"><div className="flex items-center gap-1"><p className="text-[10px] tracking-[0.12em] text-muted-foreground uppercase">{label}</p><InfoTip label={language === "zh" ? `说明${label}` : `Explain ${label}`}>{help}</InfoTip></div><p className="mt-2 truncate text-sm font-medium">{value}</p></div>
}

function StatusBadge({ status, language }: { status: string; language: "zh" | "en" }) {
  const good = status === "active" || status === "online"
  const labels = language === "zh"
    ? { active: "已启用", online: "在线", offline: "离线", disabled: "已禁用", pending: "等待批准", revoked: "已撤销" }
    : { active: "Active", online: "Online", offline: "Offline", disabled: "Disabled", pending: "Pending approval", revoked: "Revoked" }
  const text = labels[status as keyof typeof labels] ?? status
  return <Badge variant="outline" className={cn("rounded-full", good ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-amber-200 bg-amber-50 text-amber-700")}>{text}</Badge>
}

function EmptyState({ icon: Icon, title, body, action, onAction }: { icon: typeof Server; title: string; body: string; action: string; onAction: () => void }) {
  return <Card className="border-dashed border-border bg-panel/65"><CardContent className="grid min-h-80 place-items-center p-8 text-center"><div><div className="mx-auto grid size-14 place-items-center rounded-3xl bg-foreground text-background"><Icon className="size-6" /></div><h2 className="mt-5 font-heading text-3xl">{title}</h2><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-muted-foreground">{body}</p><Button className="mt-5" onClick={onAction}><Plus />{action}</Button></div></CardContent></Card>
}

async function copyText(value: string, setNotice: (value: string) => void, success: string) {
  try { await navigator.clipboard.writeText(value); setNotice(success) } catch { setNotice("Copy failed") }
}

function hasRecentHeartbeat(node: ControlNode): boolean {
  if (!node.lastSeenAt) return false
  const lastSeen = Date.parse(node.lastSeenAt)
  return Number.isFinite(lastSeen) && Date.now() - lastSeen <= NODE_ONLINE_GRACE_MS
}

function isNodeOnline(node: ControlNode): boolean {
  return node.status === "active"
    && node.runtimeState === "serving"
    && !node.providerPaused
    && hasRecentHeartbeat(node)
}

function nodeAvailabilityLabel(node: ControlNode, language: "zh" | "en"): string {
  if (node.status === "revoked") return language === "zh" ? "已撤销" : "Revoked"
  if (node.status === "disabled") return language === "zh" ? "已禁用" : "Disabled"
  if (node.status === "pending") return language === "zh" ? "等待批准" : "Pending approval"
  if (node.providerPaused) return language === "zh" ? "已暂停" : "Paused"
  if (!hasRecentHeartbeat(node)) return language === "zh" ? "离线" : "Offline"
  const labels = language === "zh"
    ? { serving: "在线", idle: "空闲", degraded: "异常" }
    : { serving: "Online", idle: "Idle", degraded: "Degraded" }
  return labels[node.runtimeState as keyof typeof labels] ?? node.runtimeState ?? (language === "zh" ? "状态未知" : "Unknown")
}

function nodeSyncHelp(node: ControlNode, language: "zh" | "en"): string {
  const desired = node.revisions.desiredRevision
  const applied = node.revisions.appliedRevision
  const base = helpCopy[language].node.sync
  if (desired == null) {
    return `${base} ${language === "zh" ? "这个节点还没有期望配置版本。" : "This node has no desired revision yet."}`
  }
  if (desired === applied) {
    return `${base} ${language === "zh" ? `当前期望和已应用均为 r${desired}。` : `Desired and applied are both r${desired}.`}`
  }
  const detail = language === "zh"
    ? `当前 Control 期望 r${desired}，节点最后应用 ${applied == null ? "无" : `r${applied}`}。`
    : `Control expects r${desired}; the node last applied ${applied == null ? "none" : `r${applied}`}.`
  const recovery = isNodeOnline(node)
    ? language === "zh" ? "节点在线时通常会继续接收、验证并应用该版本。" : "While online, the node should continue receiving, validating, and applying it."
    : language === "zh" ? "节点目前离线，重新连接后才会继续同步。" : "The node is offline and must reconnect before sync can continue."
  return `${base} ${detail}${recovery}`
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
