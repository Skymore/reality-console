import { useEffect, useState, type ReactNode } from "react"
import {
  ArrowRight,
  Check,
  ChevronRight,
  CircleAlert,
  Cloud,
  Gauge,
  Globe2,
  Laptop,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  MapPin,
  Network,
  Power,
  RefreshCw,
  Route,
  Settings2,
  ShieldCheck,
  Sparkles,
  Unplug,
  Wifi,
} from "lucide-react"

import {
  beginSetup,
  cancelSetup,
  confirmSetup,
  connect,
  disconnect,
  getSnapshot,
  logout,
  probeNodes,
  refreshBundle,
  setSelection,
  type ConnectSnapshot,
  type SafeNode,
  type SetupSession,
} from "./api"

function messageOf(reason: unknown) {
  if (reason && typeof reason === "object" && "message" in reason) return String(reason.message)
  return reason instanceof Error ? reason.message : String(reason)
}

function defaultDeviceName() {
  const platform = navigator.userAgent.includes("Windows") ? "Windows PC" : "Mac"
  return `My ${platform}`
}

function formatDate(value: string | null | undefined) {
  if (!value) return "Not available"
  return new Date(value).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })
}

function App() {
  const [snapshot, setSnapshot] = useState<ConnectSnapshot | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [setupCode, setSetupCode] = useState("")
  const [setup, setSetup] = useState<SetupSession | null>(null)
  const [deviceName, setDeviceName] = useState(defaultDeviceName)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [logoutConfirm, setLogoutConfirm] = useState(false)

  async function load(silent = false) {
    if (!silent) setBusy("load")
    try {
      setSnapshot(await getSnapshot())
      setError(null)
    } catch (reason) {
      setError(messageOf(reason))
    } finally {
      setLoaded(true)
      if (!silent) setBusy(null)
    }
  }

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(true), 5_000)
    return () => window.clearInterval(timer)
  }, [])

  async function run(action: string, operation: () => Promise<ConnectSnapshot>) {
    setBusy(action)
    setError(null)
    try {
      setSnapshot(await operation())
    } catch (reason) {
      setError(messageOf(reason))
    } finally {
      setBusy(null)
    }
  }

  async function inspectSetup() {
    setBusy("inspect")
    setError(null)
    try {
      setSetup(await beginSetup(setupCode))
      setSetupCode("")
    } catch (reason) {
      setError(messageOf(reason))
    } finally {
      setBusy(null)
    }
  }

  async function abandonSetup() {
    if (setup) await cancelSetup(setup.sessionId).catch(() => false)
    setSetup(null)
  }

  async function activate() {
    if (!setup) return
    await run("activate", async () => {
      const next = await confirmSetup(setup.sessionId, deviceName.trim())
      setSetup(null)
      return next
    })
  }

  async function removeAccount() {
    setBusy("logout")
    setError(null)
    try {
      await logout()
      setSnapshot(null)
      setSettingsOpen(false)
      setLogoutConfirm(false)
    } catch (reason) {
      setError(messageOf(reason))
    } finally {
      setBusy(null)
    }
  }

  const connected = snapshot?.runtime.phase === "connected"
  const changing = snapshot?.runtime.phase === "starting" || snapshot?.runtime.phase === "stopping"
  const selectedNode = snapshot?.bundle?.nodes.find((node) => node.nodeId === snapshot.selectedNodeId) ?? null

  if (!loaded) {
    return <main className="loading"><span className="brand-mark"><Network /></span><LoaderCircle className="spin" /><p>Preparing your private network</p></main>
  }

  if (!snapshot) {
    return (
      <main className="onboarding-shell">
        <header className="topbar" data-tauri-drag-region>
          <Brand />
          <span className="privacy"><LockKeyhole size={14} /> Device-only credentials</span>
        </header>
        <div className="app-scroll">
          <section className="onboarding">
            <div className="intro">
              <div className="intro-art"><span className="ring ring-one" /><span className="ring ring-two" /><ShieldCheck size={48} /></div>
              <p className="eyebrow">Invitation only</p>
              <h1>Join your private network.</h1>
              <p>One setup code adds your account, downloads your assigned nodes, and keeps them in sync automatically.</p>
              <div className="trust-row"><span><Check /> No manual server setup</span><span><Check /> Automatic failover</span><span><Check /> End-to-end verified updates</span></div>
            </div>
            <div className="setup-panel">
              {error && <Notice message={error} />}
              {!setup ? (
                <>
                  <p className="eyebrow">Get started</p>
                  <h2>Enter your setup code</h2>
                  <p className="muted">Ask the network owner for a new Connect code. Each code works once.</p>
                  <textarea value={setupCode} onChange={(event) => setSetupCode(event.target.value)} placeholder="pn-member-v1..." spellCheck={false} autoFocus />
                  <button className="primary wide" onClick={() => void inspectSetup()} disabled={!setupCode.trim() || busy !== null}>
                    {busy === "inspect" ? <LoaderCircle className="spin" /> : <ArrowRight />} Continue
                  </button>
                </>
              ) : (
                <>
                  <span className="accepted"><Check /> Invitation verified</span>
                  <p className="eyebrow">Welcome to</p>
                  <h2>{setup.preview.displayName}</h2>
                  <div className="setup-detail"><Cloud /><div><span>Secure control service</span><strong>{new URL(setup.preview.controllerOrigin).host}</strong></div></div>
                  <label className="field"><span>Name this device</span><input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} maxLength={80} /></label>
                  <p className="expiry">This code expires {formatDate(setup.preview.expiresAt)}.</p>
                  <div className="button-row"><button className="secondary" onClick={() => void abandonSetup()}>Back</button><button className="primary" disabled={!deviceName.trim() || busy !== null} onClick={() => void activate()}>{busy === "activate" ? <LoaderCircle className="spin" /> : <ShieldCheck />} Join network</button></div>
                </>
              )}
            </div>
          </section>
        </div>
      </main>
    )
  }

  return (
    <main className={`app-shell ${connected ? "is-connected" : ""}`}>
      <header className="topbar" data-tauri-drag-region>
        <Brand />
        <div className="top-actions">
          <span className="account-pill"><span className="avatar">{snapshot.session.account?.displayName.slice(0, 1).toUpperCase()}</span>{snapshot.session.account?.displayName}</span>
          <button className="icon-button" onClick={() => setSettingsOpen(!settingsOpen)} aria-label="Settings"><Settings2 /></button>
        </div>
      </header>

      <div className="app-scroll">
        <section className="connection-stage">
          <div className="ambient ambient-one" /><div className="ambient ambient-two" />
          <div className={`connection-visual ${connected ? "active" : ""} ${changing ? "changing" : ""}`}>
            <span className="orbit orbit-one" /><span className="orbit orbit-two" /><span className="orbit orbit-three" />
            <button
              className="power-button"
              onClick={() => void run(connected ? "disconnect" : "connect", connected ? disconnect : () => connect("system"))}
              disabled={busy !== null || changing || !snapshot.bundle?.nodes.length}
            >
              {busy === "connect" || busy === "disconnect" || changing ? <LoaderCircle className="spin" /> : connected ? <Unplug /> : <Power />}
            </button>
          </div>
          <p className="eyebrow">{changing ? "Please wait" : connected ? "Protected" : "Ready"}</p>
          <h1>{changing ? (snapshot.runtime.phase === "starting" ? "Connecting..." : "Disconnecting...") : connected ? "You're connected" : "Connect when you're ready"}</h1>
          <p className="connection-copy">
            {connected
              ? `${selectedNode?.displayName ?? "Best available node"}${selectedNode?.region ? ` · ${selectedNode.region}` : ""}`
              : snapshot.bundle?.nodes.length
                ? `${snapshot.bundle.nodes.length} ${snapshot.bundle.nodes.length === 1 ? "node" : "nodes"} available · automatic selection`
                : "Your account has no available nodes yet."}
          </p>
          {error && <Notice message={error} />}
        </section>

        <section className="status-strip">
          <StatusItem icon={<Route />} label="Route" value={selectedNode ? (selectedNode.endpointMode === "relay" ? "Managed relay" : "Direct") : "Automatic"} />
          <StatusItem icon={<Globe2 />} label="System access" value={connected && snapshot.runtime.mode === "system" ? "Enabled" : "Off"} />
          <StatusItem icon={<Gauge />} label="Bundle" value={`Generation ${snapshot.bundle?.generation ?? 0}`} />
        </section>

        <section className="content-grid">
        <div className="nodes-card">
          <div className="section-heading">
            <div><p className="eyebrow">Available routes</p><h2>Network nodes</h2></div>
            <button className="text-button" disabled={busy !== null} onClick={() => void run("refresh", async () => { await refreshBundle(); return probeNodes() })}><RefreshCw className={busy === "refresh" ? "spin" : ""} /> Sync now</button>
          </div>
          <button className={`node-row auto ${snapshot.selectionMode.kind === "automatic" ? "selected" : ""}`} onClick={() => void run("selection", () => setSelection({ kind: "automatic" }))} disabled={busy !== null}>
            <span className="node-icon auto-icon"><Sparkles /></span>
            <span className="node-copy"><strong>Automatic</strong><small>Use the best healthy route and switch when needed</small></span>
            {snapshot.selectionMode.kind === "automatic" ? <span className="selected-mark"><Check /></span> : <ChevronRight />}
          </button>
          {snapshot.bundle?.nodes.map((node) => (
            <NodeRow key={node.nodeId} node={node} selected={snapshot.selectionMode.kind === "manual" && snapshot.selectionMode.nodes === node.nodeId} active={snapshot.selectedNodeId === node.nodeId} onSelect={() => void run("selection", () => setSelection({ kind: "manual", nodes: node.nodeId }))} disabled={busy !== null} />
          ))}
          {!snapshot.bundle?.nodes.length && <div className="empty"><CircleAlert /><strong>No nodes assigned</strong><span>Ask the network owner to assign at least one active node, then sync again.</span></div>}
        </div>

        <aside className="details-card">
          <p className="eyebrow">Account</p>
          <h2>{snapshot.session.account?.displayName}</h2>
          <dl>
            <div><dt>Device</dt><dd><Laptop /> {snapshot.session.binding?.deviceId.slice(0, 8)}</dd></div>
            <div><dt>Offline access until</dt><dd>{formatDate(snapshot.bundle?.offlineExpiresAt)}</dd></div>
            <div><dt>Next sync</dt><dd>{formatDate(snapshot.bundle?.refreshAfter)}</dd></div>
          </dl>
          <div className="security-note"><ShieldCheck /><p><strong>Verified node updates</strong><span>Node credentials are encrypted for this device and never shown in the app.</span></p></div>
        </aside>
        </section>
      </div>

      {settingsOpen && (
        <div className="modal-backdrop" onMouseDown={() => setSettingsOpen(false)}>
          <section className="modal" onMouseDown={(event) => event.stopPropagation()}>
            <div className="section-heading"><div><p className="eyebrow">This device</p><h2>Settings</h2></div><button className="icon-button" onClick={() => setSettingsOpen(false)}>×</button></div>
            <div className="setting-row"><div><strong>System-wide access</strong><span>When connected, supported apps use this network automatically.</span></div><span className="badge">Default</span></div>
            <div className="setting-row"><div><strong>Local proxy</strong><span>For advanced apps that need a manual endpoint.</span></div><code>{snapshot.runtime.endpoints.socks}</code></div>
            <div className="logout-box">
              {!logoutConfirm ? <button className="logout-button" onClick={() => setLogoutConfirm(true)}><LogOut /> Remove account from this device</button> : <><p>This disconnects and removes local keys and cached nodes. Your network account is not deleted.</p><div className="button-row"><button className="secondary" onClick={() => setLogoutConfirm(false)}>Cancel</button><button className="danger" onClick={() => void removeAccount()} disabled={busy !== null}>{busy === "logout" ? <LoaderCircle className="spin" /> : null}Remove account</button></div></>}
            </div>
          </section>
        </div>
      )}
    </main>
  )
}

function Brand() {
  return <div className="brand" data-tauri-drag-region><span className="brand-mark"><Network /></span><div data-tauri-drag-region><strong>Private Network</strong><span>Connect</span></div></div>
}

function Notice({ message }: { message: string }) {
  return <div className="notice"><CircleAlert /><span>{message}</span></div>
}

function StatusItem({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return <div className="status-item"><span>{icon}</span><div><small>{label}</small><strong>{value}</strong></div></div>
}

function NodeRow({ node, selected, active, onSelect, disabled }: { node: SafeNode; selected: boolean; active: boolean; onSelect: () => void; disabled: boolean }) {
  return <button className={`node-row ${selected ? "selected" : ""}`} onClick={onSelect} disabled={disabled}>
    <span className="node-icon">{node.endpointMode === "relay" ? <Cloud /> : <Wifi />}</span>
    <span className="node-copy"><strong>{node.displayName}{active && <em>Active</em>}</strong><small><MapPin /> {node.region ?? "Private node"} · {node.endpointMode === "relay" ? "managed relay" : "direct route"}</small></span>
    {selected ? <span className="selected-mark"><Check /></span> : <ChevronRight />}
  </button>
}

export default App
