import { useEffect, useState, type ReactNode } from "react"
import {
  ArrowRight,
  Check,
  ChevronRight,
  CircleAlert,
  Cloud,
  Gauge,
  Globe2,
  Languages,
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
import { connectCopy, initialLocale, type Locale } from "./locale"

function messageOf(reason: unknown) {
  if (reason && typeof reason === "object" && "message" in reason) return String(reason.message)
  return reason instanceof Error ? reason.message : String(reason)
}

function defaultDeviceName(language: Locale) {
  const device = connectCopy[language].device
  return navigator.userAgent.includes("Windows") ? device.windows : device.mac
}

function formatDate(value: string | null | undefined, language: Locale) {
  if (!value) return connectCopy[language].notAvailable
  return new Date(value).toLocaleString(language === "zh" ? "zh-CN" : "en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })
}

function App() {
  const [language, setLanguage] = useState<Locale>(initialLocale)
  const [snapshot, setSnapshot] = useState<ConnectSnapshot | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [setupCode, setSetupCode] = useState("")
  const [setup, setSetup] = useState<SetupSession | null>(null)
  const [deviceName, setDeviceName] = useState<string>(() => defaultDeviceName(language))
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [logoutConfirm, setLogoutConfirm] = useState(false)
  const t = connectCopy[language]

  function toggleLanguage() {
    const next = language === "zh" ? "en" : "zh"
    localStorage.setItem("locale", next)
    setLanguage(next)
  }

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
    return <main className="loading"><span className="brand-mark"><Network /></span><LoaderCircle className="spin" /><p>{t.preparing}</p></main>
  }

  if (!snapshot) {
    return (
      <main className="onboarding-shell">
        <header className="topbar" data-tauri-drag-region>
          <Brand language={language} />
          <div className="top-actions">
            <span className="privacy"><LockKeyhole size={14} /> {t.deviceCredentials}</span>
            <LanguageButton language={language} label={t.switchLanguage} onClick={toggleLanguage} />
          </div>
        </header>
        <div className="app-scroll">
          <section className="onboarding">
            <div className="intro">
              <div className="intro-art"><span className="ring ring-one" /><span className="ring ring-two" /><ShieldCheck size={48} /></div>
              <p className="eyebrow">{t.onboarding.invitationOnly}</p>
              <h1>{t.onboarding.title}</h1>
              <p>{t.onboarding.description}</p>
              <div className="trust-row"><span><Check /> {t.onboarding.noManualSetup}</span><span><Check /> {t.onboarding.automaticFailover}</span><span><Check /> {t.onboarding.verifiedUpdates}</span></div>
            </div>
            <div className="setup-panel">
              {error && <Notice message={error} />}
              {!setup ? (
                <>
                  <p className="eyebrow">{t.onboarding.getStarted}</p>
                  <h2>{t.onboarding.enterCode}</h2>
                  <p className="muted">{t.onboarding.codeHint}</p>
                  <textarea value={setupCode} onChange={(event) => setSetupCode(event.target.value)} placeholder="pn-member-v1..." spellCheck={false} autoFocus />
                  <button className="primary wide" onClick={() => void inspectSetup()} disabled={!setupCode.trim() || busy !== null}>
                    {busy === "inspect" ? <LoaderCircle className="spin" /> : <ArrowRight />} {t.onboarding.continue}
                  </button>
                </>
              ) : (
                <>
                  <span className="accepted"><Check /> {t.onboarding.verified}</span>
                  <p className="eyebrow">{t.onboarding.welcome}</p>
                  <h2>{setup.preview.displayName}</h2>
                  <div className="setup-detail"><Cloud /><div><span>{t.onboarding.controlService}</span><strong>{new URL(setup.preview.controllerOrigin).host}</strong></div></div>
                  <label className="field"><span>{t.onboarding.deviceName}</span><input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} maxLength={80} /></label>
                  <p className="expiry">{t.onboarding.expires(formatDate(setup.preview.expiresAt, language))}</p>
                  <div className="button-row"><button className="secondary" onClick={() => void abandonSetup()}>{t.onboarding.back}</button><button className="primary" disabled={!deviceName.trim() || busy !== null} onClick={() => void activate()}>{busy === "activate" ? <LoaderCircle className="spin" /> : <ShieldCheck />} {t.onboarding.join}</button></div>
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
        <Brand language={language} />
        <div className="top-actions">
          <span className="account-pill"><span className="avatar">{snapshot.session.account?.displayName.slice(0, 1).toUpperCase()}</span>{snapshot.session.account?.displayName}</span>
          <LanguageButton language={language} label={t.switchLanguage} onClick={toggleLanguage} />
          <button className="icon-button" onClick={() => setSettingsOpen(!settingsOpen)} aria-label={t.settings.open} title={t.settings.open}><Settings2 /></button>
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
          <p className="eyebrow">{changing ? t.connection.pleaseWait : connected ? t.connection.protected : t.connection.ready}</p>
          <h1>{changing ? (snapshot.runtime.phase === "starting" ? t.connection.connecting : t.connection.disconnecting) : connected ? t.connection.connected : t.connection.prompt}</h1>
          <p className="connection-copy">
            {connected
              ? `${selectedNode?.displayName ?? t.connection.bestNode}${selectedNode?.region ? ` · ${selectedNode.region}` : ""}`
              : snapshot.bundle?.nodes.length
                ? t.connection.availableNodes(snapshot.bundle.nodes.length)
                : t.connection.noNodes}
          </p>
          {error && <Notice message={error} />}
        </section>

        <section className="status-strip">
          <StatusItem icon={<Route />} label={t.connection.route} value={selectedNode ? (selectedNode.endpointMode === "relay" ? t.connection.managedRelay : t.connection.direct) : t.connection.automatic} />
          <StatusItem icon={<Globe2 />} label={t.connection.systemAccess} value={connected && snapshot.runtime.mode === "system" ? t.connection.enabled : t.connection.off} />
          <StatusItem icon={<Gauge />} label={t.connection.bundle} value={t.connection.generation(snapshot.bundle?.generation ?? 0)} />
        </section>

        <section className="content-grid">
        <div className="nodes-card">
          <div className="section-heading">
            <div><p className="eyebrow">{t.nodes.eyebrow}</p><h2>{t.nodes.title}</h2></div>
            <button className="text-button" disabled={busy !== null} onClick={() => void run("refresh", async () => { await refreshBundle(); return probeNodes() })}><RefreshCw className={busy === "refresh" ? "spin" : ""} /> {t.nodes.sync}</button>
          </div>
          <button className={`node-row auto ${snapshot.selectionMode.kind === "automatic" ? "selected" : ""}`} onClick={() => void run("selection", () => setSelection({ kind: "automatic" }))} disabled={busy !== null}>
            <span className="node-icon auto-icon"><Sparkles /></span>
            <span className="node-copy"><strong>{t.nodes.automatic}</strong><small>{t.nodes.automaticDescription}</small></span>
            {snapshot.selectionMode.kind === "automatic" ? <span className="selected-mark"><Check /></span> : <ChevronRight />}
          </button>
          {snapshot.bundle?.nodes.map((node) => (
            <NodeRow key={node.nodeId} node={node} selected={snapshot.selectionMode.kind === "manual" && snapshot.selectionMode.nodes === node.nodeId} active={snapshot.selectedNodeId === node.nodeId} onSelect={() => void run("selection", () => setSelection({ kind: "manual", nodes: node.nodeId }))} disabled={busy !== null} language={language} />
          ))}
          {!snapshot.bundle?.nodes.length && <div className="empty"><CircleAlert /><strong>{t.nodes.none}</strong><span>{t.nodes.noneDescription}</span></div>}
        </div>

        <aside className="details-card">
          <p className="eyebrow">{t.account.eyebrow}</p>
          <h2>{snapshot.session.account?.displayName}</h2>
          <dl>
            <div><dt>{t.account.device}</dt><dd><Laptop /> {snapshot.session.binding?.deviceId.slice(0, 8)}</dd></div>
            <div><dt>{t.account.offlineUntil}</dt><dd>{formatDate(snapshot.bundle?.offlineExpiresAt, language)}</dd></div>
            <div><dt>{t.account.nextSync}</dt><dd>{formatDate(snapshot.bundle?.refreshAfter, language)}</dd></div>
          </dl>
          <div className="security-note"><ShieldCheck /><p><strong>{t.account.verifiedUpdates}</strong><span>{t.account.verifiedDescription}</span></p></div>
        </aside>
        </section>
      </div>

      {settingsOpen && (
        <div className="modal-backdrop" onMouseDown={() => setSettingsOpen(false)}>
          <section className="modal" onMouseDown={(event) => event.stopPropagation()}>
            <div className="section-heading"><div><p className="eyebrow">{t.settings.thisDevice}</p><h2>{t.settings.title}</h2></div><button className="icon-button" onClick={() => setSettingsOpen(false)}>×</button></div>
            <div className="setting-row"><div><strong>{t.settings.systemWide}</strong><span>{t.settings.systemWideDescription}</span></div><span className="badge">{t.settings.default}</span></div>
            <div className="setting-row"><div><strong>{t.settings.localProxy}</strong><span>{t.settings.localProxyDescription}</span></div><code>{snapshot.runtime.endpoints.socks}</code></div>
            <div className="logout-box">
              {!logoutConfirm ? <button className="logout-button" onClick={() => setLogoutConfirm(true)}><LogOut /> {t.settings.remove}</button> : <><p>{t.settings.removeDescription}</p><div className="button-row"><button className="secondary" onClick={() => setLogoutConfirm(false)}>{t.settings.cancel}</button><button className="danger" onClick={() => void removeAccount()} disabled={busy !== null}>{busy === "logout" ? <LoaderCircle className="spin" /> : null}{t.settings.confirmRemove}</button></div></>}
            </div>
          </section>
        </div>
      )}
    </main>
  )
}

function Brand({ language }: { language: Locale }) {
  const t = connectCopy[language]
  return <div className="brand" data-tauri-drag-region><span className="brand-mark"><Network /></span><div data-tauri-drag-region><strong>{t.brand}</strong><span>{t.product}</span></div></div>
}

function LanguageButton({ language, label, onClick }: { language: Locale; label: string; onClick: () => void }) {
  return <button className="icon-button language-button" onClick={onClick} aria-label={label} title={label}><Languages /><span>{language === "zh" ? "EN" : "中文"}</span></button>
}

function Notice({ message }: { message: string }) {
  return <div className="notice"><CircleAlert /><span>{message}</span></div>
}

function StatusItem({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return <div className="status-item"><span>{icon}</span><div><small>{label}</small><strong>{value}</strong></div></div>
}

function NodeRow({ node, selected, active, onSelect, disabled, language }: { node: SafeNode; selected: boolean; active: boolean; onSelect: () => void; disabled: boolean; language: Locale }) {
  const t = connectCopy[language].nodes
  return <button className={`node-row ${selected ? "selected" : ""}`} onClick={onSelect} disabled={disabled}>
    <span className="node-icon">{node.endpointMode === "relay" ? <Cloud /> : <Wifi />}</span>
    <span className="node-copy"><strong>{node.displayName}{active && <em>{t.active}</em>}</strong><small><MapPin /> {node.region ?? t.privateNode} · {node.endpointMode === "relay" ? t.relay : t.direct}</small></span>
    {selected ? <span className="selected-mark"><Check /></span> : <ChevronRight />}
  </button>
}

export default App
