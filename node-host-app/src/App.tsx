import { useEffect, useState, type ReactNode } from "react"
import {
  Activity,
  ArrowRight,
  Check,
  CircleAlert,
  Gauge,
  Globe2,
  Link2,
  LoaderCircle,
  Pause,
  Play,
  RefreshCw,
  Router,
  Server,
  Settings2,
  ShieldCheck,
  Trash2,
} from "lucide-react"

import {
  beginSetup,
  cancelSetup,
  clearManualEndpoint,
  configureManualEndpoint,
  confirmSetup,
  defaultPolicy,
  getPackageStatus,
  getServiceStatus,
  pauseProvider,
  resumeProvider,
  unpair,
  updatePolicy,
  type ProviderPolicy,
  type SetupSession,
  type SystemPackageStatus,
  type SystemServiceStatus,
} from "./api"

const GB = 1024 ** 3

function messageOf(reason: unknown) {
  return reason instanceof Error ? reason.message : String(reason)
}

function formatBytes(value: number | null | undefined) {
  if (value == null) return "Unlimited"
  if (value < GB) return `${(value / 1024 ** 2).toFixed(0)} MB`
  return `${(value / GB).toFixed(value >= 10 * GB ? 0 : 1)} GB`
}

function statusLabel(status: SystemServiceStatus | null) {
  if (!status || status.phase === "unpaired") return "Ready to pair"
  if (status.setupPhase === "ready") return "Online"
  if (status.setupPhase === "paused") return "Paused"
  if (status.phase === "needsAttention") return "Needs attention"
  return "Connecting"
}

function App() {
  const [pack, setPack] = useState<SystemPackageStatus | null>(null)
  const [status, setStatus] = useState<SystemServiceStatus | null>(null)
  const [serviceError, setServiceError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [setupCode, setSetupCode] = useState("")
  const [setup, setSetup] = useState<SetupSession | null>(null)
  const [policy, setPolicy] = useState<ProviderPolicy>(defaultPolicy)
  const [acceptOwner, setAcceptOwner] = useState(false)
  const [acceptExit, setAcceptExit] = useState(false)
  const [acceptRelay, setAcceptRelay] = useState(true)
  const [acceptMapping, setAcceptMapping] = useState(false)
  const [manualOpen, setManualOpen] = useState(false)
  const [manualAddress, setManualAddress] = useState("")
  const [manualPort, setManualPort] = useState("443")
  const [confirmNodeId, setConfirmNodeId] = useState("")

  async function refresh(silent = false) {
    if (!silent) setBusy("refresh")
    setError(null)
    const packageResult = await getPackageStatus().catch(() => null)
    setPack(packageResult)
    try {
      const next = await getServiceStatus()
      setStatus(next)
      setServiceError(null)
      if (next.providerPolicy) setPolicy(next.providerPolicy.policy)
    } catch (reason) {
      setStatus(null)
      setServiceError(messageOf(reason))
    } finally {
      if (!silent) setBusy(null)
    }
  }

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(true), 10_000)
    return () => window.clearInterval(timer)
  }, [])

  async function run(action: string, operation: () => Promise<void>) {
    setBusy(action)
    setError(null)
    try {
      await operation()
    } catch (reason) {
      setError(messageOf(reason))
    } finally {
      setBusy(null)
    }
  }

  async function inspectCode() {
    await run("inspect", async () => {
      const next = await beginSetup(setupCode)
      setSetup(next)
      setSetupCode("")
    })
  }

  async function abandonSetup() {
    if (setup) await cancelSetup(setup.sessionId).catch(() => false)
    setSetup(null)
  }

  async function finishSetup() {
    if (!setup) return
    await run("pair", async () => {
      const next = await confirmSetup(setup.sessionId, {
        authority: { acceptHostOwner: acceptOwner, acceptExitIp: acceptExit },
        sharing: { acceptRouterMapping: acceptMapping, acceptRelay },
        providerPolicy: policy,
      })
      setStatus(next)
      setSetup(null)
      setServiceError(null)
    })
  }

  async function togglePause() {
    const paused = status?.providerPolicy?.policy.paused ?? false
    await run("pause", async () => {
      const next = paused ? await resumeProvider() : await pauseProvider()
      setStatus((current) => (current ? { ...current, providerPolicy: next } : current))
      setPolicy(next.policy)
    })
  }

  async function savePolicy() {
    await run("policy", async () => {
      const next = await updatePolicy(policy)
      setStatus((current) => (current ? { ...current, providerPolicy: next } : current))
      setPolicy(next.policy)
    })
  }

  async function saveEndpoint() {
    await run("endpoint", async () => {
      await configureManualEndpoint({
        address: manualAddress.trim(),
        publicPort: Number(manualPort),
        forwardedLocalPort: 10443,
        ttlSeconds: 7 * 24 * 60 * 60,
      })
      setManualOpen(false)
      await refresh(true)
    })
  }

  const installed = pack && Object.entries(pack).every(([key, value]) => key === "platform" || value === "present")
  const paired = Boolean(status?.nodeId)
  const paused = status?.providerPolicy?.policy.paused ?? false
  const ready = status?.setupPhase === "ready"

  return (
    <main className="shell">
      <header className="topbar" data-tauri-drag-region>
        <div className="brand" data-tauri-drag-region>
          <span className="brand-mark"><Router size={19} /></span>
          <div data-tauri-drag-region>
            <strong>Private Network</strong>
            <span>Node Host</span>
          </div>
        </div>
        <button className="icon-button" onClick={() => void refresh()} disabled={busy === "refresh"} aria-label="Refresh">
          <RefreshCw size={18} className={busy === "refresh" ? "spin" : ""} />
        </button>
      </header>

      <section className="hero">
        <div>
          <p className="eyebrow">Share this Mac safely</p>
          <h1>{paired ? statusLabel(status) : "Add this Mac as a node"}</h1>
          <p className="lede">
            {paired
              ? "Your limits stay local. Pause sharing at any time without waiting for the network owner."
              : "Paste one setup code from the network owner. No router configuration or terminal commands required."}
          </p>
        </div>
        <div className={`status-orbit ${ready ? "online" : paused ? "paused" : ""}`}>
          <span className="pulse" />
          <Server size={30} />
          <strong>{paired ? statusLabel(status) : installed ? "Ready" : "Install required"}</strong>
        </div>
      </section>

      {(error || (installed && serviceError)) && (
        <div className="notice error"><CircleAlert size={18} /><span>{error ?? serviceError}</span></div>
      )}

      {!installed && pack && (
        <div className="notice warn">
          <CircleAlert size={18} />
          <span>The background service is incomplete. Reinstall the signed Private Network Node package, then refresh.</span>
        </div>
      )}

      {!paired ? (
        <section className="setup-card">
          <div className="step-number">01</div>
          {!setup ? (
            <div className="setup-content">
              <div className="section-heading">
                <div><p className="eyebrow">One-time setup</p><h2>Paste your node code</h2></div>
                <ShieldCheck size={28} />
              </div>
              <textarea
                value={setupCode}
                onChange={(event) => setSetupCode(event.target.value)}
                placeholder="pnnode1..."
                spellCheck={false}
                autoFocus
              />
              <p className="hint">The secret is inspected and retained only by the native app process. It is never saved by this screen.</p>
              <button className="primary" onClick={() => void inspectCode()} disabled={!installed || !setupCode.trim() || busy !== null}>
                {busy === "inspect" ? <LoaderCircle className="spin" size={18} /> : <ArrowRight size={18} />}
                Review setup
              </button>
            </div>
          ) : (
            <div className="setup-content">
              <div className="section-heading">
                <div><p className="eyebrow">Confirm network</p><h2>{setup.preview.displayName}</h2></div>
                <span className="verified"><Check size={15} /> Code accepted</span>
              </div>
              <div className="preview-grid">
                <div><span>Control service</span><strong>{new URL(setup.preview.controllerOrigin).host}</strong></div>
                <div><span>Expires</span><strong>{new Date(setup.preview.expiresAt).toLocaleString()}</strong></div>
              </div>
              <div className="consents">
                <label><input type="checkbox" checked={acceptOwner} onChange={(e) => setAcceptOwner(e.target.checked)} /><span><strong>I own or control this Mac</strong><small>I am allowed to run a background network service here.</small></span></label>
                <label><input type="checkbox" checked={acceptExit} onChange={(e) => setAcceptExit(e.target.checked)} /><span><strong>I understand traffic exits through this connection</strong><small>Friends may appear online from this network's public IP.</small></span></label>
                <label><input type="checkbox" checked={acceptRelay} onChange={(e) => setAcceptRelay(e.target.checked)} /><span><strong>Use the managed relay when direct access is unavailable</strong><small>Recommended for apartment and carrier-managed networks.</small></span></label>
                <label><input type="checkbox" checked={acceptMapping} onChange={(e) => setAcceptMapping(e.target.checked)} /><span><strong>Try automatic router mapping</strong><small>Optional. The node falls back safely if the router refuses it.</small></span></label>
              </div>
              <PolicyEditor policy={policy} onChange={setPolicy} compact />
              <div className="button-row">
                <button className="secondary" onClick={() => void abandonSetup()}>Cancel</button>
                <button className="primary" onClick={() => void finishSetup()} disabled={!acceptOwner || !acceptExit || busy !== null}>
                  {busy === "pair" ? <LoaderCircle className="spin" size={18} /> : <ShieldCheck size={18} />}
                  Pair and start
                </button>
              </div>
            </div>
          )}
        </section>
      ) : (
        <div className="dashboard-grid">
          <section className="card summary-card">
            <div className="section-heading">
              <div><p className="eyebrow">Live node</p><h2>{statusLabel(status)}</h2></div>
              <button className={paused ? "primary small" : "secondary small"} onClick={() => void togglePause()} disabled={busy !== null}>
                {paused ? <Play size={16} /> : <Pause size={16} />}{paused ? "Resume" : "Pause"}
              </button>
            </div>
            <div className="metric-grid">
              <Metric icon={<Activity />} label="Runtime" value={status?.runtimeState ?? "Starting"} />
              <Metric icon={<Globe2 />} label="Public path" value={status?.relayVerification === "verified" ? "Relay verified" : status?.directVerification === "verified" ? "Direct verified" : "Verifying"} />
              <Metric icon={<Gauge />} label="This month" value={formatBytes(status?.providerPolicy?.monthUsage.observedBytes)} />
              <Metric icon={<Link2 />} label="Revision" value={status?.appliedRevision ? `#${status.appliedRevision}` : "Pending"} />
            </div>
            <div className="node-id"><span>Node ID</span><code>{status?.nodeId}</code></div>
          </section>

          <section className="card">
            <div className="section-heading">
              <div><p className="eyebrow">Owner controls</p><h2>Sharing limits</h2></div>
              <Settings2 size={24} />
            </div>
            <PolicyEditor policy={policy} onChange={setPolicy} />
            <button className="primary" onClick={() => void savePolicy()} disabled={busy !== null}>
              {busy === "policy" ? <LoaderCircle className="spin" size={18} /> : <Check size={18} />} Save limits
            </button>
          </section>

          <section className="card">
            <div className="section-heading">
              <div><p className="eyebrow">Reachability</p><h2>Advanced endpoint</h2></div>
              <Globe2 size={24} />
            </div>
            <p className="body-copy">Automatic relay is the default. Add a manual public endpoint only when you already manage port forwarding or a static tunnel.</p>
            {status?.providerPolicy?.manualEndpoint.configured && (
              <div className="endpoint-state"><Check size={17} /><span>Manual endpoint configured</span><button onClick={() => void run("clear", async () => { await clearManualEndpoint(); await refresh(true) })}>Remove</button></div>
            )}
            {!manualOpen ? (
              <button className="secondary" onClick={() => setManualOpen(true)}>Configure endpoint</button>
            ) : (
              <div className="endpoint-form">
                <label><span>Public hostname or IP</span><input value={manualAddress} onChange={(e) => setManualAddress(e.target.value)} placeholder="node.example.com" /></label>
                <label><span>Public port</span><input type="number" value={manualPort} onChange={(e) => setManualPort(e.target.value)} min="1" max="65535" /></label>
                <div className="button-row"><button className="secondary" onClick={() => setManualOpen(false)}>Cancel</button><button className="primary" onClick={() => void saveEndpoint()} disabled={!manualAddress.trim()}>Save endpoint</button></div>
              </div>
            )}
          </section>

          <section className="card danger-card">
            <div className="section-heading"><div><p className="eyebrow">Local ownership</p><h2>Remove this node</h2></div><Trash2 size={24} /></div>
            <p className="body-copy">Stops all data paths and removes this Mac's node identity. The installed app remains available for pairing again.</p>
            <label><span>Type the full node ID to confirm</span><input value={confirmNodeId} onChange={(e) => setConfirmNodeId(e.target.value)} placeholder={status?.nodeId ?? ""} /></label>
            <button className="danger" disabled={confirmNodeId !== status?.nodeId || busy !== null} onClick={() => void run("unpair", async () => { const next = await unpair(confirmNodeId); setStatus(next); setConfirmNodeId("") })}>
              <Trash2 size={17} /> Unpair this Mac
            </button>
          </section>
        </div>
      )}
    </main>
  )
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return <div className="metric"><span className="metric-icon">{icon}</span><div><span>{label}</span><strong>{value}</strong></div></div>
}

function PolicyEditor({ policy, onChange, compact = false }: { policy: ProviderPolicy; onChange: (value: ProviderPolicy) => void; compact?: boolean }) {
  const capGb = policy.monthlyTransferCapBytes == null ? "" : String(Math.round(policy.monthlyTransferCapBytes / GB))
  const bandwidthMbps = policy.bandwidthLimitBps == null ? "" : String(Math.round(policy.bandwidthLimitBps / 1_000_000))
  return (
    <div className={compact ? "policy compact" : "policy"}>
      <label><span>Monthly transfer</span><div className="unit-input"><input type="number" min="1" value={capGb} placeholder="Unlimited" onChange={(e) => onChange({ ...policy, monthlyTransferCapBytes: e.target.value ? Number(e.target.value) * GB : null })} /><b>GB</b></div></label>
      <label><span>Bandwidth limit</span><div className="unit-input"><input type="number" min="1" value={bandwidthMbps} placeholder="Unlimited" onChange={(e) => onChange({ ...policy, bandwidthLimitBps: e.target.value ? Number(e.target.value) * 1_000_000 : null })} /><b>Mbps</b></div></label>
      <label><span>Concurrent sessions</span><div className="unit-input"><input type="number" min="1" max="4096" value={policy.maxConcurrentSessions} onChange={(e) => onChange({ ...policy, maxConcurrentSessions: Number(e.target.value) })} /><b>max</b></div></label>
    </div>
  )
}

export default App
