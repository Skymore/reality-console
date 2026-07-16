import { useEffect, useState, type ReactNode } from "react"
import {
  Activity,
  ArrowRight,
  Check,
  CircleAlert,
  Gauge,
  Globe2,
  Languages,
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
import { initialLocale, nodeHostCopy, type Locale } from "./locale"

const GB = 1024 ** 3

function messageOf(reason: unknown) {
  return reason instanceof Error ? reason.message : String(reason)
}

function formatBytes(value: number | null | undefined, language: Locale) {
  if (value == null) return nodeHostCopy[language].policy.unlimited
  if (value < GB) return `${(value / 1024 ** 2).toFixed(0)} MB`
  return `${(value / GB).toFixed(value >= 10 * GB ? 0 : 1)} GB`
}

function statusLabel(status: SystemServiceStatus | null, language: Locale) {
  const labels = nodeHostCopy[language].status
  if (!status || status.phase === "unpaired") return labels.readyToPair
  if (status.setupPhase === "ready") return labels.online
  if (status.setupPhase === "paused") return labels.paused
  if (status.phase === "needsAttention") return labels.needsAttention
  return labels.connecting
}

function runtimeLabel(value: string | null | undefined, language: Locale) {
  if (!value) return nodeHostCopy[language].dashboard.starting
  if (language === "en") return value
  const labels: Record<string, string> = {
    serving: "运行中",
    idle: "空闲",
    starting: "启动中",
    stopped: "已停止",
    degraded: "性能受限",
    failed: "运行失败",
  }
  return labels[value] ?? value
}

function App() {
  const [language, setLanguage] = useState<Locale>(initialLocale)
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
  const t = nodeHostCopy[language]

  function toggleLanguage() {
    const next = language === "zh" ? "en" : "zh"
    localStorage.setItem("locale", next)
    setLanguage(next)
  }

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
            <strong>{t.brand}</strong>
            <span>{t.product}</span>
          </div>
        </div>
        <div className="top-actions">
          <button className="icon-button language-button" onClick={toggleLanguage} aria-label={t.switchLanguage} title={t.switchLanguage}>
            <Languages size={17} /><span>{language === "zh" ? "EN" : "中文"}</span>
          </button>
          <button className="icon-button" onClick={() => void refresh()} disabled={busy === "refresh"} aria-label={t.refresh} title={t.refresh}>
            <RefreshCw size={18} className={busy === "refresh" ? "spin" : ""} />
          </button>
        </div>
      </header>

      <div className="shell-scroll">
        <section className="hero">
        <div>
          <p className="eyebrow">{t.shareSafely}</p>
          <h1>{paired ? statusLabel(status, language) : t.addNode}</h1>
          <p className="lede">
            {paired
              ? t.pairedDescription
              : t.unpairedDescription}
          </p>
        </div>
        <div className={`status-orbit ${ready ? "online" : paused ? "paused" : ""}`}>
          <span className="pulse" />
          <Server size={30} />
          <strong>{paired ? statusLabel(status, language) : installed ? t.ready : t.installRequired}</strong>
        </div>
        </section>

        {(error || (installed && serviceError)) && (
          <div className="notice error"><CircleAlert size={18} /><span>{error ?? serviceError}</span></div>
        )}

        {!installed && pack && (
          <div className="notice warn">
            <CircleAlert size={18} />
            <span>{t.backgroundIncomplete}</span>
          </div>
        )}

        {!paired ? (
        <section className="setup-card">
          <div className="step-number">01</div>
          {!setup ? (
            <div className="setup-content">
              <div className="section-heading">
                <div><p className="eyebrow">{t.setup.oneTime}</p><h2>{t.setup.pasteCode}</h2></div>
                <ShieldCheck size={28} />
              </div>
              <textarea
                value={setupCode}
                onChange={(event) => setSetupCode(event.target.value)}
                placeholder="pnnode1..."
                spellCheck={false}
                autoFocus
              />
              <p className="hint">{t.setup.secretHint}</p>
              <button className="primary" onClick={() => void inspectCode()} disabled={!installed || !setupCode.trim() || busy !== null}>
                {busy === "inspect" ? <LoaderCircle className="spin" size={18} /> : <ArrowRight size={18} />}
                {t.setup.review}
              </button>
            </div>
          ) : (
            <div className="setup-content">
              <div className="section-heading">
                <div><p className="eyebrow">{t.setup.confirmNetwork}</p><h2>{setup.preview.displayName}</h2></div>
                <span className="verified"><Check size={15} /> {t.setup.codeAccepted}</span>
              </div>
              <div className="preview-grid">
                <div><span>{t.setup.controlService}</span><strong>{new URL(setup.preview.controllerOrigin).host}</strong></div>
                <div><span>{t.setup.expires}</span><strong>{new Date(setup.preview.expiresAt).toLocaleString(language === "zh" ? "zh-CN" : "en-US")}</strong></div>
              </div>
              <div className="consents">
                <label><input type="checkbox" checked={acceptOwner} onChange={(e) => setAcceptOwner(e.target.checked)} /><span><strong>{t.setup.ownTitle}</strong><small>{t.setup.ownDetail}</small></span></label>
                <label><input type="checkbox" checked={acceptExit} onChange={(e) => setAcceptExit(e.target.checked)} /><span><strong>{t.setup.exitTitle}</strong><small>{t.setup.exitDetail}</small></span></label>
                <label><input type="checkbox" checked={acceptRelay} onChange={(e) => setAcceptRelay(e.target.checked)} /><span><strong>{t.setup.relayTitle}</strong><small>{t.setup.relayDetail}</small></span></label>
                <label><input type="checkbox" checked={acceptMapping} onChange={(e) => setAcceptMapping(e.target.checked)} /><span><strong>{t.setup.mappingTitle}</strong><small>{t.setup.mappingDetail}</small></span></label>
              </div>
              <PolicyEditor policy={policy} onChange={setPolicy} language={language} compact />
              <div className="button-row">
                <button className="secondary" onClick={() => void abandonSetup()}>{t.setup.cancel}</button>
                <button className="primary" onClick={() => void finishSetup()} disabled={!acceptOwner || !acceptExit || busy !== null}>
                  {busy === "pair" ? <LoaderCircle className="spin" size={18} /> : <ShieldCheck size={18} />}
                  {t.setup.pair}
                </button>
              </div>
            </div>
          )}
        </section>
        ) : (
        <div className="dashboard-grid">
          <section className="card summary-card">
            <div className="section-heading">
              <div><p className="eyebrow">{t.dashboard.liveNode}</p><h2>{statusLabel(status, language)}</h2></div>
              <button className={paused ? "primary small" : "secondary small"} onClick={() => void togglePause()} disabled={busy !== null}>
                {paused ? <Play size={16} /> : <Pause size={16} />}{paused ? t.dashboard.resume : t.dashboard.pause}
              </button>
            </div>
            <div className="metric-grid">
              <Metric icon={<Activity />} label={t.dashboard.runtime} value={runtimeLabel(status?.runtimeState, language)} />
              <Metric icon={<Globe2 />} label={t.dashboard.publicPath} value={status?.relayVerification === "verified" ? t.dashboard.relayVerified : status?.directVerification === "verified" ? t.dashboard.directVerified : t.dashboard.verifying} />
              <Metric icon={<Gauge />} label={t.dashboard.thisMonth} value={formatBytes(status?.providerPolicy?.monthUsage.observedBytes, language)} />
              <Metric icon={<Link2 />} label={t.dashboard.revision} value={status?.appliedRevision ? `#${status.appliedRevision}` : t.dashboard.pending} />
            </div>
            <div className="node-id"><span>{t.dashboard.nodeId}</span><code>{status?.nodeId}</code></div>
          </section>

          <section className="card">
            <div className="section-heading">
              <div><p className="eyebrow">{t.dashboard.ownerControls}</p><h2>{t.dashboard.sharingLimits}</h2></div>
              <Settings2 size={24} />
            </div>
            <PolicyEditor policy={policy} onChange={setPolicy} language={language} />
            <button className="primary" onClick={() => void savePolicy()} disabled={busy !== null}>
              {busy === "policy" ? <LoaderCircle className="spin" size={18} /> : <Check size={18} />} {t.dashboard.saveLimits}
            </button>
          </section>

          <section className="card">
            <div className="section-heading">
              <div><p className="eyebrow">{t.dashboard.reachability}</p><h2>{t.dashboard.advancedEndpoint}</h2></div>
              <Globe2 size={24} />
            </div>
            <p className="body-copy">{t.dashboard.endpointDescription}</p>
            {status?.providerPolicy?.manualEndpoint.configured && (
              <div className="endpoint-state"><Check size={17} /><span>{t.dashboard.endpointConfigured}</span><button onClick={() => void run("clear", async () => { await clearManualEndpoint(); await refresh(true) })}>{t.dashboard.remove}</button></div>
            )}
            {!manualOpen ? (
              <button className="secondary" onClick={() => setManualOpen(true)}>{t.dashboard.configureEndpoint}</button>
            ) : (
              <div className="endpoint-form">
                <label><span>{t.dashboard.publicHost}</span><input value={manualAddress} onChange={(e) => setManualAddress(e.target.value)} placeholder="node.example.com" /></label>
                <label><span>{t.dashboard.publicPort}</span><input type="number" value={manualPort} onChange={(e) => setManualPort(e.target.value)} min="1" max="65535" /></label>
                <div className="button-row"><button className="secondary" onClick={() => setManualOpen(false)}>{t.setup.cancel}</button><button className="primary" onClick={() => void saveEndpoint()} disabled={!manualAddress.trim()}>{t.dashboard.saveEndpoint}</button></div>
              </div>
            )}
          </section>

          <section className="card danger-card">
            <div className="section-heading"><div><p className="eyebrow">{t.dashboard.localOwnership}</p><h2>{t.dashboard.removeNode}</h2></div><Trash2 size={24} /></div>
            <p className="body-copy">{t.dashboard.removeDescription}</p>
            <label><span>{t.dashboard.confirmNodeId}</span><input value={confirmNodeId} onChange={(e) => setConfirmNodeId(e.target.value)} placeholder={status?.nodeId ?? ""} /></label>
            <button className="danger" disabled={confirmNodeId !== status?.nodeId || busy !== null} onClick={() => void run("unpair", async () => { const next = await unpair(confirmNodeId); setStatus(next); setConfirmNodeId("") })}>
              <Trash2 size={17} /> {t.dashboard.unpair}
            </button>
          </section>
        </div>
        )}
      </div>
    </main>
  )
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return <div className="metric"><span className="metric-icon">{icon}</span><div><span>{label}</span><strong>{value}</strong></div></div>
}

function PolicyEditor({ policy, onChange, language, compact = false }: { policy: ProviderPolicy; onChange: (value: ProviderPolicy) => void; language: Locale; compact?: boolean }) {
  const capGb = policy.monthlyTransferCapBytes == null ? "" : String(Math.round(policy.monthlyTransferCapBytes / GB))
  const bandwidthMbps = policy.bandwidthLimitBps == null ? "" : String(Math.round(policy.bandwidthLimitBps / 1_000_000))
  const t = nodeHostCopy[language].policy
  return (
    <div className={compact ? "policy compact" : "policy"}>
      <label><span>{t.monthlyTransfer}</span><div className="unit-input"><input type="number" min="1" value={capGb} placeholder={t.unlimited} onChange={(e) => onChange({ ...policy, monthlyTransferCapBytes: e.target.value ? Number(e.target.value) * GB : null })} /><b>GB</b></div></label>
      <label><span>{t.bandwidthLimit}</span><div className="unit-input"><input type="number" min="1" value={bandwidthMbps} placeholder={t.unlimited} onChange={(e) => onChange({ ...policy, bandwidthLimitBps: e.target.value ? Number(e.target.value) * 1_000_000 : null })} /><b>Mbps</b></div></label>
      <label><span>{t.concurrentSessions}</span><div className="unit-input"><input type="number" min="1" max="4096" value={policy.maxConcurrentSessions} onChange={(e) => onChange({ ...policy, maxConcurrentSessions: Number(e.target.value) })} /><b>{t.maximum}</b></div></label>
    </div>
  )
}

export default App
