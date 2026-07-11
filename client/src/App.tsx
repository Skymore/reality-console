import { useEffect, useState } from "react"

import { getClientState, type ClientState } from "./api"

export default function App() {
  const [state, setState] = useState<ClientState | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void getClientState().then(setState).catch((reason: unknown) => {
      setError(reason instanceof Error ? reason.message : String(reason))
    })
  }, [])

  return (
    <main>
      <p className="eyebrow">Reality Client</p>
      <h1>Frontend handoff surface</h1>
      <p>This placeholder confirms the client backend contract without defining the final UI.</p>
      <pre>{error ?? JSON.stringify(state, null, 2) ?? "Loading..."}</pre>
    </main>
  )
}
