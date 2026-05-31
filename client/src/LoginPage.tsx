import { useState, useEffect } from 'react'
import { signChallenge } from './crypto'

const AGENT_URL = 'http://localhost:8765'
const AGENT_TIMEOUT_MS = 2000

interface Props {
  onLogin: (token: string, identity: string) => void
}

type AgentState = 'probing' | 'signing' | 'available' | 'unavailable'

export default function LoginPage({ onLogin }: Props) {
  const [passphrase, setPassphrase] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [agentState, setAgentState] = useState<AgentState>('probing')

  useEffect(() => {
    let cancelled = false

    async function tryAgent() {
      try {
        const ctrl = new AbortController()
        const timer = setTimeout(() => ctrl.abort(), AGENT_TIMEOUT_MS)
        const health = await fetch(`${AGENT_URL}/health`, { signal: ctrl.signal })
        clearTimeout(timer)
        if (!health.ok) throw new Error('unhealthy')
        const { ok } = await health.json()
        if (!ok) throw new Error('not ok')
      } catch {
        if (!cancelled) setAgentState('unavailable')
        return
      }

      if (cancelled) return
      setAgentState('signing')

      try {
        // Get challenge
        const BASE = import.meta.env.DEV ? '/api' : ''
        const { challenge } = await fetch(`${BASE}/auth/challenge`).then(r => r.json())

        // Ask agent to sign it
        const ctrl2 = new AbortController()
        const timer2 = setTimeout(() => ctrl2.abort(), AGENT_TIMEOUT_MS)
        const signRes = await fetch(`${AGENT_URL}/sign`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challenge }),
          signal: ctrl2.signal,
        })
        clearTimeout(timer2)
        if (!signRes.ok) throw new Error('sign failed')
        const { signature } = await signRes.json()

        // Verify with server
        const BASE2 = import.meta.env.DEV ? '/api' : ''
        const verifyRes = await fetch(`${BASE2}/auth/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challenge, signature }),
        })
        if (!verifyRes.ok) throw new Error('verify failed')
        const { token, identity } = await verifyRes.json()

        if (!cancelled) onLogin(token, identity)
      } catch (err) {
        if (!cancelled) {
          setAgentState('available')
          setError('Agent found but login failed. Enter passphrase manually.')
        }
      }
    }

    tryAgent()
    return () => { cancelled = true }
  }, [])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const BASE = import.meta.env.DEV ? '/api' : ''
      const { challenge } = await fetch(`${BASE}/auth/challenge`).then(r => r.json())
      const signature = await signChallenge(passphrase, challenge)
      const res = await fetch(`${BASE}/auth/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge, signature }),
      })
      if (!res.ok) { setError('Invalid passphrase.'); return }
      const { token, identity } = await res.json()
      onLogin(token, identity)
    } catch {
      setError('Could not reach server.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans flex items-center justify-center">
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 w-full max-w-sm">
        <h1 className="text-xl font-bold text-white mb-1">
          <span className="text-indigo-400">⬡</span> MediaForest
        </h1>

        {agentState === 'probing' && (
          <p className="text-sm text-gray-500 mt-3">Checking for local auth agent…</p>
        )}

        {agentState === 'signing' && (
          <p className="text-sm text-indigo-400 mt-3">Signing with local agent…</p>
        )}

        {(agentState === 'unavailable' || agentState === 'available') && (
          <>
            <p className="text-sm text-gray-500 mb-6 mt-1">Enter your passphrase to continue.</p>
            {agentState === 'unavailable' && (
              <p className="text-xs text-gray-600 mb-4">
                Local auth agent not running — passphrase required.{' '}
                <a
                  href="https://github.com/anthropics/claude-code"
                  className="text-indigo-500 hover:text-indigo-400"
                  target="_blank" rel="noreferrer"
                >
                  Set up agent
                </a>
              </p>
            )}
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <input
                type="password"
                value={passphrase}
                onChange={e => setPassphrase(e.target.value)}
                placeholder="Passphrase"
                autoFocus
                className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500"
              />
              {error && <p className="text-xs text-red-400">{error}</p>}
              <button
                type="submit"
                disabled={loading || !passphrase}
                className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg px-4 py-2.5 text-sm font-medium transition-colors"
              >
                {loading ? 'Unlocking…' : 'Unlock'}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  )
}
