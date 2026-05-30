import { useState } from 'react'
import { signChallenge } from './crypto'

interface Props {
  onLogin: (token: string, identity: string) => void
}

export default function LoginPage({ onLogin }: Props) {
  const [passphrase, setPassphrase] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      // 1. Get a one-time challenge nonce from the server
      const { challenge } = await fetch('/auth/challenge').then(r => r.json())

      // 2. Sign it locally — passphrase never leaves the browser
      const signature = await signChallenge(passphrase, challenge)

      // 3. Prove ownership; server returns a session token
      const res = await fetch('/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge, signature }),
      })
      if (!res.ok) {
        setError('Invalid passphrase.')
        return
      }
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
          <span className="text-indigo-400">⬡</span> PhraseVault
        </h1>
        <p className="text-sm text-gray-500 mb-6">Enter your passphrase to continue.</p>
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
      </div>
    </div>
  )
}
