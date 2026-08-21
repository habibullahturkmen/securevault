import { useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, type RegistrationStatus, type User } from './api'

export default function AuthView({ onSignedIn }: { onSignedIn: (u: User) => void }) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [inviteCode, setInviteCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // Until the policy is known, assume open so the form never hides itself
  // on a transient error; the server enforces the real policy regardless.
  const [policy, setPolicy] = useState<RegistrationStatus>({
    mode: 'open',
    acceptingRegistrations: true,
    inviteRequired: false,
  })

  useEffect(() => {
    api
      .registrationStatus()
      .then(setPolicy)
      .catch(() => {
        /* keep the permissive default; the server still decides */
      })
  }, [])

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      if (mode === 'register') {
        await api.register(username, password, policy.inviteRequired ? inviteCode : undefined)
      }
      const user = await api.login(username, password)
      onSignedIn(user)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'something went wrong')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="center-page">
      <form className="auth-card" onSubmit={submit}>
        <h1>SecureVault</h1>
        <p className="muted">Content-addressed encrypted file storage</p>

        <label htmlFor="username">Username</label>
        <input
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          required
        />

        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
          required
        />

        {mode === 'register' && policy.inviteRequired && (
          <>
            <label htmlFor="invite">Invite code</label>
            <input
              id="invite"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              autoComplete="one-time-code"
              spellCheck={false}
              required
            />
            <p className="muted small">
              Registration is by invitation. Ask an administrator for a code.
            </p>
          </>
        )}

        {error && <p className="error" role="alert">{error}</p>}

        <button type="submit" disabled={busy}>
          {mode === 'login' ? 'Sign in' : 'Create account'}
        </button>
        {policy.acceptingRegistrations ? (
          <button
            type="button"
            className="link"
            onClick={() => {
              setMode(mode === 'login' ? 'register' : 'login')
              setError('')
            }}
          >
            {mode === 'login' ? 'Need an account? Register' : 'Have an account? Sign in'}
          </button>
        ) : (
          <p className="muted small">Registration is currently closed.</p>
        )}
      </form>
    </main>
  )
}
