import { useState, type FormEvent } from 'react'
import { api, ApiError } from './api'

export default function PasswordDialog({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.changePassword(current, next)
      // The server revoked all sessions and rotated this one; the new
      // cookies are already set.
      setDone(true)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'password change failed')
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Change password</h2>
        {done ? (
          <>
            <p>Password changed. All other sessions have been signed out.</p>
            <button onClick={onClose}>Close</button>
          </>
        ) : (
          <form className="stack" onSubmit={submit}>
            <label htmlFor="current-password">Current password</label>
            <input
              id="current-password"
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              required
            />
            <label htmlFor="new-password">New password (at least 8 characters)</label>
            <input
              id="new-password"
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
              required
            />
            {error && <p className="error" role="alert">{error}</p>}
            <button type="submit">Change password</button>
            <button type="button" className="link" onClick={onClose}>
              Cancel
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
