import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, type AuditEvent, type Invite, type RegistrationStatus } from './api'

interface AccountRow {
  id: string
  username: string
  role: string
  createdAt: string
}

const TTL_OPTIONS = [
  { hours: 24, label: '1 day' },
  { hours: 72, label: '3 days' },
  { hours: 168, label: '7 days' },
  { hours: 720, label: '30 days' },
]

export default function AdminView() {
  const [users, setUsers] = useState<AccountRow[]>([])
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [invites, setInvites] = useState<Invite[]>([])
  const [policy, setPolicy] = useState<RegistrationStatus | null>(null)
  const [error, setError] = useState('')

  const [note, setNote] = useState('')
  const [ttlHours, setTtlHours] = useState(168)
  const [issuing, setIssuing] = useState(false)
  // The freshly issued code: shown once, never retrievable again.
  const [freshCode, setFreshCode] = useState<{ code: string; note: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const refresh = useCallback(() => {
    Promise.all([api.adminUsers(), api.adminAudit(), api.adminInvites(), api.registrationStatus()])
      .then(([u, a, i, p]) => {
        setUsers(u.users)
        setEvents(a.events)
        setInvites(i.invites)
        setPolicy(p)
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : 'failed to load'))
  }, [])

  useEffect(refresh, [refresh])

  async function issueInvite(e: FormEvent) {
    e.preventDefault()
    setError('')
    setIssuing(true)
    setCopied(false)
    try {
      const res = await api.adminCreateInvite(note, ttlHours)
      setFreshCode({ code: res.code, note: res.invite.note })
      setNote('')
      refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'could not create invite')
    } finally {
      setIssuing(false)
    }
  }

  async function revoke(inv: Invite) {
    if (!confirm(`Revoke invite${inv.note ? ` "${inv.note}"` : ''}?`)) return
    try {
      await api.adminRevokeInvite(inv.id)
      refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'revoke failed')
    }
  }

  async function copyCode() {
    if (!freshCode) return
    try {
      await navigator.clipboard.writeText(freshCode.code)
      setCopied(true)
    } catch {
      /* clipboard unavailable (e.g. insecure context); the code is still on screen */
    }
  }

  return (
    <div className="admin">
      {error && <p className="error" role="alert">{error}</p>}

      <h2>Accounts</h2>
      <table className="files">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.username}</td>
              <td>{u.role}</td>
              <td>{new Date(u.createdAt).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Invites</h2>
      {policy && (
        <p className="muted">
          Registration mode: <strong>{policy.mode}</strong>
          {policy.mode !== 'invite' &&
            ' — invite codes are only required when the server runs with REGISTRATION_MODE=invite.'}
          {policy.mode === 'invite' && ' — new accounts need a code from this list.'}
        </p>
      )}
      <form className="invite-form" onSubmit={issueInvite}>
        <input
          aria-label="Note (who the invite is for)"
          placeholder="Note, e.g. who it is for (optional)"
          value={note}
          maxLength={64}
          onChange={(e) => setNote(e.target.value)}
        />
        <select
          aria-label="Invite lifetime"
          value={ttlHours}
          onChange={(e) => setTtlHours(Number(e.target.value))}
        >
          {TTL_OPTIONS.map((o) => (
            <option key={o.hours} value={o.hours}>
              valid {o.label}
            </option>
          ))}
        </select>
        <button type="submit" disabled={issuing}>
          Generate invite
        </button>
      </form>
      {freshCode && (
        <div className="invite-code" role="status">
          <div>
            <strong>Invite code{freshCode.note ? ` for ${freshCode.note}` : ''}:</strong>{' '}
            <code>{freshCode.code}</code>
          </div>
          <div className="invite-code-actions">
            <button type="button" className="small" onClick={copyCode}>
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button type="button" className="link small" onClick={() => setFreshCode(null)}>
              Dismiss
            </button>
          </div>
          <p className="muted small">
            Shown once — it is stored only as a hash. Share it with the person it is for.
          </p>
        </div>
      )}
      <table className="files">
        <thead>
          <tr>
            <th>Note</th>
            <th>Issued by</th>
            <th>Issued</th>
            <th>Expires</th>
            <th>Status</th>
            <th>Used by</th>
            <th className="actions-col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {invites.length === 0 && (
            <tr>
              <td colSpan={7} className="muted">
                No invites issued yet.
              </td>
            </tr>
          )}
          {invites.map((i) => (
            <tr key={i.id} className={i.status === 'revoked' ? 'denied-row' : ''}>
              <td>{i.note || '—'}</td>
              <td>{i.createdBy}</td>
              <td>{new Date(i.createdAt).toLocaleString()}</td>
              <td>{new Date(i.expiresAt).toLocaleString()}</td>
              <td>
                <span className={`role invite-${i.status}`}>{i.status}</span>
              </td>
              <td>{i.usedBy || '—'}</td>
              <td className="actions-col">
                {i.status === 'active' && (
                  <button className="link small danger-link" onClick={() => revoke(i)}>
                    Revoke
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Audit log (latest 200)</h2>
      <table className="files audit">
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Result</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i} className={e.result === 'denied' ? 'denied-row' : ''}>
              <td>{new Date(e.at).toLocaleString()}</td>
              <td>{e.actor || '—'}</td>
              <td>{e.action}</td>
              <td className="target-cell">{e.target}</td>
              <td>{e.result}</td>
              <td>{e.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
