import { useEffect, useState } from 'react'
import { api, ApiError, type AuditEvent } from './api'

interface AccountRow {
  id: string
  username: string
  role: string
  createdAt: string
}

export default function AdminView() {
  const [users, setUsers] = useState<AccountRow[]>([])
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([api.adminUsers(), api.adminAudit()])
      .then(([u, a]) => {
        setUsers(u.users)
        setEvents(a.events)
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : 'failed to load'))
  }, [])

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
