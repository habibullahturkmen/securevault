import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, type FileNode, type ShareGrant } from './api'

export default function ShareDialog({ file, onClose }: { file: FileNode; onClose: () => void }) {
  const [grants, setGrants] = useState<ShareGrant[]>([])
  const [username, setUsername] = useState('')
  const [role, setRole] = useState<'viewer' | 'editor'>('viewer')
  const [error, setError] = useState('')

  const refresh = useCallback(() => {
    api
      .statFile(file.id)
      .then((r) => setGrants(r.shares ?? []))
      .catch((err) => setError(err instanceof ApiError ? err.message : 'failed to load shares'))
  }, [file.id])

  useEffect(refresh, [refresh])

  async function grant(e: FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.share(file.id, username, role)
      setUsername('')
      refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'share failed')
    }
  }

  async function revoke(name: string) {
    setError('')
    try {
      await api.revoke(file.id, name)
      refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'revoke failed')
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Share “{file.name}”</h2>

        <form className="share-form" onSubmit={grant}>
          <input
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
          <select value={role} onChange={(e) => setRole(e.target.value as 'viewer' | 'editor')}>
            <option value="viewer">viewer — view and download</option>
            <option value="editor">editor — view, download, rename</option>
          </select>
          <button type="submit">Grant</button>
        </form>

        {error && <p className="error" role="alert">{error}</p>}

        <ul className="grant-list">
          {grants.length === 0 && <li className="muted">Not shared with anyone.</li>}
          {grants.map((g) => (
            <li key={g.username}>
              <span>
                {g.username} — <span className={`role role-${g.role}`}>{g.role}</span>
              </span>
              <button className="small danger" onClick={() => revoke(g.username)}>
                Revoke
              </button>
            </li>
          ))}
        </ul>

        <button className="link" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  )
}
