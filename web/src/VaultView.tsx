import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, downloadUrl, uploadFile, type FileNode, type User } from './api'
import ShareDialog from './ShareDialog'
import PasswordDialog from './PasswordDialog'
import AdminView from './AdminView'

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

export default function VaultView({ user, onLogout }: { user: User; onLogout: () => void }) {
  const [files, setFiles] = useState<FileNode[]>([])
  const [error, setError] = useState('')
  const [progress, setProgress] = useState<number | null>(null)
  const [sharing, setSharing] = useState<FileNode | null>(null)
  const [changingPassword, setChangingPassword] = useState(false)
  const [showAdmin, setShowAdmin] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  const refresh = useCallback(() => {
    api
      .listFiles()
      .then((r) => setFiles(r.files))
      .catch((err) => setError(err instanceof ApiError ? err.message : 'failed to load files'))
  }, [])

  useEffect(refresh, [refresh])

  async function handleUpload(list: FileList | null) {
    if (!list || list.length === 0) return
    setError('')
    setProgress(0)
    try {
      await uploadFile(list[0], setProgress)
      refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'upload failed')
    } finally {
      setProgress(null)
      if (fileInput.current) fileInput.current.value = ''
    }
  }

  async function handleRename(f: FileNode) {
    const name = window.prompt('New name', f.name)
    if (!name || name === f.name) return
    try {
      await api.rename(f.id, name)
      refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'rename failed')
    }
  }

  async function handleDelete(f: FileNode) {
    if (!window.confirm(`Delete "${f.name}"? This cannot be undone.`)) return
    try {
      await api.remove(f.id)
      refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'delete failed')
    }
  }

  return (
    <main className="vault">
      <header className="topbar">
        <h1>SecureVault</h1>
        <div className="topbar-actions">
          <span className="muted">
            {user.username}
            {user.role === 'admin' && ' (admin)'}
          </span>
          {user.role === 'admin' && (
            <button className="link" onClick={() => setShowAdmin(!showAdmin)}>
              {showAdmin ? 'Files' : 'Administration'}
            </button>
          )}
          <button className="link" onClick={() => setChangingPassword(true)}>
            Change password
          </button>
          <button className="link" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </header>

      {error && (
        <p className="error" role="alert">
          {error} <button className="link" onClick={() => setError('')}>dismiss</button>
        </p>
      )}

      {showAdmin ? (
        <AdminView />
      ) : (
        <>
          <div className="toolbar">
            <input
              ref={fileInput}
              type="file"
              id="file-input"
              className="visually-hidden"
              onChange={(e) => handleUpload(e.target.files)}
            />
            <label htmlFor="file-input" className="button">
              Upload file
            </label>
            {progress !== null && (
              <span className="upload-progress">
                <progress value={progress} max={100} /> {progress}%
              </span>
            )}
          </div>

          <table className="files">
            <thead>
              <tr>
                <th>Name</th>
                <th>Owner</th>
                <th>Your role</th>
                <th>Size</th>
                <th>Updated</th>
                <th className="actions-col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {files.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted center-text">
                    No files yet. Upload one to get started.
                  </td>
                </tr>
              )}
              {files.map((f) => (
                <tr key={f.id}>
                  <td>{f.name}</td>
                  <td>{f.owner}</td>
                  <td>
                    <span className={`role role-${f.myRole}`}>{f.myRole}</span>
                  </td>
                  <td>{formatSize(f.size)}</td>
                  <td>{new Date(f.updatedAt).toLocaleString()}</td>
                  <td className="actions-col">
                    {/* Buttons reflect the sharing-role matrix; the server
                        re-authorizes every request regardless. */}
                    <a className="button small" href={downloadUrl(f.id)}>
                      Download
                    </a>
                    {(f.myRole === 'owner' || f.myRole === 'editor') && (
                      <button className="small" onClick={() => handleRename(f)}>
                        Rename
                      </button>
                    )}
                    {f.myRole === 'owner' && (
                      <>
                        <button className="small" onClick={() => setSharing(f)}>
                          Share
                        </button>
                        <button className="small danger" onClick={() => handleDelete(f)}>
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {sharing && <ShareDialog file={sharing} onClose={() => setSharing(null)} />}
      {changingPassword && <PasswordDialog onClose={() => setChangingPassword(false)} />}
    </main>
  )
}
