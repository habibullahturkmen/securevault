import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type User } from './api'
import AuthView from './AuthView'
import VaultView from './VaultView'

export default function App() {
  const [user, setUser] = useState<User | null>(null)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setChecking(false))
  }, [])

  const handleLogout = useCallback(async () => {
    try {
      await api.logout()
    } catch (err) {
      // Session may already be gone; either way the client forgets it.
      if (!(err instanceof ApiError)) throw err
    }
    setUser(null)
  }, [])

  if (checking) {
    return <main className="center-page">Loading…</main>
  }
  if (!user) {
    return <AuthView onSignedIn={setUser} />
  }
  return <VaultView user={user} onLogout={handleLogout} />
}
