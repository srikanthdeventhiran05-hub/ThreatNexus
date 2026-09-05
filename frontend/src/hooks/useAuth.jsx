import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { clearSession, getStoredUser, login as loginRequest, logout as logoutRequest, register as registerRequest } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(getStoredUser)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const handleUnauthorized = () => setUser(null)
    window.addEventListener('threatnexus:unauthorized', handleUnauthorized)
    return () => window.removeEventListener('threatnexus:unauthorized', handleUnauthorized)
  }, [])

  const value = useMemo(() => ({
    user,
    loading,
    async login(email, password) { setLoading(true); try { const nextUser = await loginRequest(email, password); setUser(nextUser); return nextUser } finally { setLoading(false) } },
    async register(payload) { setLoading(true); try { return await registerRequest(payload) } finally { setLoading(false) } },
    async logout() { await logoutRequest(); setUser(null); clearSession() },
  }), [user, loading])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}
