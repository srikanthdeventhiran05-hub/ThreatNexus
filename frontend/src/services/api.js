import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('threatnexus_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('threatnexus_token')
      localStorage.removeItem('threatnexus_user')
      window.dispatchEvent(new Event('threatnexus:unauthorized'))
    }
    return Promise.reject(error)
  },
)

export default api
export const authTokenKey = 'threatnexus_token'
export const authUserKey = 'threatnexus_user'

export function getStoredUser() {
  try { return JSON.parse(localStorage.getItem(authUserKey) || 'null') } catch { return null }
}

export function setSession(token, user) {
  localStorage.setItem(authTokenKey, token)
  localStorage.setItem(authUserKey, JSON.stringify(user))
}

export function clearSession() {
  localStorage.removeItem(authTokenKey)
  localStorage.removeItem(authUserKey)
}

export async function login(email, password) {
  const body = new URLSearchParams({ username: email, password })
  const { data } = await api.post('/api/auth/login', body, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })
  const { data: user } = await api.get('/api/auth/me', { headers: { Authorization: `Bearer ${data.access_token}` } })
  setSession(data.access_token, user)
  return user
}

export async function register(payload) {
  const { data: user } = await api.post('/api/auth/register', payload)
  return user
}

export async function logout() {
  try { await api.post('/api/auth/logout') } finally { clearSession() }
}

export function isAuthenticated() {
  return Boolean(localStorage.getItem(authTokenKey))
}

export async function fetchStats() { return (await api.get('/api/stats')).data }
export async function fetchRecentAnalyses(limit = 50) { return (await api.get(`/api/analyses/recent?limit=${limit}`)).data }
export async function analyze(payload, quick = false) { return (await api.post(`/api/${quick ? 'quick-scan' : 'analyze'}`, payload)).data }
export async function fetchSettings() { return (await api.get('/api/settings')).data }
export async function saveSettings(payload) { return (await api.put('/api/settings', payload)).data }
export async function deleteAnalysis(id) { return (await api.delete(`/api/analyses/${id}`)).data }
