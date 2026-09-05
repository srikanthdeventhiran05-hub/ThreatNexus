import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Shield, Loader2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../hooks/useAuth'

export default function Login() {
  const { user, login, loading } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [form, setForm] = useState({ email: '', password: '' })
  if (user) return <Navigate to="/" replace />

  const submit = async (event) => {
    event.preventDefault()
    try { await login(form.email, form.password); toast.success('Welcome back'); navigate(location.state?.from || '/') }
    catch (error) { toast.error(error.response?.data?.detail || 'Unable to sign in') }
  }

  return <AuthLayout title="Sign in to ThreatNexus" subtitle="Continue your email threat investigations.">
    <form onSubmit={submit} className="space-y-4">
      <input required type="email" placeholder="Email address" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} className="auth-input" />
      <input required type="password" placeholder="Password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} className="auth-input" />
      <button disabled={loading} className="auth-button">{loading && <Loader2 className="w-4 h-4 animate-spin" />}Sign in</button>
    </form>
    <p className="text-sm text-gray-500 text-center mt-6">New to ThreatNexus? <Link className="text-tn-accent hover:underline" to="/register">Create an account</Link></p>
  </AuthLayout>
}

function AuthLayout({ title, subtitle, children }) { return <div className="min-h-screen bg-tn-dark flex items-center justify-center p-6"><div className="w-full max-w-md bg-tn-card border border-tn-border rounded-2xl p-8"><div className="flex items-center gap-3 mb-8"><div className="w-11 h-11 rounded-xl bg-tn-accent flex items-center justify-center"><Shield className="w-6 h-6 text-white" /></div><div><h1 className="text-lg font-bold text-white">ThreatNexus</h1><p className="text-xs text-gray-500">Email Forensics</p></div></div><h2 className="text-2xl font-bold text-white">{title}</h2><p className="text-gray-500 mt-2 mb-6">{subtitle}</p>{children}</div></div> }
