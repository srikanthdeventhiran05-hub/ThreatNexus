import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../hooks/useAuth'

export default function Register() {
  const { user, register, loading } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ email: '', username: '', password: '' })
  if (user) return <Navigate to="/" replace />
  const submit = async (event) => { event.preventDefault(); try { await register(form); toast.success('Account created'); navigate('/login') } catch (error) { toast.error(error.response?.data?.detail || 'Unable to create account') } }
  return <div className="min-h-screen bg-tn-dark flex items-center justify-center p-6"><div className="w-full max-w-md bg-tn-card border border-tn-border rounded-2xl p-8"><h1 className="text-2xl font-bold text-white">Create your account</h1><p className="text-gray-500 mt-2 mb-6">Start investigating suspicious email activity.</p><form onSubmit={submit} className="space-y-4"><input required type="email" placeholder="Email address" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} className="auth-input" /><input required minLength={3} placeholder="Username" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} className="auth-input" /><input required minLength={6} type="password" placeholder="Password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} className="auth-input" /><button disabled={loading} className="auth-button">{loading && <Loader2 className="w-4 h-4 animate-spin" />}Create account</button></form><p className="text-sm text-gray-500 text-center mt-6">Already registered? <Link className="text-tn-accent hover:underline" to="/login">Sign in</Link></p></div></div>
}
