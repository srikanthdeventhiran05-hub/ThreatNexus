import { BrowserRouter as Router, Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import Dashboard from './pages/Dashboard'
import Analyze from './pages/Analyze'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import Register from './pages/Register'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { Shield, Scan, FileText, Settings as SettingsIcon, Activity, LogOut } from 'lucide-react'

function Sidebar() {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const links = [{ path: '/', label: 'Dashboard', icon: Activity }, { path: '/analyze', label: 'Analyze', icon: Scan }, { path: '/reports', label: 'Reports', icon: FileText }, { path: '/settings', label: 'Settings', icon: SettingsIcon }]
  const signOut = async () => { await logout(); navigate('/') }
  return <div className="w-64 bg-tn-darker border-r border-tn-border min-h-screen p-4 flex flex-col"><div className="flex items-center gap-3 mb-10 px-2"><div className="w-10 h-10 bg-tn-accent rounded-lg flex items-center justify-center"><Shield className="w-6 h-6 text-white" /></div><div><h1 className="text-lg font-bold text-white">ThreatNexus</h1><p className="text-xs text-gray-500">Email Forensics</p></div></div><nav className="space-y-1">{links.map(({ path, label, icon: Icon }) => <Link key={path} to={path} className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${location.pathname === path ? 'bg-tn-accent/10 text-tn-accent border border-tn-accent/30' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}><Icon className="w-4 h-4" />{label}</Link>)}</nav><div className="mt-auto space-y-3"><div className="bg-tn-card rounded-lg p-3 border border-tn-border"><p className="text-xs text-gray-500 truncate">{user?.email}</p><div className="flex items-center gap-2 mt-1"><div className="w-2 h-2 bg-tn-success rounded-full animate-pulse-glow" /><span className="text-sm text-tn-success">Operational</span></div></div><button onClick={signOut} className="w-full flex items-center gap-3 px-3 py-2.5 text-sm text-gray-400 hover:text-white hover:bg-white/5 rounded-lg"><LogOut className="w-4 h-4" />Sign out</button></div></div>
}

function Layout({ children }) { return <div className="flex min-h-screen bg-tn-dark"><Sidebar /><main className="flex-1 p-8 overflow-auto">{children}</main></div> }

export default function App() { return <Router><AuthProvider><Toaster position="top-right" toastOptions={{ style: { background: '#1e293b', color: '#fff' } }} /><Routes><Route path="/register" element={<Register />} /><Route path="*" element={<Layout><Routes><Route path="/" element={<Dashboard />} /><Route path="/analyze" element={<Analyze />} /><Route path="/reports" element={<Reports />} /><Route path="/settings" element={<Settings />} /></Routes></Layout>} /></Routes></AuthProvider></Router> }
