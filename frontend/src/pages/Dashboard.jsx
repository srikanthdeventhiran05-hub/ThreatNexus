import { useState, useEffect } from 'react'
import { Shield, AlertTriangle, CheckCircle, TrendingUp, Mail, Globe, Activity } from 'lucide-react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import axios from 'axios'

const COLORS = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#dc2626']

function StatCard({ icon: Icon, label, value, color, sub }) {
  return (
    <div className="bg-tn-card border border-tn-border rounded-xl p-5 hover:border-tn-accent/30 transition-all">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-500 text-sm">{label}</p>
          <p className={`text-2xl font-bold mt-1 ${color || 'text-white'}`}>{value}</p>
          {sub && <p className="text-xs text-gray-600 mt-1">{sub}</p>}
        </div>
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color ? `bg-${color}/10` : 'bg-tn-accent/10'}`}>
          <Icon className="w-5 h-5 text-tn-accent" />
        </div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchStats()
  }, [])

  const fetchStats = async () => {
    try {
      const res = await axios.get('/api/stats')
      setStats(res.data)
    } catch {
      setStats({
        total_analyses: 0, threats_detected: 0, safe_emails: 0,
        high_risk_count: 0, avg_risk_score: 0, top_threat_types: [],
        recent_analyses: [], threat_distribution: {},
      })
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="w-8 h-8 border-2 border-tn-accent border-t-transparent rounded-full animate-spin"></div>
      </div>
    )
  }

  const pieData = stats.threat_distribution ? [
    { name: 'Safe', value: stats.threat_distribution.safe || 0 },
    { name: 'Low', value: stats.threat_distribution.low || 0 },
    { name: 'Medium', value: stats.threat_distribution.medium || 0 },
    { name: 'High', value: stats.threat_distribution.high || 0 },
    { name: 'Critical', value: stats.threat_distribution.critical || 0 },
  ].filter(d => d.value > 0) : []

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-gray-500 mt-1">AI-Powered Email Threat Intelligence</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Mail} label="Total Analyses" value={stats.total_analyses} />
        <StatCard icon={AlertTriangle} label="Threats Detected" value={stats.threats_detected} color="text-tn-danger" />
        <StatCard icon={CheckCircle} label="Safe Emails" value={stats.safe_emails} color="text-tn-success" />
        <StatCard icon={TrendingUp} label="Avg Risk Score" value={stats.avg_risk_score.toFixed(1)} color="text-tn-warning" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-tn-card border border-tn-border rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4">Threat Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({ name, value }) => `${name}: ${value}`}>
                  {pieData.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-600">
              No data yet. Analyze your first email.
            </div>
          )}
        </div>

        <div className="bg-tn-card border border-tn-border rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4">Top Threat Types</h3>
          {stats.top_threat_types.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={stats.top_threat_types}>
                <XAxis dataKey="type" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-600">
              No threat data available.
            </div>
          )}
        </div>
      </div>

      <div className="bg-tn-card border border-tn-border rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4">Recent Analyses</h3>
        {stats.recent_analyses.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 border-b border-tn-border">
                  <th className="text-left py-3 px-4">Sender</th>
                  <th className="text-left py-3 px-4">Subject</th>
                  <th className="text-left py-3 px-4">Threat Level</th>
                  <th className="text-left py-3 px-4">Risk Score</th>
                  <th className="text-left py-3 px-4">Type</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_analyses.map((a) => (
                  <tr key={a.id} className="border-b border-tn-border/50 hover:bg-white/5">
                    <td className="py-3 px-4">{a.sender_email}</td>
                    <td className="py-3 px-4 max-w-xs truncate">{a.subject}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        a.threat_level === 'safe' ? 'bg-tn-success/10 text-tn-success' :
                        a.threat_level === 'low' ? 'bg-blue-500/10 text-blue-400' :
                        a.threat_level === 'medium' ? 'bg-tn-warning/10 text-tn-warning' :
                        a.threat_level === 'high' ? 'bg-orange-500/10 text-orange-400' :
                        'bg-tn-danger/10 text-tn-danger'
                      }`}>
                        {a.threat_level?.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-tn-border rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${
                            a.risk_score < 20 ? 'bg-tn-success' :
                            a.risk_score < 40 ? 'bg-blue-400' :
                            a.risk_score < 60 ? 'bg-tn-warning' :
                            a.risk_score < 80 ? 'bg-orange-400' :
                            'bg-tn-danger'
                          }`} style={{ width: `${Math.min(a.risk_score, 100)}%` }} />
                        </div>
                        <span className="text-xs">{a.risk_score}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-gray-400">{a.threat_type}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-600 text-center py-8">No analyses yet. Go to Analyze to scan your first email.</p>
        )}
      </div>
    </div>
  )
}
