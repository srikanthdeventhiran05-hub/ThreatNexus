import { useState, useEffect } from 'react'
import { FileText, Download, Search } from 'lucide-react'
import { fetchRecentAnalyses } from '../services/api'

export default function Reports() {
  const [analyses, setAnalyses] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  useEffect(() => { fetchAnalyses() }, [])

  const fetchAnalyses = async () => {
    try {
      const data = await fetchRecentAnalyses(50)
      setAnalyses(data)
    } catch { /* empty */ } finally { setLoading(false) }
  }

  const filtered = analyses.filter(a =>
    a.sender_email?.toLowerCase().includes(search.toLowerCase()) ||
    a.subject?.toLowerCase().includes(search.toLowerCase()) ||
    a.threat_type?.toLowerCase().includes(search.toLowerCase())
  )

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'threatnexus-report.json'; a.click()
    URL.revokeObjectURL(url)
  }

  if (loading) {
    return <div className="flex items-center justify-center h-96"><div className="w-8 h-8 border-2 border-tn-accent border-t-transparent rounded-full animate-spin"></div></div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Reports</h1>
          <p className="text-gray-500 mt-1">Forensic analysis reports and export</p>
        </div>
        <button onClick={exportJSON} className="px-4 py-2 bg-tn-card border border-tn-border rounded-lg text-sm flex items-center gap-2 hover:border-tn-accent/50 transition-all">
          <Download className="w-4 h-4" /> Export JSON
        </button>
      </div>

      <div className="relative">
        <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by sender, subject, type..."
          className="w-full bg-tn-card border border-tn-border rounded-lg pl-10 pr-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
      </div>

      <div className="bg-tn-card border border-tn-border rounded-xl overflow-hidden">
        {filtered.length > 0 ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 border-b border-tn-border">
                <th className="text-left py-3 px-4">ID</th>
                <th className="text-left py-3 px-4">Sender</th>
                <th className="text-left py-3 px-4">Subject</th>
                <th className="text-left py-3 px-4">Threat</th>
                <th className="text-left py-3 px-4">Level</th>
                <th className="text-left py-3 px-4">Score</th>
                <th className="text-left py-3 px-4">Date</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(a => (
                <tr key={a.id} className="border-b border-tn-border/50 hover:bg-white/5">
                  <td className="py-3 px-4 text-gray-500">#{a.id}</td>
                  <td className="py-3 px-4">{a.sender_email}</td>
                  <td className="py-3 px-4 max-w-xs truncate">{a.subject}</td>
                  <td className="py-3 px-4 text-gray-400">{a.threat_type}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                      a.threat_level === 'safe' ? 'bg-tn-success/10 text-tn-success' :
                      a.threat_level === 'low' ? 'bg-blue-500/10 text-blue-400' :
                      a.threat_level === 'medium' ? 'bg-tn-warning/10 text-tn-warning' :
                      'bg-tn-danger/10 text-tn-danger'
                    }`}>{a.threat_level?.toUpperCase()}</span>
                  </td>
                  <td className="py-3 px-4">{a.risk_score}</td>
                  <td className="py-3 px-4 text-gray-500">{a.created_at ? new Date(a.created_at).toLocaleDateString() : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="py-16 text-center text-gray-600">
            <FileText className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>No reports available. Analyze emails to generate reports.</p>
          </div>
        )}
      </div>
    </div>
  )
}
