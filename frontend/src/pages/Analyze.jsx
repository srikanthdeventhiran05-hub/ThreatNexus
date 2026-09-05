import { useState } from 'react'
import { Upload, Search, Shield, AlertTriangle, Globe, Mail, Link as LinkIcon, FileText, ChevronDown, ChevronUp, Loader2 } from 'lucide-react'
import toast from 'react-hot-toast'
import axios from 'axios'

function ScoreGauge({ score, level }) {
  const color =
    score < 20 ? '#10b981' : score < 40 ? '#3b82f6' :
    score < 60 ? '#f59e0b' : score < 80 ? '#f97316' : '#ef4444'

  return (
    <div className="relative w-32 h-32">
      <svg className="w-32 h-32 transform -rotate-90" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="50" fill="none" stroke="#1e293b" strokeWidth="10" />
        <circle cx="60" cy="60" r="50" fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${score * 3.14} 314`} strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs text-gray-500">{level?.toUpperCase()}</span>
      </div>
    </div>
  )
}

function Section({ title, icon: Icon, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="bg-tn-card border border-tn-border rounded-xl overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors">
        <div className="flex items-center gap-3">
          <Icon className="w-4 h-4 text-tn-accent" />
          <span className="font-medium">{title}</span>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
      </button>
      {open && <div className="p-4 border-t border-tn-border">{children}</div>}
    </div>
  )
}

export default function Analyze() {
  const [mode, setMode] = useState('full')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [form, setForm] = useState({
    sender_email: '', recipient_email: '', subject: '',
    raw_headers: '', raw_body: '',
  })
  const [quickForm, setQuickForm] = useState({
    sender_email: '', subject: '', body_preview: '',
  })

  const analyzeEmail = async () => {
    setLoading(true)
    try {
      const endpoint = mode === 'full' ? '/api/analyze' : '/api/quick-scan'
      const payload = mode === 'full' ? form : quickForm
      const res = await axios.post(endpoint, payload)
      setResult(res.data)
      toast.success('Analysis complete')
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Email Analysis</h1>
        <p className="text-gray-500 mt-1">Detect, trace and investigate email threats</p>
      </div>

      <div className="flex gap-2 bg-tn-card p-1 rounded-lg border border-tn-border w-fit">
        <button onClick={() => setMode('full')} className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${mode === 'full' ? 'bg-tn-accent text-white' : 'text-gray-400 hover:text-white'}`}>
          Full Analysis
        </button>
        <button onClick={() => setMode('quick')} className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${mode === 'quick' ? 'bg-tn-accent text-white' : 'text-gray-400 hover:text-white'}`}>
          Quick Scan
        </button>
      </div>

      <div className="bg-tn-card border border-tn-border rounded-xl p-6">
        {mode === 'full' ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-400 mb-1 block">Sender Email</label>
                <input value={form.sender_email} onChange={e => setForm({...form, sender_email: e.target.value})}
                  placeholder="attacker@phishing.com"
                  className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
              </div>
              <div>
                <label className="text-sm text-gray-400 mb-1 block">Recipient Email</label>
                <input value={form.recipient_email} onChange={e => setForm({...form, recipient_email: e.target.value})}
                  placeholder="victim@company.com"
                  className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
              </div>
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Subject</label>
              <input value={form.subject} onChange={e => setForm({...form, subject: e.target.value})}
                placeholder="URGENT: Verify your account immediately"
                className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Email Headers (Raw)</label>
              <textarea value={form.raw_headers} onChange={e => setForm({...form, raw_headers: e.target.value})}
                placeholder="Paste raw email headers here..."
                rows={5}
                className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm font-mono focus:border-tn-accent focus:outline-none" />
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Email Body (Raw)</label>
              <textarea value={form.raw_body} onChange={e => setForm({...form, raw_body: e.target.value})}
                placeholder="Paste email body here..."
                rows={8}
                className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm font-mono focus:border-tn-accent focus:outline-none" />
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-400 mb-1 block">Sender Email</label>
                <input value={quickForm.sender_email} onChange={e => setQuickForm({...quickForm, sender_email: e.target.value})}
                  placeholder="sender@example.com"
                  className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
              </div>
              <div>
                <label className="text-sm text-gray-400 mb-1 block">Subject</label>
                <input value={quickForm.subject} onChange={e => setQuickForm({...quickForm, subject: e.target.value})}
                  placeholder="Email subject"
                  className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
              </div>
            </div>
            <div>
              <label className="text-sm text-gray-400 mb-1 block">Body Preview</label>
              <textarea value={quickForm.body_preview} onChange={e => setQuickForm({...quickForm, body_preview: e.target.value})}
                placeholder="First few lines of the email body..."
                rows={5}
                className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
            </div>
          </div>
        )}
        <button onClick={analyzeEmail} disabled={loading}
          className="mt-4 px-6 py-2.5 bg-tn-accent hover:bg-tn-accent/80 disabled:opacity-50 rounded-lg text-sm font-medium flex items-center gap-2 transition-all">
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          {loading ? 'Analyzing...' : 'Analyze Email'}
        </button>
      </div>

      {result && (
        <div className="space-y-6">
          <div className="bg-tn-card border border-tn-border rounded-xl p-6">
            <div className="flex items-center gap-8">
              <ScoreGauge score={result.risk_score} level={result.threat_level} />
              <div className="flex-1">
                <h3 className="text-lg font-bold mb-2">Analysis Result</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500">Threat Type</span>
                    <p className="font-medium mt-1">{result.threat_type || 'N/A'}</p>
                  </div>
                  <div>
                    <span className="text-gray-500">SPF</span>
                    <p className={`font-medium mt-1 ${result.spf_result === 'pass' ? 'text-tn-success' : 'text-tn-danger'}`}>
                      {result.spf_result?.toUpperCase()}
                    </p>
                  </div>
                  <div>
                    <span className="text-gray-500">DKIM</span>
                    <p className={`font-medium mt-1 ${result.dkim_result === 'pass' ? 'text-tn-success' : 'text-tn-danger'}`}>
                      {result.dkim_result?.toUpperCase()}
                    </p>
                  </div>
                  <div>
                    <span className="text-gray-500">DMARC</span>
                    <p className={`font-medium mt-1 ${result.dmarc_result === 'pass' ? 'text-tn-success' : 'text-tn-danger'}`}>
                      {result.dmarc_result?.toUpperCase()}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {result.sender_ip && (
            <Section title="Sender Geolocation" icon={Globe} defaultOpen={true}>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div><span className="text-gray-500">IP Address</span><p className="mt-1 font-mono">{result.sender_ip}</p></div>
                <div><span className="text-gray-500">Country</span><p className="mt-1">{result.sender_country || 'Unknown'}</p></div>
                <div><span className="text-gray-500">City</span><p className="mt-1">{result.sender_city || 'Unknown'}</p></div>
                <div><span className="text-gray-500">Reputation</span><p className="mt-1">{(result.sender_reputation * 100).toFixed(0)}%</p></div>
              </div>
            </Section>
          )}

          {result.suspicious_patterns?.length > 0 && (
            <Section title="Suspicious Patterns" icon={AlertTriangle} defaultOpen={true}>
              <div className="space-y-2">
                {result.suspicious_patterns.map((p, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm">
                    <div className="w-1.5 h-1.5 bg-tn-warning rounded-full"></div>
                    <span>{p}</span>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {result.detected_links?.length > 0 && (
            <Section title="Link Analysis" icon={LinkIcon}>
              <div className="space-y-2">
                {result.detected_links.map((l, i) => (
                  <div key={i} className="flex items-center justify-between p-2 bg-tn-dark rounded-lg text-sm">
                    <span className="font-mono truncate max-w-lg">{l.url}</span>
                    {l.is_threat && <span className="text-tn-danger text-xs font-medium">MALICIOUS</span>}
                    {l.is_shortener && <span className="text-tn-warning text-xs font-medium">SHORTENER</span>}
                  </div>
                ))}
              </div>
            </Section>
          )}

          {result.trace_path?.length > 0 && (
            <Section title="Trace Path" icon={Globe} defaultOpen={true}>
              <div className="space-y-3">
                {result.trace_path.map((hop, i) => (
                  <div key={i} className="flex items-center gap-4 p-3 bg-tn-dark rounded-lg">
                    <div className="w-8 h-8 bg-tn-accent/10 rounded-full flex items-center justify-center text-xs font-bold text-tn-accent">
                      {i + 1}
                    </div>
                    <div className="flex-1">
                      <p className="text-sm font-mono">{hop.ip}</p>
                      <p className="text-xs text-gray-500">{hop.location} - {hop.isp}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {result.forensic_evidence?.length > 0 && (
            <Section title="Forensic Evidence" icon={FileText}>
              <div className="space-y-3">
                {result.forensic_evidence.map((e, i) => (
                  <div key={i} className="p-3 bg-tn-dark rounded-lg">
                    <p className="text-sm font-medium text-tn-accent">{e.type}</p>
                    <p className="text-xs text-gray-400 mt-1">{e.description}</p>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {result.recommendations?.length > 0 && (
            <Section title="Recommendations" icon={Shield} defaultOpen={true}>
              <div className="space-y-2">
                {result.recommendations.map((r, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm p-2 bg-tn-dark rounded-lg">
                    <AlertTriangle className="w-4 h-4 text-tn-warning mt-0.5 flex-shrink-0" />
                    <span>{r}</span>
                  </div>
                ))}
              </div>
            </Section>
          )}
        </div>
      )}
    </div>
  )
}
