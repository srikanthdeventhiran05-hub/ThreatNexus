import { useState } from 'react'
import { Key, Globe, Server, Shield } from 'lucide-react'
import toast from 'react-hot-toast'

export default function Settings() {
  const [config, setConfig] = useState({
    virustotal_key: '',
    abuseipdb_key: '',
    api_url: 'http://localhost:8000',
    elasticsearch_url: 'http://localhost:9200',
    confidence_threshold: '0.5',
    auto_block: 'false',
  })

  const saveConfig = () => {
    toast.success('Settings saved (restart backend to apply)')
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-gray-500 mt-1">Configure API keys and system parameters</p>
      </div>

      <div className="bg-tn-card border border-tn-border rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2 mb-4">
          <Key className="w-4 h-4 text-tn-accent" />
          <h3 className="font-semibold">API Keys</h3>
        </div>
        <div>
          <label className="text-sm text-gray-400 mb-1 block">VirusTotal API Key</label>
          <input type="password" value={config.virustotal_key} onChange={e => setConfig({...config, virustotal_key: e.target.value})}
            placeholder="Enter VirusTotal API key"
            className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
          <p className="text-xs text-gray-600 mt-1">For URL and domain reputation checks</p>
        </div>
        <div>
          <label className="text-sm text-gray-400 mb-1 block">AbuseIPDB API Key</label>
          <input type="password" value={config.abuseipdb_key} onChange={e => setConfig({...config, abuseipdb_key: e.target.value})}
            placeholder="Enter AbuseIPDB API key"
            className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
          <p className="text-xs text-gray-600 mt-1">For IP reputation and abuse reports</p>
        </div>
      </div>

      <div className="bg-tn-card border border-tn-border rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2 mb-4">
          <Server className="w-4 h-4 text-tn-accent" />
          <h3 className="font-semibold">Endpoints</h3>
        </div>
        <div>
          <label className="text-sm text-gray-400 mb-1 block">Backend API URL</label>
          <input value={config.api_url} onChange={e => setConfig({...config, api_url: e.target.value})}
            className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
        </div>
        <div>
          <label className="text-sm text-gray-400 mb-1 block">Elasticsearch URL</label>
          <input value={config.elasticsearch_url} onChange={e => setConfig({...config, elasticsearch_url: e.target.value})}
            className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
        </div>
      </div>

      <div className="bg-tn-card border border-tn-border rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-4 h-4 text-tn-accent" />
          <h3 className="font-semibold">Detection Settings</h3>
        </div>
        <div>
          <label className="text-sm text-gray-400 mb-1 block">Confidence Threshold</label>
          <input type="number" min="0" max="1" step="0.1" value={config.confidence_threshold}
            onChange={e => setConfig({...config, confidence_threshold: e.target.value})}
            className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none" />
          <p className="text-xs text-gray-600 mt-1">Minimum confidence for origin assessment (0.0 - 1.0)</p>
        </div>
        <div>
          <label className="text-sm text-gray-400 mb-1 block">Auto-block High Risk</label>
          <select value={config.auto_block} onChange={e => setConfig({...config, auto_block: e.target.value})}
            className="w-full bg-tn-dark border border-tn-border rounded-lg px-4 py-2.5 text-sm focus:border-tn-accent focus:outline-none">
            <option value="false">Disabled</option>
            <option value="true">Enabled</option>
          </select>
        </div>
      </div>

      <button onClick={saveConfig}
        className="px-6 py-2.5 bg-tn-accent hover:bg-tn-accent/80 rounded-lg text-sm font-medium transition-all">
        Save Settings
      </button>
    </div>
  )
}
