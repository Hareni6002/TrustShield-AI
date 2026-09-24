import { useEffect, useState } from 'react'
import { Activity } from 'lucide-react'
import { getIntegrationStatus } from '../services/api'

const labels = { gemini: 'Gemini', virustotal: 'VirusTotal', google_safe_browsing: 'Safe Browsing', urlhaus: 'URLhaus' }

export default function ProviderStatus() {
  const [status, setStatus] = useState(null)

  useEffect(() => {
    let mounted = true
    getIntegrationStatus().then((value) => mounted && setStatus(value)).catch(() => mounted && setStatus({}))
    return () => { mounted = false }
  }, [])

  return <section className="provider-status" aria-label="Integration status"><div className="provider-status-head"><Activity size={14} /><span>PROVIDER HEALTH</span></div><div className="provider-status-grid">{Object.entries(labels).map(([key, label]) => { const value = status?.[key]; const state = value?.status === 'available' || value?.available ? 'ONLINE' : value?.status === 'not_configured' ? 'NOT CONFIGURED' : status ? 'UNAVAILABLE' : 'CHECKING'; return <div key={key}><span>{label}</span><b className={`provider-state ${state.toLowerCase().replaceAll(' ', '-')}`}>{state}</b></div> })}</div></section>
}
