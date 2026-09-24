import { useEffect, useState } from 'react'
import { Clock3, ExternalLink, ShieldAlert } from 'lucide-react'
import { getHistory, getHistoryResult } from '../services/api'
import PageTransition from '../components/PageTransition'

const percent = (value) => value == null ? 'Unavailable' : `${Math.round(value * 100)}%`

export default function HistoryPage({ onScanAgain, onViewResult }) {
  const [data, setData] = useState({ items: [], total: 0 })
  const [loading, setLoading] = useState(true)
  useEffect(() => { getHistory().then(setData).catch(() => {}).finally(() => setLoading(false)) }, [])
  return <PageTransition><main className="utility-page"><p className="eyebrow">Scan archive</p><h1>Scan History</h1><p className="utility-intro">Compact records of completed scans. No raw page content or provider credentials are stored.</p>{loading ? <div className="empty-state"><p>Loading scan history...</p></div> : data.items.length === 0 ? <div className="empty-state"><Clock3 size={28} /><h2>No scans yet</h2><p>Completed scans will appear here.</p><button className="primary-button" onClick={onScanAgain}>START A SCAN</button></div> : <div className="history-list">{data.items.map((item) => <article className="history-card" key={item.id}><div className="history-card-main"><span className="history-domain"><ShieldAlert size={16} />{item.domain}</span><small>{new Date(item.created_at).toLocaleString()}</small><strong>{item.risk_level}</strong></div><div className="history-metrics"><b>{item.trustshield_score}<small>TRUST SCORE</small></b><b>{percent(item.ml_probability)}<small>ML RISK</small></b><b>{item.community_reports}<small>REPORTS</small></b></div><div className="history-actions"><button type="button" onClick={() => onViewResult(item.id)}>VIEW RESULT</button><button type="button" onClick={() => onScanAgain(item.url)}>SCAN AGAIN</button><a href={item.normalized_url} target="_blank" rel="noreferrer" aria-label={`Open ${item.domain}`}><ExternalLink size={15} /></a></div></article>)}</div>}</main></PageTransition>
}




