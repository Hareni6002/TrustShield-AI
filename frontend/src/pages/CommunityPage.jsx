import { useEffect, useState } from 'react'
import { BarChart3, Flag, ShieldCheck } from 'lucide-react'
import { getCommunitySummary, submitCommunityReport } from '../services/api'
import PageTransition from '../components/PageTransition'

const categories = [['phishing', 'Phishing'], ['fake_shopping', 'Fake Shopping'], ['fake_job', 'Fake Job'], ['investment_scam', 'Investment Scam'], ['loan_scam', 'Loan Scam'], ['crypto_scam', 'Crypto Scam'], ['brand_impersonation', 'Brand Impersonation'], ['credential_theft', 'Credential Theft'], ['malware', 'Malware'], ['other', 'Other']]

export default function CommunityPage({ result, onScanAgain, onBack }) {
  const domain = result?.domain_analysis?.domain_name || ''
  const [summary, setSummary] = useState(null)
  const [form, setForm] = useState({ url: result?.normalized_url || '', category: 'phishing', description: '' })
  const [message, setMessage] = useState('')
  useEffect(() => { if (domain) getCommunitySummary(domain).then(setSummary).catch(() => {}) }, [domain])
  async function submit(event) { event.preventDefault(); setMessage(''); try { await submitCommunityReport(form); setMessage('Report submitted for moderation.'); setForm((current) => ({ ...current, description: '' })); if (domain) setSummary(await getCommunitySummary(domain)) } catch (error) { setMessage(error.response?.data?.detail || 'Report could not be submitted.') } }
  return <PageTransition><main className="utility-page community-page"><button className="utility-back-button" type="button" onClick={onBack}>← BACK</button><p className="eyebrow">Community intelligence</p><h1>{domain || 'Community Reports'}</h1><p className="utility-intro">Community reports are moderation-reviewed signals. They do not replace technical or reputation evidence.</p>{summary && <div className="community-overview"><div><Flag size={18} /><strong>{summary.total_reports}</strong><span>TOTAL REPORTS</span></div><div><ShieldCheck size={18} /><strong>{summary.verified_reports}</strong><span>VERIFIED</span></div><div><BarChart3 size={18} /><strong>{summary.community_risk_score}<small>/100</small></strong><span>COMMUNITY RISK</span></div></div>}<section className="community-grid"><form className="community-form" onSubmit={submit}><h2>Report this website</h2><label>URL<input value={form.url} onChange={(event) => setForm({ ...form, url: event.target.value })} required /></label><label>Category<select value={form.category} onChange={(event) => setForm({ ...form, category: event.target.value })}>{categories.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label>Description<textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} minLength={10} maxLength={5000} required placeholder="Describe the observed behavior..." /></label><button className="primary-button" type="submit">SUBMIT REPORT</button>{message && <p className="form-message">{message}</p>}</form><section className="community-reports"><h2>Latest reports</h2>{summary?.latest_reports?.length ? summary.latest_reports.map((report) => <article key={report.id}><span>{report.category.replaceAll('_', ' ')}</span><strong>{report.status}</strong><p>{report.description}</p><small>{new Date(report.created_at).toLocaleDateString()}</small></article>) : <div className="empty-state"><p>No community reports for this domain.</p></div>}</section></section><button className="text-button" onClick={() => onScanAgain()}>SCAN ANOTHER WEBSITE →</button></main></PageTransition>
}




