import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Activity, Code2, Globe2, LockKeyhole, Network, Server, ShieldCheck } from 'lucide-react'
import SignalCard from '../components/SignalCard'
import { BrandScanner, DomainTimeline, LexicalRadar, StatusNode } from '../components/Visuals'
import { askTrustShield, getAISummary } from '../services/api'

const display = (value) => value == null || value === '' ? 'Unavailable' : value
const bool = (value, yes = 'Detected', no = 'Not detected') => value ? yes : no

function DetailShell({ eyebrow, title, onBack, children }) {
  return <motion.main className="detail-page" initial={{ opacity: 0, x: 18 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -18 }}><button className="back-button" onClick={onBack}>← BACK TO OVERVIEW</button><p className="eyebrow">{eyebrow}</p><h1>{title}</h1>{children}</motion.main>
}

function DataGrid({ items }) {
  return <div className="data-grid">{items.map(([label, value]) => <div className="data-cell" key={label}><span>{label}</span><strong>{display(value)}</strong></div>)}</div>
}

export function TechnicalPage({ result, onBack }) {
  const { ssl_analysis: ssl, dns_analysis: dns, http_analysis: http, url_analysis: url } = result
  return <DetailShell eyebrow="Technical intelligence" title="Connection & infrastructure" onBack={onBack}><div className="status-console"><StatusNode icon={LockKeyhole} label="SSL" value={ssl.ssl_valid ? 'VALID' : ssl.ssl_available ? 'UNVERIFIED' : 'UNAVAILABLE'} detail={ssl.days_until_expiry == null ? 'Certificate status' : `${ssl.days_until_expiry} days to expiry`} tone={ssl.ssl_valid ? 'low' : 'high'} /><StatusNode icon={Network} label="DNS" value={dns.dns_resolves ? 'RESOLVED' : 'FAILED'} detail={`${dns.ip_addresses.length} IPv4 addresses`} tone={dns.dns_resolves ? 'low' : 'high'} /><StatusNode icon={Server} label="HTTP" value={http.http_status || '—'} detail="Final response" tone="neutral" /><StatusNode icon={Activity} label="REDIRECTS" value={http.redirect_count} detail={http.redirect_count > 1 ? 'Multiple hops' : 'Stable route'} tone={http.redirect_count > 1 ? 'amber' : 'low'} /></div><div className="console-connector" /><DataGrid items={[["HTTPS status", bool(url.has_https, 'Enabled', 'Not enabled')], ["Final URL", http.final_url], ["Certificate issuer", ssl.certificate_issuer], ["Certificate subject", ssl.certificate_subject]]} /></DetailShell>
}

export function DomainPage({ result, onBack }) {
  const domain = result.domain_analysis
  return <DetailShell eyebrow="Domain intelligence" title={domain.domain_name} onBack={onBack}><DomainTimeline domain={domain} /><div className="domain-facts"><span>REGISTRAR<strong>{display(domain.registrar)}</strong></span><span>REMAINING<strong>{domain.registration_remaining_days == null ? 'DATA UNAVAILABLE' : `${domain.registration_remaining_days} DAYS`}</strong></span><span>NAMESERVERS<strong>{display(domain.name_servers?.join(', '))}</strong></span></div></DetailShell>
}

export function BrandPage({ result, onBack }) {
  const brand = result.brand_analysis
  return <DetailShell eyebrow="Brand intelligence" title="Brand & typosquatting" onBack={onBack}><BrandScanner brand={brand} url={result.normalized_url} />{brand.explanation && <p className="explanation-note">{brand.explanation}</p>}</DetailShell>
}

export function LexicalPage({ result, onBack }) {
  const lexical = result.lexical_analysis
  return <DetailShell eyebrow="Lexical intelligence" title="Domain language signals" onBack={onBack}><LexicalRadar lexical={lexical} subdomainCount={result.url_analysis.subdomain_count} hasPunycode={result.url_analysis.has_punycode} /><DataGrid items={[["Domain entropy", lexical.domain_entropy], ["Randomness score", `${lexical.domain_randomness_score}/100`], ["TLD risk", lexical.tld_risk_indicator], ["Digit ratio", lexical.domain_digit_ratio], ["Hyphen count", lexical.domain_hyphen_count], ["Suspicious path terms", lexical.suspicious_path_keywords?.join(', ')]]} /></DetailShell>
}

export function MLPage({ result, onBack }) {
  const ml = result.ml_analysis
  return <DetailShell eyebrow="Model inference" title="AI threat assessment" onBack={onBack}>{ml.model_available ? <div className="ai-console"><div className="ai-console-hero"><div className="ai-arc"><span>{ml.phishing_probability == null ? '—' : `${Math.round(ml.phishing_probability * 100)}%`}</span><small>{ml.prediction}</small></div></div><div className="probability-list"><Probability label="Phishing" value={ml.phishing_probability} warning /><Probability label="Legitimate" value={ml.legitimate_probability} /><div className="model-strip"><span>MODEL<strong>{ml.model_version || 'Unavailable'}</strong></span><span>THRESHOLD<strong>LOADED FROM MODEL</strong></span></div></div></div> : <div className="empty-state"><h2>Model unavailable</h2><p>{display(ml.error)}</p></div>}</DetailShell>
}

export function ExplainabilityPage({ result, onBack }) {
  const ml = result.ml_analysis
  const explanation = result.explainability
  const factors = [...(explanation?.top_risk_factors || []), ...(explanation?.top_trust_factors || [])]
  const maxImpact = Math.max(...factors.map((factor) => Math.abs(factor.impact)), 0.01)
  return <DetailShell eyebrow="Explainable machine learning" title="Why this result?" onBack={onBack}>
    <div className="explanation-hero"><div><span>PHISHING PROBABILITY</span><strong>{ml.phishing_probability == null ? 'Unavailable' : `${Math.round(ml.phishing_probability * 100)}%`}</strong></div><div><span>EXPLAINER</span><strong>{explanation?.method || 'Unavailable'}</strong></div></div>
    {explanation?.available ? <>
      <p className="explanation-intro">Why did the ML model predict this? These factors explain the model's phishing estimate only; technical and external reputation evidence are shown separately.</p>
      <ContributionGroup title="Factors increasing risk" factors={explanation.top_risk_factors} maxImpact={maxImpact} risk />
      <ContributionGroup title="Factors reducing risk" factors={explanation.top_trust_factors} maxImpact={maxImpact} />
      <div className="explanation-summary"><span>MODEL SUMMARY</span>{explanation.summary?.map((item) => <p key={item}>{item}</p>)}</div><div className="evidence-boundaries"><div><span>TECHNICAL EVIDENCE</span><p>SSL, DNS, HTTP, domain age, and page signals.</p></div><div><span>ML EVIDENCE</span><p>Feature contributions from the phishing model.</p></div><div><span>EXTERNAL REPUTATION</span><p>Independent provider records shown in the Reputation tab.</p></div></div>
    </> : <div className="empty-state"><h2>Explanation unavailable</h2><p>{explanation?.message || 'Model explanation is currently unavailable.'}</p></div>}
  </DetailShell>
}

export function ReputationPage({ result, onBack }) {
  const reputation = result.reputation_analysis
  const providers = [
    ['VirusTotal', reputation.providers.virustotal],
    ['Google Threat Check', reputation.providers.google_safe_browsing],
    ['URLhaus', reputation.providers.urlhaus],
  ]
  return <DetailShell eyebrow="External threat intelligence" title="Reputation signals" onBack={onBack}><div className="reputation-hero"><div><span>OVERALL REPUTATION RISK</span><strong>{reputation.reputation_risk_score}<small>/100</small></strong></div><div><span>CONFIDENCE</span><strong>{reputation.reputation_confidence}</strong><p>{reputation.providers_available} of {reputation.providers_checked} providers available</p></div></div><p className="explanation-intro">Blacklist absence is not proof of safety. These providers add independent external evidence and are kept separate from technical and ML signals.</p><div className="provider-grid">{providers.map(([name, provider]) => <ProviderCard key={name} name={name} provider={provider} />)}</div></DetailShell>
}

function ProviderCard({ name, provider = {} }) {
  const status = provider.status || 'lookup_failed'
  const statusLabel = { threat_found: 'THREAT FOUND', no_record: 'NO RECORD', available: 'CLEAR', not_configured: 'NOT CONFIGURED', rate_limited: 'TEMPORARILY UNAVAILABLE', invalid_key: 'CONFIGURATION ISSUE', lookup_failed: 'LOOKUP FAILED' }[status] || status.replaceAll('_', ' ').toUpperCase()
  return <motion.article className={`provider-card provider-${status}`} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}><div className="provider-card-head"><span>{name}</span><strong>{statusLabel}</strong></div>{name === 'VirusTotal' && <div className="provider-stats"><b>{provider.harmless ?? 0}<small>HARMLESS</small></b><b>{provider.suspicious ?? 0}<small>SUSPICIOUS</small></b><b>{provider.malicious ?? 0}<small>MALICIOUS</small></b></div>}{name === 'Google Threat Check' && <p>{provider.threat_detected ? `${provider.matches?.length || 0} threat match(es) detected.` : provider.message || 'No known threat match found.'}</p>}{name === 'URLhaus' && <p>{provider.message || provider.threat || 'No URLhaus threat record found.'}</p>}{provider.tags?.length > 0 && <p className="provider-tags">Tags: {provider.tags.join(', ')}</p>}{provider.message && name === 'VirusTotal' && <p>{provider.message}</p>}</motion.article>
}

export function AIInsightPage({ result, onBack }) {
  const [summary, setSummary] = useState(result.ai_summary)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let mounted = true
    setLoading(true)
    getAISummary(result.scan_id).then((value) => { if (mounted) setSummary(value) }).catch(() => {}).finally(() => { if (mounted) setLoading(false) })
    return () => { mounted = false }
  }, [result.scan_id])
  return <DetailShell eyebrow="AI evidence interpretation" title="TrustShield AI verdict" onBack={onBack}><div className="ai-verdict-head"><span>AI-GENERATED INTERPRETATION OF THE EVIDENCE</span>{loading && <strong>INTERPRETING EVIDENCE...</strong>}</div><section className="ai-summary-card"><span>SUMMARY</span><p>{summary?.summary}</p></section><div className="ai-insight-grid"><InsightList title="Main concerns" items={summary?.main_concerns} tone="concern" /><InsightList title="Positive evidence" items={summary?.positive_evidence} tone="positive" /></div><section className="ai-action-card"><span>RECOMMENDED ACTION</span><p>{summary?.recommended_action}</p></section><div className="ai-source-row">{(summary?.sources || []).map((source) => <span key={source}>{source}</span>)}</div></DetailShell>
}

function InsightList({ title, items = [], tone }) {
  return <section className={`ai-list ${tone}`}><h2>{title}</h2>{items.length ? items.map((item) => <p key={item}>{item}</p>) : <p>No material evidence recorded.</p>}</section>
}

export function AskTrustShieldPage({ result, onBack }) {
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [messages, setMessages] = useState([])
  const suggestions = ['Why is this risky?', 'Can I enter my password?', 'Can I make a payment?', 'Why did ML flag this?', 'What should I verify?']
  async function submitQuestion(value = question) {
    const trimmed = value.trim()
    if (!trimmed || loading) return
    setQuestion('')
    setMessages((current) => [...current, { role: 'user', text: trimmed }])
    setLoading(true)
    try {
      const answer = await askTrustShield(result.scan_id, trimmed)
      setMessages((current) => [...current, { role: 'assistant', text: answer.answer, fallback: answer.fallback_used }])
    } catch {
      setMessages((current) => [...current, { role: 'assistant', text: 'The assistant could not answer right now. Review the evidence tabs and verify the official domain independently.', fallback: true }])
    } finally {
      setLoading(false)
    }
  }
  return <DetailShell eyebrow="Evidence-grounded assistant" title="Ask TrustShield" onBack={onBack}><div className="ask-context"><span>CURRENTLY ANALYZING</span><strong>{result.normalized_url}</strong></div><div className="chat-window">{messages.length === 0 && <div className="chat-empty"><span>TRUSTSHIELD AI</span><p>Ask a short question about this scan. Answers stay tied to the current website evidence.</p></div>}{messages.map((message, index) => <div className={`chat-message ${message.role}`} key={`${message.role}-${index}`}><span>{message.role === 'user' ? 'YOU' : 'TRUSTSHIELD AI'}</span><p>{message.text}</p></div>)}{loading && <div className="chat-message assistant"><span>TRUSTSHIELD AI</span><p className="typing-indicator">INTERPRETING EVIDENCE...</p></div>}</div><div className="question-chips">{suggestions.map((suggestion) => <button key={suggestion} onClick={() => submitQuestion(suggestion)}>{suggestion}</button>)}</div><form className="ask-form" onSubmit={(event) => { event.preventDefault(); submitQuestion() }}><input value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about this website..." /><button type="submit" disabled={loading}>SEND</button></form></DetailShell>
}

function ContributionGroup({ title, factors, maxImpact, risk }) {
  return <section className={`contribution-group${risk ? ' risk' : ' trust'}`}><div className="section-heading compact"><h2>{title}</h2><span className="contribution-direction">{risk ? '0 → RISK' : 'TRUST ← 0'}</span></div>{factors.length ? factors.map((factor) => <div className="contribution-row" key={factor.feature}><div className="contribution-label"><strong>{factor.display_name}</strong><small>{factor.explanation}</small></div><div className="contribution-track"><motion.i initial={{ width: 0 }} animate={{ width: `${Math.max(4, Math.abs(factor.impact) / maxImpact * 50)}%` }} /><span /></div><b>{factor.impact > 0 ? '+' : ''}{factor.impact.toFixed(2)}</b></div>) : <p className="empty-contribution">No material factors in this direction.</p>}</section>
}

function Probability({ label, value, warning = false }) {
  const percentage = value == null ? 0 : Math.round(value * 100)
  return <div className="probability"><div><span>{label}</span><strong>{value == null ? 'Unavailable' : `${percentage}%`}</strong></div><div className="meter"><motion.i className={warning ? 'warning-meter' : ''} initial={{ width: 0 }} animate={{ width: `${percentage}%` }} /></div></div>
}

export function ContentPage({ result, onBack }) {
  const content = result.content_analysis
  return <DetailShell eyebrow="Website inspection" title="Website anatomy" onBack={onBack}><div className="anatomy-list">{[["PAGE TITLE", content.page_title, Globe2], ["META DESCRIPTION", content.meta_description, Code2], ["LOGIN FORM", bool(content.has_login_form), ShieldCheck], ["PASSWORD FIELD", bool(content.has_password_field), LockKeyhole], ["PAYMENT TERMS", bool(content.has_payment_keywords), Activity], ["INTERNAL LINKS", content.internal_links, Network], ["EXTERNAL LINKS", content.external_links, Globe2]].map(([label, value, Icon]) => <div className="anatomy-row" key={label}><Icon size={17} /><span>{label}</span><strong>{display(value)}</strong></div>)}</div></DetailShell>
}

export function SignalsPage({ result, onBack, warning = false }) {
  const title = warning ? 'Warning signals' : 'Positive signals'
  const signals = warning ? result.warning_signals : result.positive_signals
  return <DetailShell eyebrow="Explainable evidence" title={title} onBack={onBack}><div className="signal-timeline">{signals.length ? signals.map((signal, index) => <div className="timeline-event" key={signal}><span className="timeline-dot" /><span className="timeline-time">LIVE</span><SignalCard signal={signal} warning={warning} index={index} /></div>) : <div className="empty-state"><p>No signals recorded.</p></div>}</div></DetailShell>
}

export function RawDetailsPage({ result, onBack }) {
  return <DetailShell eyebrow="Developer details" title="Raw scan response" onBack={onBack}><div className="terminal-head"><Code2 size={16} /><span>TRUSTSHIELD // RAW TELEMETRY</span><button onClick={() => navigator.clipboard?.writeText(JSON.stringify(result, null, 2))}>COPY JSON</button></div><details className="json-details" open><summary>JSON PAYLOAD</summary><pre>{JSON.stringify(result, null, 2)}<span className="terminal-cursor">█</span></pre></details></DetailShell>
}




