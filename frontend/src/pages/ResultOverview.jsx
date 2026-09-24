import { useState } from 'react'
import { Activity, Brain, Clipboard, Download, Fingerprint, Globe2, ShieldAlert, ShieldCheck } from 'lucide-react'
import { MatrixRow, SignalConflict, TrustScoreRing } from '../components/Visuals'
import SecurityRadar from '../components/SecurityRadar'
import TrustDNA from '../components/TrustDNA'
import RiskStory from '../components/RiskStory'
import { downloadScanReport } from '../services/api'

const percent = (value) => value == null ? 'Unavailable' : `${Math.round(value * 100)}%`
const valueOrUnavailable = (value) => value == null || value === '' ? 'Unavailable' : value

export default function ResultOverview({ result, onDetail, onNewScan, onCommunity }) {
  const domain = result.domain_analysis
  const brand = result.brand_analysis
  const lexical = result.lexical_analysis
  const ml = result.ml_analysis
  const domainRisk = domain.domain_age_days == null ? 0 : Math.max(0, Math.round(100 - Math.min(100, Math.log10(domain.domain_age_days + 1) * 25)))
  const brandRisk = brand.possible_brand_impersonation ? Math.max(brand.brand_similarity_score || 0, 70) : 0
  const radarValues = [100 - result.technical_trust_score, domainRisk, brandRisk, lexical.lexical_risk_score, ml.phishing_probability == null ? 0 : Math.round(ml.phishing_probability * 100), result.reputation_analysis.reputation_risk_score]
  const dnaSignals = [{ label: 'Technical', value: result.technical_trust_score }, { label: 'Domain', value: 100 - domainRisk }, { label: 'Brand', value: 100 - brandRisk }, { label: 'Lexical', value: 100 - lexical.lexical_risk_score }, { label: 'ML', value: ml.phishing_probability == null ? 0 : Math.round((1 - ml.phishing_probability) * 100) }, { label: 'Reputation', value: 100 - result.reputation_analysis.reputation_risk_score }]
  const [reportLoading, setReportLoading] = useState(false)
  const [reportMessage, setReportMessage] = useState('')

  async function handleReportDownload() {
    setReportLoading(true)
    setReportMessage('')
    try {
      await downloadScanReport(result.scan_id)
      setReportMessage('REPORT READY')
    } catch {
      setReportMessage('REPORT UNAVAILABLE')
    } finally {
      setReportLoading(false)
    }
  }

  async function copySummary() {
    const warnings = (result.warning_signals || []).slice(0, 3).map((signal) => `- ${signal}`).join('\n') || '- None recorded'
    const positives = (result.positive_signals || []).slice(0, 3).map((signal) => `- ${signal}`).join('\n') || '- None recorded'
    const summary = `TrustShield AI\nDomain: ${domain.domain_name}\nTrustShield Score: ${result.trustshield_score}/100\nRisk Level: ${result.trustshield_risk_level}\n\nTop warnings:\n${warnings}\n\nTop positives:\n${positives}`
    try {
      await navigator.clipboard.writeText(summary)
      setReportMessage('SUMMARY COPIED')
    } catch {
      setReportMessage('COPY UNAVAILABLE')
    }
  }
  return <main className="results-page">
    <button className="report-site-button" onClick={onCommunity}>REPORT THIS WEBSITE</button>
    <section className="overview-visual-suite"><SecurityRadar values={radarValues} /><TrustDNA signals={dnaSignals} /><RiskStory result={result} /></section>
    <div className="result-heading"><div><p className="eyebrow">Scan overview</p><h1>{domain.domain_name}</h1><div className="result-url-row"><p className="result-url">{result.normalized_url}</p><a className="visit-button" href={result.normalized_url} target="_blank" rel="noopener noreferrer">VISIT ↗</a></div></div><div className="result-actions"><button className="outline-button" onClick={copySummary}><Clipboard size={14} /> COPY SUMMARY</button><button className="primary-button" onClick={handleReportDownload} disabled={reportLoading}><Download size={14} /> {reportLoading ? "GENERATING..." : "DOWNLOAD REPORT"}</button><button className="outline-button" onClick={onNewScan}>SCAN ANOTHER WEBSITE</button></div></div>{reportMessage && <p className="report-status" role="status">{reportMessage}</p>}
    <section className="overview-hero"><div className="hero-score-side"><TrustScoreRing score={result.trustshield_score} riskLevel={result.trustshield_risk_level} /></div><div className="intelligence-matrix"><div className="matrix-heading"><span>TRUSTSHIELD INTELLIGENCE MATRIX</span><small>FUSED SIGNAL SYNTHESIS</small></div><MatrixRow icon={ShieldCheck} label="Technical Security" value={`${result.technical_trust_score}%`} detail={result.risk_level} progress={result.technical_trust_score} onClick={() => onDetail('technical')} /><MatrixRow icon={Globe2} label="Domain Intelligence" value={domain.domain_age_days == null ? 'UNKNOWN' : domain.domain_age_days > 365 ? 'ESTABLISHED' : 'NEW'} detail={domain.domain_age_days == null ? 'Age unavailable' : `${domain.domain_age_days} days old`} tone="amber" onClick={() => onDetail('domain')} /><MatrixRow icon={Fingerprint} label="Brand Risk" value={brand.possible_brand_impersonation ? 'POSSIBLE' : 'LOW'} detail={brand.detected_brand ? `${brand.detected_brand} signal` : 'No brand match'} tone={brand.possible_brand_impersonation ? 'amber' : 'green'} progress={brand.possible_brand_impersonation ? 72 : 8} onClick={() => onDetail('brand')} /><MatrixRow icon={Activity} label="Lexical Risk" value={`${lexical.lexical_risk_score}/100`} detail={lexical.lexical_risk_level} tone="amber" progress={lexical.lexical_risk_score} onClick={() => onDetail('lexical')} /><MatrixRow icon={Brain} label="ML Phishing Risk" value={percent(ml.phishing_probability)} detail={valueOrUnavailable(ml.prediction)} tone="red" progress={ml.phishing_probability == null ? 0 : ml.phishing_probability * 100} onClick={() => onDetail('ml')} /><MatrixRow icon={ShieldAlert} label="External Reputation" value={`${result.reputation_analysis.reputation_risk_score}/100`} detail={`${result.reputation_analysis.reputation_level} · ${result.reputation_analysis.reputation_confidence} CONFIDENCE`} tone={result.reputation_analysis.reputation_risk_score >= 35 ? 'red' : 'green'} progress={result.reputation_analysis.reputation_risk_score} onClick={() => onDetail('reputation')} /></div></section>
    <SignalConflict signalConflict={result.signal_conflict || ml.signal_conflict} conflictMessage={result.conflict_message || ml.conflict_message} technical={result.technical_trust_score} phishing={ml.phishing_probability} reputationRisk={result.reputation_analysis.reputation_risk_score} threatSources={result.reputation_analysis.threat_sources} onOpen={() => onDetail(result.reputation_analysis.threat_sources ? 'reputation' : 'ml')} />
    <div className="section-heading"><div><span className="eyebrow">Signal summary</span><h2>What we found</h2></div><button className="text-button" onClick={() => onDetail('signals')}>VIEW ALL SIGNALS ↗</button></div>
    <section className="overview-lower"><div><div className="section-heading compact"><h2>Positive signals</h2><button className="text-button" onClick={() => onDetail('positive')}>VIEW ALL ↗</button></div>{(result.positive_signals || []).slice(0, 3).map((signal) => <p className="mini-signal positive-line" key={signal}>✓ {signal}</p>)}</div><div><div className="section-heading compact"><h2>Warning signals</h2><button className="text-button" onClick={() => onDetail('warning')}>VIEW ALL ↗</button></div>{(result.warning_signals || []).slice(0, 3).map((signal) => <p className="mini-signal warning-line" key={signal}>! {signal}</p>)}</div></section>
  </main>
}








