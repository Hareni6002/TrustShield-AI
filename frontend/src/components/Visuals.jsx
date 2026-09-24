import { AlertTriangle, Fingerprint } from 'lucide-react'
import { motion } from 'framer-motion'

export function TrustScoreRing({ score, riskLevel }) {
  const radius = 104
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference
  const tone = score >= 70 ? 'low' : score >= 40 ? 'medium' : 'high'
  return <div className={`trust-ring ${tone}`}>
    <svg viewBox="0 0 240 240" aria-label={`Trust score ${score} out of 100`} role="img"><circle className="ring-track" cx="120" cy="120" r={radius} /><motion.circle className="ring-progress" cx="120" cy="120" r={radius} strokeDasharray={circumference} initial={{ strokeDashoffset: circumference }} animate={{ strokeDashoffset: offset }} transition={{ duration: 1.2, ease: 'easeOut' }} /></svg>
    <div className="ring-content"><span>TRUST SCORE</span><strong>{score}<small>/100</small></strong><em>{riskLevel}</em></div>
    <div className="ring-orbit" />
  </div>
}

export function MatrixRow({ icon: Icon, label, value, detail, tone = 'red', progress, onClick }) {
  return <motion.button className="matrix-row" onClick={onClick} whileHover={{ x: 5 }}><span className={`matrix-icon ${tone}`}><Icon size={16} strokeWidth={1.8} /></span><span className="matrix-label"><b>{label}</b><small>{detail}</small></span>{progress != null && <span className="matrix-meter"><i style={{ width: `${progress}%` }} /></span>}<strong>{value}</strong><span className="matrix-arrow">↗</span></motion.button>
}

export function SignalConflict({ signalConflict, conflictMessage, technical, phishing, reputationRisk, threatSources, onOpen }) {
  if (!signalConflict) return null
  return <motion.section className="conflict-panel" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}><div className="conflict-title"><AlertTriangle size={17} /><span>SIGNAL CONFLICT DETECTED</span></div><div className="conflict-split"><div><small>TECHNICAL EVIDENCE</small><strong>{technical}</strong><em>LOW RISK</em></div><b>VS</b><div><small>ML MODEL</small><strong>{Math.round(phishing * 100)}%</strong><em>ELEVATED RISK</em></div></div><p>Different signals are pointing in different directions. Further verification is recommended.</p><button onClick={onOpen}>VIEW ML ANALYSIS ↗</button></motion.section>
}

export function StatusNode({ icon: Icon, label, value, detail, tone = 'neutral' }) {
  return <motion.div className={`status-node ${tone}`} whileHover={{ y: -4 }}><div className="node-icon"><Icon size={20} strokeWidth={1.5} /></div><span>{label}</span><strong>{value}</strong><small>{detail}</small></motion.div>
}

export function DomainTimeline({ domain }) {
  return <div className="domain-lifecycle"><div className="lifecycle-top"><span>CREATION DATE</span><strong>{domain.creation_date ? new Date(domain.creation_date).toLocaleDateString() : 'DATA UNAVAILABLE'}</strong></div><div className="lifecycle-line"><i /><b>DOMAIN LIFETIME</b><span /></div><div className="lifecycle-age"><strong>{domain.domain_age_days == null ? '—' : domain.domain_age_days.toLocaleString()}</strong><span>DAYS OLD</span></div><div className="lifecycle-bottom"><span>EXPIRATION DATE</span><strong>{domain.expiration_date ? new Date(domain.expiration_date).toLocaleDateString() : 'DATA UNAVAILABLE'}</strong></div></div>
}

export function BrandScanner({ brand, url }) {
  const tone = brand.possible_brand_impersonation ? 'high' : 'low'
  return <div className="brand-scanner"><div className="brand-scanner-core"><Fingerprint size={22} /><span>DETECTED BRAND</span><strong>{brand.detected_brand || 'NO MATCH'}</strong><div className={`similarity-ring ${tone}`}><span>{brand.brand_similarity_score}%</span><small>SIMILARITY</small></div></div><div className="brand-checks"><Check label="Official domain match" value={!brand.possible_brand_impersonation && Boolean(brand.detected_brand)} /><Check label="Typosquatting" value={brand.possible_typosquatting} warning /><Check label="Misleading subdomain" value={brand.misleading_subdomain_detected} warning /><Check label="Homoglyph risk" value={brand.possible_homoglyph_impersonation} warning /></div>{brand.possible_brand_impersonation && <div className="domain-comparison"><div><span>ENTERED DOMAIN</span><strong>{url}</strong></div><b>VS</b><div><span>POSSIBLE TARGET</span><strong>{brand.legitimate_domains?.[0] || 'Unavailable'}</strong></div></div>}</div>
}

function Check({ label, value, warning }) {
  return <div className="brand-check"><span className={value ? warning ? 'check-icon warning' : 'check-icon active' : 'check-icon'}>{value ? warning ? '!' : '✓' : '—'}</span><span>{label}</span><strong>{value ? warning ? 'Possible' : 'Match' : 'Not detected'}</strong></div>
}

export function LexicalRadar({ lexical, subdomainCount, hasPunycode }) {
  const values = [Math.min(100, lexical.domain_entropy * 20), lexical.domain_randomness_score, Math.min(100, lexical.domain_digit_ratio * 100), Math.min(100, lexical.domain_hyphen_count * 25), Math.min(100, subdomainCount * 22), Math.min(100, lexical.suspicious_path_keywords.length * 24)]
  const points = values.map((value, index) => { const angle = -Math.PI / 2 + (Math.PI * 2 * index) / values.length; const radius = 84 * (value / 100); return `${120 + Math.cos(angle) * radius},${120 + Math.sin(angle) * radius}` }).join(' ')
  return <div className="lexical-visual"><svg viewBox="0 0 240 240" role="img" aria-label="Lexical signal radar"><polygon className="radar-grid" points="120,36 193,78 193,162 120,204 47,162 47,78" /><polygon className="radar-grid inner" points="120,64 169,92 169,148 120,176 71,148 71,92" /><motion.polygon className="radar-fill" points={points} initial={{ opacity: 0, scale: .5 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: .8 }} /><circle cx="120" cy="120" r="4" className="radar-dot" /></svg><div className="radar-center"><span>LEXICAL RISK</span><strong>{lexical.lexical_risk_score}</strong><small>{lexical.lexical_risk_level}</small></div><div className="radar-label entropy">ENTROPY</div><div className="radar-label random">RANDOMNESS</div><div className="radar-label digits">DIGITS</div><div className="radar-label path">PATH RISK</div><div className="radar-label subs">SUBDOMAINS</div><div className="radar-label hyphen">HYPHENS</div><p className="radar-footnote">Punycode: {hasPunycode ? 'Detected' : 'Not detected'}</p></div>
}




