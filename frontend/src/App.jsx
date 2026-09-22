import { useState } from 'react'
import axios from 'axios'
import './App.css'

const API_URL = 'http://127.0.0.1:8000'

function App() {
  const [url, setUrl] = useState('https://example.com')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function analyzeWebsite(event) {
    event.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const response = await axios.post(`${API_URL}/api/scan`, { url })
      setResult(response.data)
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'The website could not be analyzed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="app-shell">
      <section className="panel">
        <p className="eyebrow">Phase 1A · Technical Analysis</p>
        <h1>TrustShield AI</h1>
        <p className="intro">Analyze a public website URL using transparent technical signals.</p>
        <form className="scan-form" onSubmit={analyzeWebsite}>
          <label htmlFor="url">Website URL</label>
          <div className="input-row">
            <input id="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" />
            <button type="submit" disabled={loading}>{loading ? 'Analyzing…' : 'Analyze Website'}</button>
          </div>
        </form>
        {error && <p className="error">{error}</p>}
        {result && <ScanResult result={result} />}
      </section>
    </main>
  )
}

function ScanResult({ result }) {
  const { domain_analysis: domain, ssl_analysis: ssl, dns_analysis: dns, http_analysis: http, brand_analysis: brand, lexical_analysis: lexical } = result
  return (
    <section className="results" aria-live="polite">
      <div className="score-row">
        <div><span className="muted">URL</span><strong>{result.normalized_url}</strong></div>
        <div className="score"><span className="muted">Technical Trust Score</span><strong>{result.technical_trust_score}/100</strong></div>
      </div>
      <p className="risk-level">{result.risk_level}</p>
      <div className="columns">
        <SignalList title="Positive Signals" items={result.positive_signals} empty="No positive signals recorded." />
        <SignalList title="Warning Signals" items={result.warning_signals} empty="No warning signals recorded." warning />
      </div>
      <div className="intelligence-grid">
        <section className="intelligence-card">
          <h2>Brand Analysis</h2>
          <Fact label="Possible Brand" value={brand.detected_brand || 'None detected'} />
          <Fact label="Similarity" value={`${brand.brand_similarity_score}%`} />
          <Fact label="Impersonation" value={brand.possible_brand_impersonation ? 'Possible' : 'Not detected'} />
          <Fact label="Typosquatting" value={brand.possible_typosquatting ? 'Detected' : 'Not detected'} />
        </section>
        <section className="intelligence-card">
          <h2>Lexical Risk</h2>
          <Fact label="Score" value={`${lexical.lexical_risk_score}/100 ${lexical.lexical_risk_level}`} />
          <Fact label="TLD" value={`${lexical.tld || 'Unavailable'} · ${lexical.tld_risk_indicator}`} />
          <Fact label="Domain Entropy" value={lexical.domain_entropy} />
          <Fact label="Randomness" value={`${lexical.domain_randomness_score}/100`} />
          <Fact label="Suspicious Path" value={lexical.suspicious_path_keywords.join(', ') || 'None detected'} />
        </section>
      </div>
      <dl className="facts">
        <Fact label="Domain Age" value={domain.domain_age_days == null ? 'Unavailable' : `${domain.domain_age_days} days`} />
        <Fact label="SSL Status" value={ssl.ssl_valid ? 'Valid' : ssl.ssl_available ? 'Available, not verified' : 'Unavailable'} />
        <Fact label="DNS Status" value={dns.dns_resolves ? 'Resolves' : 'Unavailable'} />
        <Fact label="Redirect Count" value={http.redirect_count} />
        <Fact label="HTTP Status" value={http.http_status || 'Unavailable'} />
        <Fact label="Page Title" value={http.page_title || 'Unavailable'} />
      </dl>
    </section>
  )
}

function SignalList({ title, items, empty, warning = false }) {
  return <div className={warning ? 'signal-list warning-list' : 'signal-list'}>
    <h2>{title}</h2>
    {items.length ? <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul> : <p>{empty}</p>}
  </div>
}

function Fact({ label, value }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>
}

export default App
