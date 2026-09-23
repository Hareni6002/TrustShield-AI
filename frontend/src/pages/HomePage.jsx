import { motion } from 'framer-motion'
import UrlScanner from '../components/UrlScanner'

export default function HomePage({ url, setUrl, onSubmit, error }) {
  return <main className="home-page">
    <div className="hero-copy"><motion.p className="eyebrow" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>Website trust intelligence</motion.p><motion.h1 initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.12 }}>Think Before<br /><em>You Trust.</em></motion.h1><motion.p className="hero-subtitle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.25 }}>Analyze any website using technical intelligence, domain signals, lexical risk analysis and AI-powered scam detection.</motion.p></div>
    <UrlScanner url={url} setUrl={setUrl} onSubmit={onSubmit} error={error} />
    <div className="home-footnote"><span className="status-dot" />Real-time analysis · Explainable signals · No browsing history stored</div>
  </main>
}
