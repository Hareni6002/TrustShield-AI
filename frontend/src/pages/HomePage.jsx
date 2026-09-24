import { motion } from 'framer-motion'
import { ArrowDownRight, LockKeyhole, ShieldCheck } from 'lucide-react'
import UrlScanner from '../components/UrlScanner'
import SecurityHeroVisual from '../components/SecurityHeroVisual'
import FeatureGrid from '../components/FeatureGrid'
import ProviderStatus from '../components/ProviderStatus'

export default function HomePage({ url, setUrl, onSubmit, error }) {
  return <main className="home-experience"><section className="home-command-hero"><div className="home-command-copy"><motion.p className="eyebrow" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>Website trust intelligence</motion.p><motion.h1 initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .12 }}>Know before<br /><em>you click.</em></motion.h1><motion.p className="hero-subtitle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .25 }}>AI-powered website intelligence for scam, phishing and reputation analysis.</motion.p><UrlScanner url={url} setUrl={setUrl} onSubmit={onSubmit} error={error} /><div className="home-command-meta"><span><LockKeyhole size={13} />Technical signals</span><span><ShieldCheck size={13} />Explainable results</span></div><ProviderStatus /></div><SecurityHeroVisual /></section><section className="home-scroll-cue"><ArrowDownRight size={16} /><span>EXPLORE THE INTELLIGENCE LAYER</span></section><FeatureGrid /><div className="home-footnote"><span className="status-dot" />Real-time analysis · Explainable signals · No browsing history stored</div></main>
}




