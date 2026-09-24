import { motion } from 'framer-motion'
import { BrainCircuit, Fingerprint, Globe2, Network, ShieldAlert, Sparkles } from 'lucide-react'

const features = [
  ['domain', 'DOMAIN INTELLIGENCE', 'Digital identity, lifecycle and infrastructure.', Globe2, 'tall'],
  ['ai', 'AI THREAT MODEL', 'Pattern recognition grounded in scan evidence.', BrainCircuit, 'small'],
  ['brand', 'BRAND PROTECTION', 'Spot impersonation before it reaches your inbox.', Fingerprint, 'small'],
  ['reputation', 'REPUTATION INTELLIGENCE', 'Independent threat sources, kept transparent.', ShieldAlert, 'wide'],
  ['network', 'SCAM NETWORK', 'Observed infrastructure and lexical relationships.', Network, 'wide'],
  ['explain', 'EXPLAINABLE SECURITY', 'Every signal has a reason and a boundary.', Sparkles, 'small'],
]

export default function FeatureGrid() {
  return <section className="feature-explorer"><div className="feature-section-head"><div><p className="eyebrow">Signal architecture</p><h2>What TrustShield checks</h2></div><span>EXPLORE THE INTELLIGENCE LAYER</span></div><div className="feature-grid">{features.map(([id, title, copy, Icon, size]) => <motion.article className={`feature-tile ${size}`} key={id} whileHover={{ y: -5 }}><div className={`feature-tile-visual feature-visual-${id}`}>{id === 'domain' && <div className="feature-orbit"><Globe2 size={50} /><i /><i /><i /></div>}{id === 'ai' && <div className="feature-neural">{[1, 2, 3, 4, 5].map((item) => <i key={item} />)}</div>}{id === 'brand' && <div className="brand-diff"><b>PAYPAL</b><span>PAYPA<span>1</span></span></div>}{id === 'reputation' && <div className="provider-dots"><i>VT</i><i>GS</i><i>UH</i><b>TRUST</b></div>}{id === 'network' && <div className="network-preview"><i /><i /><i /><b /></div>}{id === 'explain' && <div className="explain-flow"><span>RISK</span><b>↓</b><strong>AI</strong></div>}</div><div className="feature-tile-copy"><Icon size={16} /><div><h3>{title}</h3><p>{copy}</p></div><span className="feature-arrow">↗</span></div></motion.article>)}</div></section>
}




