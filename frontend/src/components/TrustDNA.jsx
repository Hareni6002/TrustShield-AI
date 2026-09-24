import { motion } from 'framer-motion'

export default function TrustDNA({ signals }) {
  return <section className="trust-dna-panel"><div className="visual-panel-head"><span>TRUST DNA</span><small>SECURITY FINGERPRINT</small></div><div className="dna-wave" aria-label="Trust DNA signal fingerprint">{signals.map((signal, index) => <motion.i key={signal.label} style={{ height: `${Math.max(8, signal.value)}%` }} animate={{ opacity: [.45, 1, .45] }} transition={{ duration: 2, delay: index * .12, repeat: Infinity }} />)}</div><div className="dna-legend">{signals.map((signal) => <div key={signal.label}><span>{signal.label}</span><b>{signal.value}</b></div>)}</div></section>
}




