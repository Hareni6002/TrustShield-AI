import { motion } from 'framer-motion'

const labels = ['Technical', 'Domain', 'Brand', 'Lexical', 'ML', 'Reputation']

export default function SecurityRadar({ values }) {
  const points = labels.map((_, index) => {
    const angle = -Math.PI / 2 + (Math.PI * 2 * index) / labels.length
    const radius = 76 * (Math.max(0, Math.min(100, values[index] || 0)) / 100)
    return `${120 + Math.cos(angle) * radius},${120 + Math.sin(angle) * radius}`
  }).join(' ')
  return <section className="security-radar-panel"><div className="visual-panel-head"><span>SECURITY RADAR</span><small>REAL SCAN SIGNALS</small></div><div className="security-radar"><svg viewBox="0 0 240 240" role="img" aria-label="Security risk radar"><polygon className="radar-ring" points="120,35 194,77 194,163 120,205 46,163 46,77" /><polygon className="radar-ring inner" points="120,65 168,92 168,148 120,175 72,148 72,92" /><line x1="120" y1="35" x2="120" y2="205" /><line x1="46" y1="77" x2="194" y2="163" /><line x1="46" y1="163" x2="194" y2="77" /><motion.polygon className="radar-signal-fill" points={points} initial={{ opacity: 0 }} animate={{ opacity: .72 }} transition={{ duration: .8 }} /><motion.circle className="radar-sweep-dot" cx="120" cy="120" r="4" animate={{ r: [3, 7, 3], opacity: [.5, 1, .5] }} transition={{ duration: 2, repeat: Infinity }} /></svg>{labels.map((label, index) => <span className={`security-radar-label radar-label-${index}`} key={label}>{label}</span>)}</div></section>
}




