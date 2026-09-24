import { motion } from 'framer-motion'
import { BrainCircuit, Globe2, LockKeyhole, Radar, ShieldCheck, Waypoints } from 'lucide-react'

const signals = [
  ['SSL', LockKeyhole, -28, -34], ['DNS', Waypoints, -42, 8], ['AI', BrainCircuit, 35, -36],
  ['ML', Radar, 44, 11], ['REPUTATION', Globe2, -26, 43],
]

export default function SecurityHeroVisual() {
  return <div className="security-hero-visual" aria-label="TrustShield security intelligence visualization" role="img"><div className="hero-grid" /><svg className="hero-connections" viewBox="0 0 520 440" aria-hidden="true">{signals.map(([label, Icon, x, y]) => <line key={label} x1="260" y1="220" x2={260 + x * 4} y2={220 + y * 4} />)}</svg><div className="hero-orbit orbit-one" /><div className="hero-orbit orbit-two" /><motion.div className="hero-shield" animate={{ boxShadow: ['0 0 25px rgba(214,173,85,.24)', '0 0 65px rgba(214,173,85,.55)', '0 0 25px rgba(214,173,85,.24)'] }} transition={{ duration: 3, repeat: Infinity }}><ShieldCheck size={48} strokeWidth={1.2} /><span>TRUST<br />SHIELD</span></motion.div>{signals.map(([label, Icon, x, y], index) => <motion.div className="hero-signal" key={label} style={{ transform: `translate(${x * 4}px, ${y * 4}px)` }} animate={{ y: [0, -4, 0], opacity: [.72, 1, .72] }} transition={{ duration: 2.8, delay: index * .25, repeat: Infinity }}><Icon size={15} /><span>{label}</span></motion.div>)}<span className="hero-particle particle-one" /><span className="hero-particle particle-two" /><span className="hero-particle particle-three" /></div>
}




