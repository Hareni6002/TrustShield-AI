import { motion } from 'framer-motion'

export default function ScoreReveal({ result, onView }) {
  return <main className="reveal-screen"><motion.div initial={{ scale: 0.75, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ duration: 0.65, ease: 'easeOut' }}><p className="eyebrow">Analysis complete</p><div className="reveal-score">{result.trustshield_score}<span>/100</span></div><h1>TRUSTSHIELD SCORE</h1><p className="risk-level-large">{result.trustshield_risk_level}</p><button className="primary-button" onClick={onView}>VIEW ANALYSIS <span>→</span></button></motion.div></main>
}
