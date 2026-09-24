import { motion } from 'framer-motion'

export default function SignalCard({ signal, warning = false, index = 0 }) {
  return <motion.div className={warning ? 'signal-card warning' : 'signal-card positive'} initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.06 }}><span>{warning ? '!' : '✓'}</span><p>{signal}</p></motion.div>
}




