import { motion } from 'framer-motion'

export default function MetricCard({ label, value, detail, accent = 'red', onClick }) {
  return <motion.button className={`metric-card ${accent}`} whileHover={{ y: -4, borderColor: 'rgba(238, 37, 49, .55)' }} onClick={onClick}><span>{label}</span><strong>{value}</strong><small>{detail}</small><i>↗</i></motion.button>
}
