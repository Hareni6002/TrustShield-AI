import { motion } from 'framer-motion'

export default function PageTransition({ children, className = '' }) {
  return <motion.div className={className} initial={{ opacity: 0, y: 18, scale: 0.99 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: -12 }} transition={{ duration: 0.38, ease: 'easeOut' }}>{children}</motion.div>
}
