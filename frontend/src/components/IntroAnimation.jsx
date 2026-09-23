import { motion } from 'framer-motion'

export default function IntroAnimation({ onComplete }) {
  return <motion.section className="intro-screen" initial={{ opacity: 1 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.7 }} onAnimationComplete={() => setTimeout(onComplete, 2600)}>
    <div className="intro-orb" />
    <motion.div className="intro-light" initial={{ x: '-120%', opacity: 0 }} animate={{ x: '120%', opacity: [0, 0.8, 0] }} transition={{ duration: 2.1, ease: 'easeInOut' }} />
    <div className="intro-lockup">
      <motion.div className="intro-logo" initial={{ opacity: 0, scale: 1.12, letterSpacing: '0.55em' }} animate={{ opacity: 1, scale: 1, letterSpacing: '0.18em' }} transition={{ duration: 1.1, delay: 0.35, ease: 'easeOut' }}>TRUSTSHIELD</motion.div>
      <motion.div className="intro-ai" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, delay: 1.15 }}>AI</motion.div>
      <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.8, delay: 1.55 }}>Know Before You Trust</motion.p>
    </div>
  </motion.section>
}
