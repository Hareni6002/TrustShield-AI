import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'

export default function TrustGauge({ score, onComplete }) {
  const [displayScore, setDisplayScore] = useState(0)
  const onCompleteRef = useRef(onComplete)
  const targetAngle = -90 + (score * 1.8)
  useEffect(() => { onCompleteRef.current = onComplete }, [onComplete])
  useEffect(() => {
    const start = window.setTimeout(() => {
      const interval = window.setInterval(() => setDisplayScore((value) => {
        if (value >= score) { window.clearInterval(interval); return score }
        return Math.min(score, value + Math.max(1, Math.ceil((score - value) / 9)))
      }), 24)
      return () => window.clearInterval(interval)
    }, 800)
    const finish = window.setTimeout(() => onCompleteRef.current(), 3300)
    return () => { window.clearTimeout(start); window.clearTimeout(finish) }
  }, [score])

  return <main className="gauge-screen">
    <p className="eyebrow">Signal synthesis</p>
    <h1>Calculating Trust Level</h1>
    <div className="gauge-wrap">
      <svg className="gauge-svg" viewBox="0 0 320 180" role="img" aria-label={`Trust score ${score} out of 100`}><defs><linearGradient id="riskGradient" x1="0" x2="1"><stop offset="0" stopColor="#8a6a35" /><stop offset="0.5" stopColor="#b28c4a" /><stop offset="1" stopColor="#a9a18f" /></linearGradient></defs><path d="M 30 160 A 130 130 0 0 1 290 160" fill="none" stroke="#29261f" strokeWidth="18" strokeLinecap="round" /><path d="M 30 160 A 130 130 0 0 1 290 160" fill="none" stroke="url(#riskGradient)" strokeWidth="4" strokeLinecap="round" /></svg>
      <div className="gauge-label left">HIGH RISK</div><div className="gauge-label center">CAUTION</div><div className="gauge-label right">TRUSTED</div>
      <motion.div className="gauge-needle" initial={{ rotate: -90 }} animate={{ rotate: [-90, 27, -34, 62, targetAngle] }} transition={{ duration: 2.7, ease: 'easeInOut', times: [0, 0.2, 0.42, 0.65, 1] }}><span /></motion.div>
      <div className="gauge-center"><span>TRUST SCORE</span><strong>{displayScore}<small>/100</small></strong></div>
    </div>
  </main>
}




