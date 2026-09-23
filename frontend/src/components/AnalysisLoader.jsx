import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'

const STAGES = ['Validating URL', 'Inspecting Domain', 'Checking SSL Certificate', 'Resolving DNS', 'Analyzing Redirects', 'Inspecting Website Structure', 'Detecting Brand Impersonation', 'Measuring Lexical Risk', 'Running Machine Learning Model', 'Calculating Trust Score']

export default function AnalysisLoader({ url }) {
  const [activeStage, setActiveStage] = useState(0)
  useEffect(() => {
    const timer = window.setInterval(() => setActiveStage((value) => Math.min(STAGES.length - 1, value + 1)), 300)
    return () => window.clearInterval(timer)
  }, [])
  return <main className="analysis-screen">
    <div className="scan-radar"><span /><i /></div>
    <p className="eyebrow">Live intelligence scan</p>
    <h1>Analyzing Website</h1>
    <p className="scan-target">{url}</p>
    <div className="stage-list">
      {STAGES.map((stage, index) => <motion.div className={index < activeStage ? 'stage-row complete' : index === activeStage ? 'stage-row active' : 'stage-row'} key={stage} initial={{ opacity: 0.25 }} animate={{ opacity: index === activeStage ? [0.45, 1, 0.45] : index < activeStage ? 0.8 : 0.25 }} transition={{ duration: 1.2, repeat: index === activeStage ? Infinity : 0 }}><span className="stage-icon">{index < activeStage ? '✓' : index === activeStage ? '•' : '○'}</span>{stage}<span className="stage-line" /></motion.div>)}
    </div>
  </main>
}
