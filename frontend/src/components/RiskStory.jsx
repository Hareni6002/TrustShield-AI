import { ArrowDown, CircleCheck, TriangleAlert } from 'lucide-react'

export default function RiskStory({ result }) {
  const positives = result.positive_signals || []
  const warnings = result.warning_signals || []
  const items = (warnings.length ? warnings : positives).slice(0, 3)
  const positiveMode = !warnings.length
  return <section className="risk-story-panel"><div className="visual-panel-head"><span>WHY THIS SCORE?</span><small>EVIDENCE STORY</small></div><div className="risk-story-list">{items.length ? items.map((item, index) => <div className="risk-story-step" key={item}><div className={positiveMode ? 'story-icon positive' : 'story-icon'}>{positiveMode ? <CircleCheck size={16} /> : <TriangleAlert size={16} />}</div><div><small>0{index + 1}</small><strong>{item}</strong></div>{index < items.length - 1 && <ArrowDown className="story-arrow" size={15} />}</div>) : <p className="visual-empty">No material evidence recorded yet.</p>}</div><div className="story-result"><span>FINAL TRUST SCORE</span><strong>{result.trustshield_score}<small>/100</small></strong><em>{result.trustshield_risk_level}</em></div></section>
}




