import { useEffect, useState } from 'react'
import { Network as NetworkIcon } from 'lucide-react'
import { getNetwork } from '../services/api'
import PageTransition from '../components/PageTransition'

export default function NetworkPage({ result, onBack, onScanAgain }) {
  const domain = result?.domain_analysis?.domain_name || ''
  const [graph, setGraph] = useState(null)
  useEffect(() => { if (domain) getNetwork(domain).then(setGraph).catch(() => {}) }, [domain])
  const related = graph?.nodes?.filter((node) => node.id !== domain) || []
  return <PageTransition><main className="utility-page network-page"><button className="utility-back-button" type="button" onClick={onBack}>← BACK</button><p className="eyebrow">Related domain intelligence</p><h1>Scam Network</h1><p className="utility-intro">Observed infrastructure and lexical similarities from previously scanned domains. Relationships do not prove common ownership.</p>{!domain ? <div className="empty-state"><NetworkIcon size={28} /><p>Run a scan to inspect related stored domains.</p></div> : graph && graph.edges.length === 0 ? <div className="network-empty-state"><NetworkIcon size={34} /><h2>No related domains discovered yet</h2><p>Scan additional domains to build relationship intelligence.</p><button className="primary-button" onClick={() => onScanAgain()}>SCAN ANOTHER DOMAIN</button></div> : graph && <><div className="network-summary"><NetworkIcon size={18} /><span>{graph.nodes.length} observed domains · {graph.edges.length} relationships</span></div><div className="network-canvas"><svg className="network-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">{related.map((node, index) => { const angle = (index / Math.max(related.length, 1)) * Math.PI * 2; return <line key={node.id} x1="50" y1="50" x2={50 + Math.cos(angle) * 34} y2={50 + Math.sin(angle) * 34} /> })}</svg><div className="network-center"><strong>{domain}</strong><span>Current domain</span></div>{related.map((node, index) => { const angle = (index / Math.max(related.length, 1)) * Math.PI * 2; return <div className="network-node" key={node.id} style={{ left: `${50 + Math.cos(angle) * 34}%`, top: `${50 + Math.sin(angle) * 34}%` }}><strong>{node.id}</strong><span>Risk {node.risk}/100</span></div>})}{graph.edges.map((edge) => <div className="network-edge-label" key={`${edge.source}-${edge.target}-${edge.type}`}>{edge.type.replaceAll('_', ' ')} · {edge.confidence}%</div>)}</div><p className="network-note">Relationships indicate technical similarity, not proof of common ownership.</p></>}</main></PageTransition>
}




