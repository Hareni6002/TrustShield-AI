import { useState } from 'react'
import {
  BadgeCheck,
  Brain,
  Bot,
  ChevronLeft,
  ChevronRight,
  Code2,
  FileSearch,
  Fingerprint,
  Globe2,
  History,
  LayoutDashboard,
  Menu,
  MessageSquareText,
  Network,
  Radar,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  Users,
  X,
} from 'lucide-react'

const groups = [
  { label: 'SCAN SUMMARY', items: [['overview', 'Overview', LayoutDashboard]] },
  { label: 'CORE ANALYSIS', items: [['technical', 'Technical', ShieldCheck], ['domain', 'Domain', Globe2], ['brand', 'Brand & Typosquatting', Fingerprint], ['lexical', 'Lexical Analysis', Radar]] },
  { label: 'AI INTELLIGENCE', items: [['ml', 'Machine Learning', Brain], ['explainability', 'AI Explanation', ScanSearch], ['ai-insight', 'AI Insight', Bot], ['ask', 'Ask TrustShield', MessageSquareText]] },
  { label: 'THREAT INTELLIGENCE', items: [['reputation', 'Reputation', ShieldAlert]] },
  { label: 'CONTENT', items: [['content', 'Website Content', FileSearch]] },
  { label: 'EVIDENCE', items: [['positive', 'Positive Signals', BadgeCheck], ['warning', 'Warning Signals', TriangleAlert]] },
  { label: 'DEVELOPER', items: [['raw', 'Raw Details', Code2]] },
  { label: 'COMMUNITY', items: [['history', 'Scan History', History], ['community', 'Community Intelligence', Users], ['network', 'Scam Network', Network]] },
]

export default function AnalysisSidebar({ activeTab, result, onSelect, onNewScan }) {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('trustshield-sidebar-collapsed') === 'true')
  const [drawerOpen, setDrawerOpen] = useState(false)

  function toggleCollapsed() {
    setCollapsed((current) => {
      const next = !current
      localStorage.setItem('trustshield-sidebar-collapsed', String(next))
      return next
    })
  }

  function selectItem(id) {
    onSelect(id)
    setDrawerOpen(false)
  }

  const target = result?.domain_analysis?.domain_name || result?.normalized_url || 'Unavailable'
  const score = result?.trustshield_score ?? '—'
  const showLabels = !collapsed || drawerOpen

  return <>
    <button className="analysis-menu-button" type="button" onClick={() => setDrawerOpen(true)} aria-label="Open analysis navigation"><Menu size={19} /></button>
    {drawerOpen && <button className="sidebar-scrim" type="button" onClick={() => setDrawerOpen(false)} aria-label="Close analysis navigation" />}
    <aside className={`analysis-sidebar${collapsed ? ' collapsed' : ''}${drawerOpen ? ' drawer-open' : ''}`} aria-label="Scan analysis navigation">
      <div className="sidebar-topline"><span>{showLabels && 'SCAN ANALYSIS'}</span><button className="sidebar-collapse" type="button" onClick={toggleCollapsed} aria-label={collapsed ? 'Expand analysis navigation' : 'Collapse analysis navigation'} title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>{collapsed ? <ChevronRight size={17} /> : <ChevronLeft size={17} />}</button><button className="sidebar-close" type="button" onClick={() => setDrawerOpen(false)} aria-label="Close analysis navigation"><X size={18} /></button></div>
      <nav className="analysis-nav">
        {groups.map((group) => <section className="analysis-nav-group" key={group.label}><span className="analysis-nav-label">{showLabels && group.label}</span>{group.items.map(([id, label, Icon]) => <button key={id} type="button" className={`analysis-nav-item${activeTab === id ? ' active' : ''}`} onClick={() => selectItem(id)} title={!showLabels ? label : undefined} aria-label={label} aria-current={activeTab === id ? 'page' : undefined}><Icon size={17} strokeWidth={1.8} /><span>{showLabels && label}</span>{activeTab === id && <i aria-hidden="true" />}</button>)}</section>)}
      </nav>
      <div className="sidebar-footer">
        {showLabels && <div className="sidebar-target"><span>CURRENT TARGET</span><strong title={target}>{target}</strong><small>TrustShield Score <b>{score}/100</b></small></div>}
        <button className="sidebar-new-scan" type="button" onClick={onNewScan} title="Scan another website"><span aria-hidden="true">+</span>{showLabels && 'NEW SCAN'}</button>
      </div>
    </aside>
  </>
}




