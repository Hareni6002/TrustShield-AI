import { useState } from 'react'
import { AnimatePresence } from 'framer-motion'
import './App.css'
import Navbar from './components/Navbar'
import AnalysisSidebar from './components/AnalysisSidebar'
import IntroAnimation from './components/IntroAnimation'
import TrustGauge from './components/TrustGauge'
import ScoreReveal from './components/ScoreReveal'
import PageTransition from './components/PageTransition'
import { scanWebsite } from './services/api'
import HomePage from './pages/HomePage'
import ScanningPage from './pages/ScanningPage'
import ResultOverview from './pages/ResultOverview'
import HistoryPage from './pages/HistoryPage'
import CommunityPage from './pages/CommunityPage'
import NetworkPage from './pages/NetworkPage'
import { getHistoryResult } from './services/api'
import { TechnicalPage, DomainPage, BrandPage, LexicalPage, MLPage, ExplainabilityPage, ReputationPage, AIInsightPage, AskTrustShieldPage, ContentPage, SignalsPage, RawDetailsPage } from './pages/DetailPages'

const MIN_SCAN_TIME = 2600

function App() {
  const [introVisible, setIntroVisible] = useState(() => sessionStorage.getItem('trustshield-intro-seen') !== 'true')
  const [screen, setScreen] = useState(() => introVisible ? 'intro' : 'home')
  const [url, setUrl] = useState('')
  const [activeUrl, setActiveUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('overview')

  function finishIntro() {
    sessionStorage.setItem('trustshield-intro-seen', 'true')
    setIntroVisible(false)
    setScreen('home')
  }

  function resetToHome(nextUrl = '') {
    setScreen('home')
    setResult(null)
    setError('')
    setActiveTab('overview')
    if (nextUrl) setUrl(nextUrl)
  }

  function validateInput(value) {
    const candidate = value.trim().includes('://') ? value.trim() : `https://${value.trim()}`
    try {
      const parsed = new URL(candidate)
      if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return 'Enter a valid http or https URL.'
      if (!parsed.hostname.includes('.') && !/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) return 'Enter a complete domain, such as example.com.'
      return ''
    } catch {
      return 'Enter a valid website URL.'
    }
  }

  async function handleScan(event) {
    event.preventDefault()
    const validationError = validateInput(url)
    if (validationError) { setError(validationError); return }
    setError('')
    setActiveUrl(url.trim())
    setScreen('scanning')
    const startedAt = Date.now()
    try {
      const [scanResult] = await Promise.all([scanWebsite(url.trim()), new Promise((resolve) => setTimeout(resolve, Math.max(0, MIN_SCAN_TIME - (Date.now() - startedAt))))])
      setResult(scanResult)
      setActiveTab('overview')
      setScreen('gauge')
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'We could not complete the website scan.')
      setScreen('error')
    }
  }

  function openDetail(tab) {
    setActiveTab(tab)
  }

  function navigateAnalysis(item) {
    if (item === 'history' || item === 'community' || item === 'network') {
      setScreen(item)
      return
    }
    setScreen('results')
    setActiveTab(item)
  }

  function openCommunity() {
    setScreen('community')
  }

  async function openHistoryResult(historyId) {
    try {
      const scanResult = await getHistoryResult(historyId)
      setResult(scanResult)
      setActiveTab('overview')
      setScreen('results')
    } catch {
      setError('The full scan result is no longer available. Run a new scan instead.')
      setScreen('error')
    }
  }

  function renderResults() {
    if (activeTab === 'overview') return <ResultOverview result={result} onDetail={openDetail} onNewScan={resetToHome} onCommunity={openCommunity} />
    const props = { result, onBack: () => setActiveTab('overview') }
    if (activeTab === 'technical') return <TechnicalPage {...props} />
    if (activeTab === 'domain') return <DomainPage {...props} />
    if (activeTab === 'brand') return <BrandPage {...props} />
    if (activeTab === 'lexical') return <LexicalPage {...props} />
    if (activeTab === 'ml') return <MLPage {...props} />
    if (activeTab === 'explainability') return <ExplainabilityPage {...props} />
    if (activeTab === 'reputation') return <ReputationPage {...props} />
    if (activeTab === 'ai-insight') return <AIInsightPage {...props} />
    if (activeTab === 'ask') return <AskTrustShieldPage {...props} />
    if (activeTab === 'content') return <ContentPage {...props} />
    if (activeTab === 'positive') return <SignalsPage {...props} />
    if (activeTab === 'warning') return <SignalsPage {...props} warning />
    return <RawDetailsPage {...props} />
  }

  if (introVisible) return <AnimatePresence mode="wait"><IntroAnimation onComplete={finishIntro} /></AnimatePresence>
  const resultScreen = ['results'].includes(screen)
  const utilityScreen = ['history', 'community', 'network'].includes(screen)
  return <div className="app-frame">
    {screen !== 'scanning' && screen !== 'gauge' && screen !== 'reveal' && <Navbar active={resultScreen ? 'scan' : utilityScreen ? 'history' : 'home'} onNavigate={(target) => target === 'scan' || target === 'home' ? resetToHome() : target === 'history' ? setScreen('history') : undefined} onNewScan={resetToHome} />}
    <AnimatePresence mode="wait">
      {screen === 'home' && <PageTransition key="home"><HomePage url={url} setUrl={setUrl} onSubmit={handleScan} error={error} /></PageTransition>}
      {screen === 'scanning' && <PageTransition key="scanning"><ScanningPage url={activeUrl} /></PageTransition>}
      {screen === 'gauge' && result && <PageTransition key="gauge"><TrustGauge score={result.trustshield_score} onComplete={() => setScreen('reveal')} /></PageTransition>}
      {screen === 'reveal' && result && <PageTransition key="reveal"><ScoreReveal result={result} onView={() => setScreen('results')} /></PageTransition>}
      {screen === 'results' && result && <div className="analysis-layout"><AnalysisSidebar activeTab={activeTab} result={result} onSelect={navigateAnalysis} onNewScan={resetToHome} /><main className="analysis-main"><PageTransition key={activeTab}>{renderResults()}</PageTransition></main></div>}
      {screen === 'history' && <HistoryPage onScanAgain={resetToHome} onViewResult={openHistoryResult} />}
      {screen === 'community' && <CommunityPage result={result} onScanAgain={resetToHome} onBack={() => setScreen(result ? 'results' : 'home')} />}
      {screen === 'network' && <NetworkPage result={result} onBack={() => setScreen(result ? 'results' : 'home')} onScanAgain={resetToHome} />}
      {screen === 'error' && <PageTransition key="error"><main className="error-screen"><p className="eyebrow">Scan interrupted</p><h1>Analysis Failed</h1><p>We could not complete the website scan.</p><div className="error-detail">{error}</div><div className="error-actions"><button className="primary-button" onClick={() => { setError(''); setScreen('home') }}>TRY AGAIN</button><button className="outline-button" onClick={resetToHome}>ENTER ANOTHER URL</button></div></main></PageTransition>}
    </AnimatePresence>
  </div>
}

export default App




