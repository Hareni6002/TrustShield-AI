export default function Navbar({ active, onNavigate, onNewScan }) {
  const links = [
    { id: 'home', label: 'Home' },
    { id: 'scan', label: 'Scan' },
    { id: 'history', label: 'History', disabled: true },
    { id: 'about', label: 'About', disabled: true },
  ]
  return <header className="navbar">
    <button className="brand-mark" onClick={onNewScan} aria-label="TrustShield AI home"><span className="brand-pulse" />TRUSTSHIELD <em>AI</em></button>
    <nav aria-label="Primary navigation">
      {links.map((link) => <button key={link.id} className={active === link.id ? 'nav-link active' : 'nav-link'} disabled={link.disabled} onClick={() => onNavigate(link.id)}>{link.label}</button>)}
    </nav>
  </header>
}




