import { motion } from 'framer-motion'

export default function UrlScanner({ url, setUrl, onSubmit, error }) {
  return <motion.form className="url-scanner" onSubmit={onSubmit} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3, duration: 0.6 }}>
    <label htmlFor="website-url">Website URL</label>
    <div className={error ? 'scanner-input error-input' : 'scanner-input'}>
      <span>↗</span>
      <input id="website-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="Enter a website URL" autoComplete="url" />
      <button type="submit">ANALYZE WEBSITE <span>→</span></button>
    </div>
    {error && <motion.p className="form-error" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}>{error}</motion.p>}
  </motion.form>
}




