import axios from 'axios'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

export async function scanWebsite(url) {
  const response = await axios.post(`${API_URL}/api/scan`, { url })
  return response.data
}

export async function getAISummary(scanId) {
  const response = await axios.post(`${API_URL}/api/ai/summary`, { scan_id: scanId })
  return response.data
}

export async function askTrustShield(scanId, question) {
  const response = await axios.post(`${API_URL}/api/ai/ask`, { scan_id: scanId, question })
  return response.data
}

export async function getHistory(page = 1, limit = 20) {
  const response = await axios.get(`${API_URL}/api/history`, { params: { page, limit } })
  return response.data
}

export async function getHistoryResult(historyId) {
  const response = await axios.get(`${API_URL}/api/history/${historyId}/result`)
  return response.data
}

export async function getCommunitySummary(domain) {
  const response = await axios.get(`${API_URL}/api/reports/domain/${encodeURIComponent(domain)}`)
  return response.data
}

export async function submitCommunityReport(report) {
  const response = await axios.post(`${API_URL}/api/reports`, report)
  return response.data
}

export async function getNetwork(domain) {
  const response = await axios.get(`${API_URL}/api/network/${encodeURIComponent(domain)}`)
  return response.data
}

export async function getIntegrationStatus() {
  const response = await axios.get(`${API_URL}/api/integrations/status`)
  return response.data
}

export async function downloadScanReport(scanId) {
  const response = await axios.get(`${API_URL}/api/scans/${encodeURIComponent(scanId)}/report`, { responseType: 'blob' })
  const contentDisposition = response.headers['content-disposition'] || ''
  const fileName = contentDisposition.match(/filename="?([^";]+)"?/i)?.[1] || 'trustshield-security-report.pdf'
  const url = URL.createObjectURL(response.data)
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
