import axios from 'axios'

const API_URL = 'http://127.0.0.1:8000'

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
