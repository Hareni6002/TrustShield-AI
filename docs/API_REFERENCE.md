# TrustShield AI — API Reference

- `GET /health` — service health.
- `POST /api/scan` — validate and analyze a URL.
- `GET /api/model-info` — ML model metadata.
- `GET /api/integrations/status` — provider availability without secrets.
- `GET /api/history` — paginated scan history.
- `GET /api/history/{history_id}/result` — stored scan result.
- `GET /api/scans/{scan_id}/report` — downloadable PDF report.
- `POST /api/ai/summary` — generate/retrieve AI summary for a stored scan.
- `POST /api/ai/ask` — ask a bounded question about a stored scan.
- `GET /api/reports/domain/{domain}` — community report summary.
- `POST /api/reports` — submit a community report.
- `GET /api/network/{domain}` — stored domain relationships.
