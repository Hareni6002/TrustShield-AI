# Phase 4: External Reputation Intelligence

TrustShield AI now adds independent external reputation evidence without replacing technical, lexical, or ML analysis.

## Providers

- VirusTotal URL analysis, configured with `VIRUSTOTAL_API_KEY`.
- Google Safe Browsing URL threat matching, configured with `GOOGLE_SAFE_BROWSING_API_KEY`.
- URLhaus public URL lookup, controlled by `URLHAUS_ENABLED`.

Provider keys are read only by the backend. They are never sent to the browser, included in scan JSON, logged, or committed. Copy the variables from `backend/.env.example` into the local `backend/.env` when needed.

## Provider states and failures

Each provider returns an explicit status such as `available`, `threat_found`, `no_record`, `not_configured`, `rate_limited`, `invalid_key`, or `lookup_failed`. Provider failures produce partial results and never fail the scan. VirusTotal rate limits are presented as a temporary unavailability message rather than raw `429` output.

The three lookups run in parallel with bounded six-second HTTP timeouts. Results are cached in memory by normalized URL for 30 minutes.

## Reputation scoring

`reputation_risk_score` is 0–100. Google threat matches score 95, URLhaus active records score 90, and VirusTotal contributes based on malicious and suspicious detections. Multiple provider risks combine as `1 - product(1 - provider_risk / 100)`. A missing blacklist record contributes no threat evidence; it is never treated as proof of safety. If providers are available but show no record, the reputation component is neutral rather than fully trusted.

`external_threat_evidence_count` counts providers with threat evidence. `reputation_confidence` reflects provider availability and agreement, not whether the URL is trustworthy.

## TrustShield score

When available, the broader score uses transparent weights:

`25% technical trust + 20% lexical trust + 25% ML trust + 30% reputation trust`

ML trust is `100 - phishing_probability * 100`. Lexical trust is `100 - lexical_risk_score`. Reputation trust is `100 - reputation_risk_score` when threats exist, neutral `50` for available no-record checks, and omitted when no reputation provider is available. Missing components cause the remaining weights to be renormalized. The result is clamped to 0–100.

Risk labels are `LOW OBSERVED RISK`, `CAUTION`, `ELEVATED RISK`, `SUSPICIOUS`, and `HIGH RISK`. The system does not claim that a URL is definitely safe or definitely fraudulent.

## Frontend

The overview now presents `TRUSTSHIELD SCORE`; the original technical trust score remains visible as a separate matrix signal. The `REPUTATION` tab shows VirusTotal, Google, and URLhaus status cards, counts, threat records, confidence, and the explicit distinction between `NO RECORD` and safe.
