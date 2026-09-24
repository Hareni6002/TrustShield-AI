# TrustShield API integration status

This document records the integration contract and verification approach. It contains no credentials.

## Gemini

- Configured: `AI_PROVIDER=gemini` and a non-empty `AI_API_KEY`.
- Working: the provider discovers models supporting `generateContent`, probes the configured model, and caches a compatible Flash fallback when the configured model is unavailable.
- Purpose: evidence-grounded scan explanations and answers.
- Limitations: outages, invalid credentials, quotas, and malformed output fall back to deterministic explanations.
- Rate limits: HTTP 429 is converted to a safe provider error and never breaks a scan.

## VirusTotal

- Configured: `VIRUSTOTAL_API_KEY` is present.
- Working: parser and sanitized failure states are covered by mocked tests; live status depends on account quota.
- Purpose: URL reputation detections and analysis counts.
- Limitations: no record is neutral, not proof of safety.
- Rate limits: 429 becomes `rate_limited`; 401/403 becomes `invalid_key`; timeouts and network failures become `lookup_failed`.

## Google Safe Browsing

- Configured: `GOOGLE_SAFE_BROWSING_API_KEY` is present.
- Working: clean no-match parsing and error mapping are covered by mocked tests; live status depends on Google Cloud API enablement, restrictions, and quota.
- Purpose: known threat-match lookup.
- Limitations: no match means no known match was found, not that a site is safe.
- Rate limits: 429 becomes `rate_limited`; authentication/request failures are sanitized.

## URLhaus

- Configured: controlled by `URLHAUS_ENABLED` and a non-empty `URLHAUS_AUTH_KEY`.
- Working: authenticated no-record and threat-record parsing are covered by mocked tests; live status depends on URLhaus availability.
- Purpose: URLhaus malware URL records.
- Limitations: no record is neutral, not proof of safety.
- Rate limits: timeouts, network failures, and non-success responses become `lookup_failed`; invalid credentials become `authentication_failed`.

## Safe diagnostics

`GET /api/integrations/status` returns only boolean configuration flags and coarse states. It never returns keys, tokens, headers, or secret fragments.
