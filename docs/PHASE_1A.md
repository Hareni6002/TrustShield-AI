# Phase 1A: Real-Time Website URL Analysis

## Purpose

Phase 1A provides the first real-time technical analysis foundation for TrustShield AI. A submitted HTTP or HTTPS URL is normalized, inspected, and scored using transparent rules. The score is preliminary technical context, not a final safety verdict.

## Modules

- `url_analyzer.py`: validation, normalization, URL structure features, keywords, IP and shortener detection.
- `domain_analyzer.py`: bounded WHOIS lookup and domain date calculations.
- `ssl_analyzer.py`: HTTPS certificate availability, verification, issuer, subject, and expiry.
- `dns_analyzer.py`: A, AAAA, MX, and NS lookups with graceful record-level failures.
- `http_analyzer.py`: bounded requests, redirect chain, HTML metadata, forms, links, and payment terms.
- `risk_engine.py`: explainable weighted technical risk and trust scores.
- `utils/security.py`: hostname resolution and local/private network blocking.

## Signals Analyzed

The scan uses URL structure, suspicious terms, IP-based hosts, shorteners, punycode, HTTPS and certificate state, domain age when WHOIS provides it, DNS resolution, redirect count, page title, description, password/login forms, payment terms, and internal/external link counts.

## Risk Scoring

`technical_risk_score` ranges from 0 to 100 and is clamped after weighted warning and positive adjustments. `technical_trust_score` is `100 - technical_risk_score`. The risk label is derived from the trust score using the preliminary bands in the project brief. No individual signal automatically classifies a site as safe or fraudulent.

## API

`POST /api/scan`

```json
{"url": "https://example.com"}
```

The response includes typed URL, domain, SSL, DNS, HTTP/content, score, risk level, positive signals, and warning signals.

## Known Limitations

- WHOIS availability and date formats vary by registry; missing data remains unavailable.
- DNS and HTTP results depend on network access, rate limits, server behavior, and timeouts.
- No reputation providers, machine learning, LLM, screenshot analysis, authentication, or community reports are included yet.
- A valid certificate, payment form, password field, or young domain is only one contextual signal and is not proof of legitimacy or fraud.
- Requests do not execute JavaScript and cap HTML inspection at approximately 1 MB.
