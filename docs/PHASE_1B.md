# Phase 1B: Brand Impersonation and Lexical Intelligence

## Purpose

Phase 1B extends the Phase 1A technical scan with explainable domain-language analysis. It identifies possible brand impersonation, typosquatting, misleading brand-like subdomains, punycode, random-looking labels, suspicious paths, and cautionary TLDs without declaring a site definitively safe or fraudulent.

## New Modules and Data

- `backend/app/services/brand_analyzer.py`: known-brand matching, similarity, digit substitutions, official-domain exceptions, misleading subdomains, and lightweight homoglyph awareness.
- `backend/app/services/domain_lexical_analyzer.py`: entropy, randomness, digit/symbol patterns, path terms, TLD indicators, and lexical risk levels.
- `backend/data/known_brands.json`: expandable local brand-to-legitimate-domain reference data.

The API response now includes `brand_analysis` and `lexical_analysis` alongside the Phase 1A analysis groups.

## Typosquatting and Brand Logic

Brand comparisons use `SequenceMatcher` plus conservative substitutions such as `0 → o`, `1 → l`, `3 → e`, `4 → a`, and `5 → s`. An exact match to a known legitimate registered domain is explicitly treated as official, including ordinary subdomains such as `support.paypal.com`.

The analyzer separately checks for a legitimate-looking brand domain embedded in the subdomain of an unrelated registered domain, such as `paypal.com.fake-login.xyz`. This produces a clear explanation naming both the visible brand domain and the actual registered domain.

## Punycode and Homoglyph Handling

Hostnames containing `xn--` are reported as punycode and contribute only a small supporting signal unless combined with stronger brand evidence. A small mapping of visually similar Cyrillic and Greek characters provides a cautious possible-homoglyph signal; it is not presented as certainty.

## Lexical Scoring

`lexical_risk_score` ranges from 0 to 100 with levels `MINIMAL`, `LOW`, `MODERATE`, `HIGH`, and `VERY HIGH`. Brand impersonation and misleading subdomains carry more weight than TLD or path indicators. Domain entropy and randomness remain supporting evidence. The Phase 1A technical score incorporates lexical risk as one weighted component rather than replacing the original URL, domain, SSL, DNS, and HTTP signals.

## False-Positive Protections

- Official known-brand domains are not flagged as impersonation.
- A brand word, cautionary TLD, password path, or payment term alone does not classify a site as malicious.
- Low similarity matches are not assigned a detected brand.
- Scores are bounded and explanations use language such as “possible” and “potential.”

## Limitations

- The local brand catalog is a starter list and cannot represent every legitimate regional or service domain.
- Similarity and homoglyph analysis are heuristic and can miss creative attacks or produce occasional contextual warnings.
- No machine learning, LLM, reputation provider, Safe Browsing, VirusTotal, or live malicious-site testing is included.
