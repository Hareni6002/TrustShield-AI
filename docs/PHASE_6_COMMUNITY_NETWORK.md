# Phase 6: Community intelligence, scan history and related domains

## History

Successful scans write a compact summary to SQLite table `scan_history`. Stored fields include the URL, normalized domain, TrustShield score, risk level, ML probability, reputation risk, timestamps, and selected observed metadata. Raw page content, API credentials, authorization headers, and reporter contact information are not stored in history responses.

Endpoints:

- `GET /api/history?page=1&limit=20`
- `GET /api/history/{id}`
- `DELETE /api/history/{id}`

## Community reports

`POST /api/reports` accepts a validated URL, supported category, and description. Reports begin as `pending`. Repeated same-domain/category/description submissions within seven days are retained and marked `possible_duplicate=true`; they are not silently deleted.

`GET /api/reports/domain/{domain}` returns counts, verified category totals, a separate `community_risk_score`, and recent public report data. Reporter email is never returned. `GET /api/reports?status=pending` and `PATCH /api/reports/{id}` provide simple moderation support for `verified` and `rejected` states.

## Community scoring

Community risk is independent from the existing TrustShield score. Verified reports receive the strongest weight, pending reports receive a small weight, and repeated verified reports add a limited duplicate signal. The score is bounded from 0 to 100. One pending report cannot dominate the result.

## Related domain network

`GET /api/network/{domain}` uses only metadata from previously stored scans. It can identify `SAME_IP`, `SAME_NAMESERVER`, `SAME_REGISTRAR`, and `SIMILAR_DOMAIN` relationships with evidence and confidence. The graph is capped at 30 nodes. It does not crawl the internet or claim common ownership.

The UI wording is intentionally limited to observed infrastructure or lexical similarity. A relationship is not proof that domains belong to the same operator.

## Privacy and limitations

Public report summaries omit reporter name and email. Network results depend on which domains have already been scanned and on the availability of metadata at scan time. Moderation endpoints currently have no admin authentication and should be protected before production deployment.
