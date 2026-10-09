# Family4 network indicators

Date: 2026-10-09. Source apps: `dev.tracebasinmoss.routepearl` (5555xBasin) and
`io.tracelatticeglow.proofharbor` (5555xLat).
These indicators originate from the native bootstrap's decoded URL and network
implementation. Static recovery does not establish malicious content served by
the endpoint, a production payload, or common operators with earlier families.

| Indicator | Type | Confidence | Source | Suggested action |
|---|---|---|---|---|
| `https://dev.fest-drift.com/remote-config` | Exact HTTPS URL, native POST configuration endpoint | High for static presence and native role; runtime contact separate | `reports/family4/dev.tracebasinmoss.routepearl/04_detection_report.md`, original descriptor VA `0x2e2b0`; native analysis | Alert and correlate with the app's DEX-loader capability; inspect response only on authorized lab interception |
| `dev.fest-drift.com` | Hostname | High for extraction; no domain-wide maliciousness verdict | Host portion of the recovered URL above | Monitor DNS/SNI/HTTP Host for attribution to the app; avoid automatic parent-domain blocking |
| `https://proofharbor.android-app-api.com/public/v5/kr` | Exact HTTPS POST endpoint | Native recovery and app-generated request confirmed with local response | `reports/family4/io.tracelatticeglow.proofharbor/02_variant_analysis.md` | Alert and correlate with the native DEX-loader capability |
| `proofharbor.android-app-api.com` | Hostname | Same bounded evidence as the URL; no domain-wide verdict | Host portion of the recovered URL above | Monitor and attribute to the app |

The companion `.txt` contains these four literal indicators for ingestion. The
URL path and method require HTTP visibility; TLS SNI/DNS normally expose only the
host. Host rotation evades both indicators. SDK hosts from Adjust, AppsFlyer and
Google are deliberately excluded because the code audit does not associate them
with this native response-to-loader path. No JA3, resolved IP or live backend
behavior is inferred. Neither samples nor hashes were submitted to third parties.
