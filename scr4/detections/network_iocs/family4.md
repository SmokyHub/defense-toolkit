# Family4 network indicators

Date: 2026-10-09. Source app: `dev.tracebasinmoss.routepearl` (5555xBasin).
These indicators originate from the native bootstrap's decoded URL and network
implementation. Static recovery does not establish malicious content served by
the endpoint, a production payload, or common operators with earlier families.

| Indicator | Type | Confidence | Source | Suggested action |
|---|---|---|---|---|
| `https://dev.fest-drift.com/remote-config` | Exact HTTPS URL, native POST configuration endpoint | High for static presence and native role; runtime contact separate | `reports/family4/dev.tracebasinmoss.routepearl/04_detection_report.md`, original descriptor VA `0x2e2b0`; native analysis | Alert and correlate with the app's DEX-loader capability; inspect response only on authorized lab interception |
| `dev.fest-drift.com` | Hostname | High for extraction; no domain-wide maliciousness verdict | Host portion of the recovered URL above | Monitor DNS/SNI/HTTP Host for attribution to the app; avoid automatic parent-domain blocking |

The companion `.txt` contains these two literal indicators for ingestion. The
URL path and method require HTTP visibility; TLS SNI/DNS normally expose only the
host. Host rotation evades both indicators. SDK hosts from Adjust, AppsFlyer and
Google are deliberately excluded because the code audit does not associate them
with this native response-to-loader path. No JA3, resolved IP or live backend
behavior is inferred. Neither samples nor hashes were submitted to third parties.
