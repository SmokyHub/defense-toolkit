# Family4 network and response-execution validation

The original `dev.tracebasinmoss.routepearl` app executed a benign DEX supplied in
an analyst-generated HTTPS response. The response was persisted unchanged, its
entry point ran inside the app, and its added button executed and changed the
screen. Four negative controls received and persisted their respective responses
but did not execute the fixture. This establishes response-driven code-loading
capability under a trusted analyst proxy. It does not establish the contents,
selection criteria, or purpose of an unseen production payload.

## Evidence and scope

Analysis date: 2026-10-09. Source evidence is under
`captures/family4/dev.tracebasinmoss.routepearl/`, specifically the `disabled`,
`short-dex`, `wrong-header-size`, `wrong-file-size`, and `positive` trial directories. Each contains
`exchange.json`, `trial.json`, `preferences-after.xml`, `logcat.txt`, `ui.xml`, and
`screen.png`. The positive also includes `button-logcat.txt`, `button-ui.xml`, and
`button-screen.png`. Raw device identifiers and request metadata remain in the
gitignored capture directory; they are not reproduced here.

`exchange.json` records selected ordinary HTTP Toolkit GUI/DOM state. It is **not
a HAR, packet capture, or byte-exact network export**. Large response bodies are
only partially rendered in the captured DOM. Body identity is independently
verified using the supplied response file and the app-created preference value.
This evidence is sufficient for the controlled exchanges below, not for a complete
device endpoint inventory or precise wire-level timing.

The orchestrating session used the authorized physical Pixel 7 and the original
app. Each trial records `instrumentation: false`; no Frida attach or app hooks
were used. A pre-existing Frida server was running. Consequently these results
do not show that attaching instrumentation would leave the app's anti-analysis
score unchanged. Existing HTTP Toolkit trust configuration was in use. The
positive WebView log also records an existing analyst certificate exception;
this is lab configuration, not evidence of a production certificate-validation
weakness.

The exact POST/URL request breakpoint was answered through HTTP Toolkit's
**Respond directly** operation, without forwarding these requests to the live
backend. All five selected exchanges completed as HTTP 200, with JSON content
type and the matching response length. No real backend reply is represented by
the five generated test responses. A pre-existing preference snapshot was
preserved separately as `preferences-before.xml`; its contents and origin are
outside these five controlled-response claims.

## Endpoint inventory and detector handoff

| Indicator | Observed use and verdict |
|---|---|
| `dev.fest-drift.com` | App-generated request destination; corroborates the native request path in [02_native_analysis.md](02_native_analysis.md). Confirmed response-driven loader endpoint in this sample; production malicious content is unverified. |
| `POST https://dev.fest-drift.com/remote-config` | All five selected requests use this exact method and URL. Request JSON is an empty object in these trials. Prefer the host + method + path combination to the generic path alone. |
| Header names `ds`, `dtaah`, `nfb`, `uaf` | Present together on the five selected requests. Ancillary sample-specific features, unsuitable as standalone maliciousness indicators. Values omitted. |

The captured request metadata includes locale/time-zone, time-like and device
user-agent information. No IMEI, Android ID, contacts, SMS, credentials or other
sensitive body content is visible in the selected requests. This limited view
cannot exclude other exchanges or transmissions. The original URL is HTTPS:
plaintext visible to a trusted intercepting proxy is not proof of cleartext
transmission on the original connection.

No additional app endpoint, raw socket bypass, nonstandard port or custom binary
network protocol is established by this evidence. The DOM interface includes
names of generated client-code examples such as OkHttp and libcurl; those are UI
options, not observed SDK traffic. No ad/analytics endpoint has been classified
as noise from these selected exchanges. An unselected request exists in the GUI
list count, but its host, body and app attribution are not captured here and must
not be invented or classified.

## Five controlled responses

All five `preferences-after.xml` files contain string entry `67`. After normal XML
entity decoding, the UTF-8 bytes of that value equal the corresponding supplied
response file **exactly**, including its SHA-256 and length recorded by
`exchange.json`. Equality was checked for every trial, not inferred from a
successful HTTP status. The cache write itself does not establish execution:
the app persists rejected responses too.

| Trial | PID | JSON bytes | DEX condition | Observed result |
|---|---:|---:|---|---|
| `disabled` | 13814 | 11 | Outer selector `67` is null | No fixture entry/UI/button markers; original puzzle UI remains. |
| `short-dex` | 13899 | 634 | First 64 bytes of the benign DEX | No fixture markers; original UI remains. |
| `wrong-header-size` | 13990 | 15136 | Full 5120-byte buffer, but `header.file_size` is 5124 | No fixture markers; original UI remains. |
| `wrong-file-size` | 14273 | 15138 | Full 5120-byte buffer, `header.file_size` 5124, valid recomputed SHA-1/Adler-32 | No fixture markers; original UI remains. |
| `positive` | 14078 | 15136 | Valid, unchanged 5120-byte benign DEX | Entry, UI installation, and button execution all confirmed. |

Despite its directory name, `wrong-header-size` changes **file_size**, not the
DEX `header_size` field: header size stays 112. Only byte offset 32 differs from
the valid fixture. That edit also leaves the embedded checksum/signature stale.
Thus the negative runtime result alone does not isolate the native size check
from later Android DEX integrity checks. The exact buffer-length equality check
and 112-byte minimum are established by native analysis; these negative trials
are consistent with them. The short input also violates other DEX structure
requirements, so it is not an isolated boundary-value experiment.

The later `wrong-file-size` trial corrects that checksum confound: its SHA-1
signature and Adler-32 checksum were recomputed and independently verified against
its mutated bytes. The actual buffer is still 5120 bytes while the declared file
size is 5124. Its response also persisted unchanged, with no fixture execution.
This supports rejection of the inconsistent size without relying on stale
checksums. It still does not dynamically identify the first rejecting function;
the native control flow establishes that the native size gate precedes class
loader creation.

Response identities, SHA-256:

| Trial | Supplied response and received cache SHA-256 |
|---|---|
| `disabled` | `6338a0f8dd32f807fefbcb0f2b1a9b3694bd74ccd4154d5b19bcaa79a53f4860` |
| `short-dex` | `06cf1e93130e5ebd60880bc75c6092105c910e3d948c96b2e42f60e55cb2db21` |
| `wrong-header-size` | `258ab6f8d6d248896260c0bc28c96b33945d8b9f3733687d4210d6e4f2689f70` |
| `wrong-file-size` | `298e105accfa093d3239b2b788081eeb9c9175a781e2047b35483002aa2a5a2f` |
| `positive` | `fcc63fb7943d6ac5181f455eaaffcec9bad4cca5596e3674d0e6582c75121d2e` |

These are analyst test-response identifiers, **not malware IOCs**. The valid
benign DEX has SHA-256
`8de5fb444a932ad2eb5af51fb1082f4cf6d293441808f37ab84e546e936017d0`.
Its bytes are the same in `work/family4/proof-response.json`, the positive trial
response, and the app-created cache. Full response objects also compare equal.

## Positive execution proof

All three fixture markers are attributed to recorded PID **14078** and host
package `dev.tracebasinmoss.routepearl`:

- `ENTRY_CALLED` at device-log time `09:06:43.861`, thread 14096. The logged
  loader is `dalvik.system.InMemoryDexClassLoader`, with an in-memory DEX.
- `UI_INSTALLED` at `09:06:47.105`, main thread 14078. The first UI dump contains
  the added `TEST ADDED FUNCTIONALITY` button.
- `BUTTON_EXECUTED` at `09:08:47.879`, main thread 14078. The resulting UI dump
  and screenshot show `APK Defense: DEX executed` and
  `DEX BUTTON HANDLER EXECUTED`, identifying the host package. The page states
  that it is local and makes no network requests.

The four negative logs contain none of these fixture markers, and their saved
UI dumps retain the original puzzle screen without the added button. These
observations cover the recorded observation windows, not indefinite future app
behavior. The benign WebView is fixture-provided functionality; it does not show
that a production payload would display gambling, advertising or other content.

## Timing, pinning and limitations

The host-side DOM records show response releases at approximately 12:03:17.696,
12:04:04.589, 12:05:34.682, 12:06:44.249 and 12:11:05.150 UTC. Editing/resume takes about
0.43–0.48 seconds after the responder starts its edit operation. These five
requests follow separate analyst launches and interventions, not a natural
periodic sequence: **beaconing is not established**. Device-log times use a
different clock/time-zone basis and are not synchronized to host DOM timestamps;
do not infer subsecond response-to-entry latency by subtracting them.

The request successfully traversed the configured trusted analyst proxy without
app hooks. There is no captured certificate rejection or controlled pinning
comparison, so this does not prove the presence or absence of pinning across
other hosts or environments. Native risk scoring and cached response reuse are
documented separately; absent traffic in another run could have several causes.
No anti-emulator conclusion follows from these physical-device trials.

The confirmed behavior is JSON response ingestion, unchanged persistence, and
benign in-memory code execution with a visible interactive effect. It is not
proof of arbitrary interception against an unmodified trust store, privilege
escalation, attribution, or production backend behavior.
