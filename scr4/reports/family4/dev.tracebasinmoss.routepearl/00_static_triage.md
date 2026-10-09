# Family 4 — 5555xBasin static triage

Date: 2026-10-09. Scope: the user-identified app saved from the authorized Pixel 7. This report records initial static observations, not execution proof or operator attribution.

## Identity and inputs

| Property | Value |
|---|---|
| Label | 5555xBasin |
| Package | `dev.tracebasinmoss.routepearl` |
| Version | 1.0.5, code 11 |
| Minimum / target SDK | 32 / 36 |
| Debuggable | false |
| Launcher | `dev.tracebasinmoss.routepearl.MainActivity` |
| Input | `samples/family4/dev.tracebasinmoss.routepearl/` — base plus 85 splits |
| Base SHA-256 | `43394330e7f3ff40dabd347fdab415e9d5e229da00442a6f1322de9b7d28a0cb` |
| Certificate SHA-256 | `81937f9ec872b7db4e65f30273633a70848a417efb61d29e359d5fdb7266093d` |

Certificate subject and issuer are identical: CN=Android, OU=Android, O=Google Inc., L=Mountain View, ST=California, C=US. These are certificate text fields and do not establish Google authorship. No external certificate/hash lookup was performed.

`scripts/unpack_apk.sh samples/family4/dev.tracebasinmoss.routepearl family4/dev.tracebasinmoss.routepearl` processed the complete split set. Per-input hashes, split names, components and permissions are recorded in `work/family4/dev.tracebasinmoss.routepearl/static_report.json`. Decoded resources/smali, Java and native libraries are in the adjacent `apktool/`, `apktool_splits/`, `jadx/` and `native_libs/` directories. JADX reported 56 errors while processing 2,447 entries; primary application bootstrap classes remain readable.

## Framework and initial call flow

This is a Kotlin/Java Android app using Jetpack Compose and JNI. There is no `libflutter.so`, `libapp.so`, `libhermes.so` or React Native bundle. Blutter/Hermes are not the next analysis tools.

The readable bootstrap is:

1. `MainActivity.onCreate()` invokes `RuntimeConfig.INSTANCE.start(this)` (`jadx/sources/dev/tracebasinmoss/routepearl/MainActivity.java:58`).
2. `RuntimeConfig.start(Activity)` uses a synchronized, process-local `requested` flag and launches a coroutine once. It is not itself a retry loop.
3. The coroutine invokes `FestDrift.dev(activity, new JSONObject())`. Failures are caught and produce default `AppConfig` state.
4. `z5555xbasin.FestDrift` loads `z5555xbasin` and calls native `_n4581150eae37011bd161(Activity, JSONObject): JSONObject`.
5. Returned JSON is passed to `RuntimeConfigKt.toAppConfig()`, which reads `level_count` and `show_help` for the visible application configuration.

The native bridge receives an Activity and an initially empty object. The Java wrapper does not establish the remote schema, DEX loading, size threshold, or destination URL. Those require native tracing and dynamic validation. Java-level configuration keys must not be mistaken for the complete native response contract.

## Native inventory and handoff

The app has **three distinct native library names**, nine ELF files across four ABIs. The user's observation of one library corresponds to one app-specific JNI library; two additional dependency libraries are present in the splits.

| Library | ABIs | Initial association |
|---|---|---|
| `libz5555xbasin.so` | arm64-v8a only | App-specific bridge described above; first priority for Ghidra |
| `libsigner.so` | arm64-v8a, armeabi-v7a, x86, x86_64 | Loaded by `com.adjust.sdk.sig.NativeLibHelper`; dependency association, not an independent trust verdict |
| `libandroidx.graphics.path.so` | arm64-v8a, armeabi-v7a, x86, x86_64 | Loaded by AndroidX path implementation |

Primary Ghidra input: `work/family4/dev.tracebasinmoss.routepearl/native_libs/arm64-v8a/libz5555xbasin.so`, 184,824 bytes, SHA-256 `260e1aec4db63cea64f5f9486db3f639c9b4b5546099def8e1c50a593513b04c`. It is a stripped AArch64 ELF, and its strings expose `JNI_OnLoad` without a plainly visible URL or DEX-loader class in the initial keyword sweep. Full hashes and source split names are in `native_libs/INDEX.tsv`.

Prioritize native registration, the bridge's network acquisition and parsing, any byte-count guard, and class-loader/reflective invocation. Absence of a Java loader string is not evidence that the native side cannot load DEX. Because the app-specific library exists only in the arm64 split, x86 availability of the dependency libraries does not establish that its bootstrap can run on an x86 device.

## Permission and exported-component risks

The manifest requests INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, FLASHLIGHT, VIBRATE, READ_INSTALL_SESSIONS, AD_ID, install-referrer binding, Huawei common-data and Samsung app-info permissions. It does not declare SMS, contacts, accessibility, device administrator, overlays, location, package installation or storage runtime permissions in this input. Network access and attribution/install metadata remain relevant to the native flow. Requested vendor permissions do not prove that access was granted.

`MainActivity` is exported and has the normal MAIN/LAUNCHER filter; it has no permission guard or declared deep-link filter. `androidx.profileinstaller.ProfileInstallReceiver` is exported but guarded by `android.permission.DUMP`. Both content providers and the Google/Play auxiliary activities are explicitly non-exported. There are no declared services. A signature-protected `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` is defined for the package. `allowBackup=true` is enabled with custom backup/data-extraction rules; assess persisted sensitive data if later analysis finds any.

## Obfuscation and packing assessment

R8 renaming is extensive in supporting code, while the main app and native bridge retain useful names and Kotlin metadata. JADX remains useful for the app bootstrap; inspect smali for failed methods. The native bridge is stripped and hides any meaningful remote logic from the initial Java/strings sweep, making Ghidra necessary. This is not enough to conclude that the entire APK is packed.

The base has one `classes.dex` (3,188,024 bytes). Its small asset inventory consists of four blobs under `assets/com/appsflyer/internal/` and the baseline profile files. Their presence alone does not establish encrypted executable payloads, steganography or malicious packing. No Flutter/Hermes application payload was found.

## Raw IOC candidates and limits

`scripts/extract_iocs.sh work/family4/dev.tracebasinmoss.routepearl/jadx` emitted URL candidates to `work/family4/dev.tracebasinmoss.routepearl/ioc_candidates.txt`. The helper exited at its empty IPv4-match stage because of `pipefail`; the remaining API sweep was performed separately and saved to `api_candidates.txt` (49 lines).

Visible URL strings are dominated by dependency references: `app.adjust.com`, `app.adjust.io`, `gdpr.adjust.com`, `ssrv.adjust.com`, `subscription.adjust.com` and AppsFlyer format strings such as `https://%sconversions.%s/api/v` and `https://%slaunches.%s/api/v`. Google API scope strings and documentation URLs also occur. These are **unverified string candidates**, not confirmed C2 indicators or recommendations for blanket blocking. No plaintext app-specific backend was identified in the initial Java sweep. Native analysis and observed traffic must determine the relevant endpoint.

## Stage outcome

Native Ghidra analysis is required, starting with `libz5555xbasin.so`. Obfuscation limits some supporting Java methods but does not prevent tracing the native entry point. DEX fetching, its size check, and response-driven execution remain hypotheses at this triage stage; downstream evidence should resolve them before a detection or proof-response generator is marked validated.
