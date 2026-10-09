# Family 4 Java entry and return-path audit

Analyzed 2026-10-09; package `dev.tracebasinmoss.routepearl`, label `5555xBasin`, version `1.0.5` (11). Scope: saved original split APKs, existing JADX output and corresponding apktool smali. No backend requests or device actions were performed for this audit.

All Java source paths below are relative to `work/family4/dev.tracebasinmoss.routepearl/jadx/sources/`. Smali paths are relative to `work/family4/dev.tracebasinmoss.routepearl/apktool/smali/`.

## Scope and confidence

The static report does not include a dedicated framework field. Its native inventory and the entry code identify an Android/Kotlin Compose app with a custom JNI library, rather than Flutter or Hermes. The ARM64 split has three libraries: `libz5555xbasin.so`, `libandroidx.graphics.path.so`, and `libsigner.so`. Only the first is app-specific; the other two are loaded by AndroidX graphics and Adjust SDK code respectively. The app-specific library is present only in the ARM64 split in the saved inventory. An unsupported ABI can therefore break its initialization without implying anti-emulator logic.

The startup, native wrapper and return parsing decompile clearly. Critical calls and the empty JSON constructor were verified in smali. Decompiled UI code contains normal reconstruction warnings and duplicate accessor names, so this audit does not assume the reconstructed Java can compile. Native networking, payload interpretation, environment gates and execution require the separate native analysis; their absence in Java is not evidence that the app lacks them.

## F4-J01: Startup invokes a custom native configuration/behavior entry

**Confidence: high for the call path; no Java-only verdict about maliciousness.**

`dev/tracebasinmoss/routepearl/MainActivity.java:55–59`, `MainActivity.onCreate`:

```java
super.onCreate(savedInstanceState);
RuntimeConfig.INSTANCE.start(this);
```

`dev/tracebasinmoss/routepearl/RuntimeConfig.java:105–112`, `RuntimeConfig.start`:

```java
synchronized (started) {
    if (requested) return;
    requested = true;
    z.l(scope, null, new AnonymousClass2(activity, null), 3);
}
```

`dev/tracebasinmoss/routepearl/RuntimeConfig.java:64–70`, `RuntimeConfig.AnonymousClass2.invokeSuspend`:

```java
kVar = FestDrift.dev(activity, new JSONObject());
```

`dev/tracebasinmoss/routepearl/z5555xbasin/FestDrift.java:8–20`, class initializer and `dev`:

```java
System.loadLibrary("z5555xbasin");
private static native JSONObject _n4581150eae37011bd161(
    Activity activity, JSONObject jSONObject);
return _n4581150eae37011bd161(activity, jSONObject);
```

Smali independently confirms `new JSONObject()` followed by the wrapper at `dev/tracebasinmoss/routepearl/RuntimeConfig$start$2.smali:224–233`; the native signature is at `dev/tracebasinmoss/routepearl/z5555xbasin/FestDrift.smali:34`, and its call is at line 51.

This is the correct app-specific native entry to trace, reached automatically at launch with the live Activity and an **empty** JSON object. Java does not fetch a response and hand it to this entry. Native side effects can occur before the returned JSON is consumed. Loading a fixed named library and having this JNI signature are not, alone, proof of a DEX loader.

`requested` is set before execution and is never reset in the reviewed class. An exception still leaves it true. Recreating the Activity in the same process does not naturally repeat this entry; a fresh process is needed for reliable launch-to-response experiments. This is a process-local once flag, not a persistent response cache.

## F4-J02: Native return controls ordinary game UI; range check is not DEX size

**Confidence: high.**

`dev/tracebasinmoss/routepearl/RuntimeConfig.java:68–82`, `invokeSuspend`, catches every `Throwable`, converts failure to null, constructs default `AppConfig` on null, and updates the state flow. The default constructor supplies `levelCount=72`, `showHelp=true` (`dev/tracebasinmoss/routepearl/AppConfig.java:17–19`). A native failure may therefore leave a functioning game screen.

`dev/tracebasinmoss/routepearl/RuntimeConfigKt.java:20–35`, `numberOrNull`, accepts an actual JSON `Number` only if finite and exactly representable as a Java signed integer. `toAppConfig` at lines 40–57 then reads:

```java
Integer n = numberOrNull(json, "level_count");
// Accept 1 through 72; otherwise default 72.
Boolean showHelp = booleanOrNull(json, "show_help");
// Actual Boolean only; otherwise default true.
```

The original range condition is `1 > iIntValue2 || iIntValue2 >= 73` at line 47. `booleanOrNull` checks `instanceof Boolean` at lines 10–17. The corresponding smali implementation begins at `dev/tracebasinmoss/routepearl/RuntimeConfigKt.smali:271`.

Consumers demonstrate meaning: `dev/tracebasinmoss/routepearl/MainActivityKt.java:1070` uses `getLevelCount()` to select unlocked game levels, line 1391 builds `IntRange(1, levelCount)`, and lines 1078/1200 use `getShowHelp()` for help UI. This check constrains the game configuration **after** the native call; it does not constrain DEX length. An analyzer must not use 72/73 as payload-size evidence.

`dev/tracebasinmoss/routepearl/LocalStore.java:15–26` stores game progress under `route_progress`, keys `best_<level>`. No response or DEX cache is implemented by that class.

## Network endpoints, request identity and payload size

No app-specific URL, request method, HTTP header/body construction, response decoding, DEX byte-array construction, or DEX size check was found in the Java path above. The only native-bound JSON is freshly allocated and empty. Recover endpoint, request identity, response schema, cache behavior and payload constraints from `libz5555xbasin.so`; this audit does not infer them from unrelated SDK traffic.

Adjust and AppsFlyer include HTTP clients. For example, `com/adjust/sdk/network/UtilNetworking.java:26–38` sets SDK connection options and opens HTTPS connections; `com/appsflyer/internal/AFc1aSDK.java:40–87` constructs SDK POST requests including `Content-Length` from the SDK request body. No demonstrated Java call chain links those content-length checks to the app's native DEX consumer. They are not evidence for a payload length condition.

## Dynamic code loading and reflection

No `DexClassLoader` or `InMemoryDexClassLoader` call was found in the decompiled Java tree. The fixed `System.loadLibrary` sites are the app wrapper above, `androidx/graphics/path/PathIteratorPreApi34Impl.java:12`, and `com/adjust/sdk/sig/NativeLibHelper.java:11`. The custom native library may invoke Java loading APIs through JNI, which would not require those API references in classes.dex.

Reflection matches in AndroidX, Adjust and AppsFlyer were not linked to an app-controlled hidden-API or class-loading chain. No app-specific reflection-abuse finding was established in Java.

## Anti-analysis / environment checks

No Java branch based on debugger, root, emulator, region or time was found controlling `RuntimeConfig.start`, `FestDrift.dev` or native-return parsing.

`i1/b.java:89–93` compares the fingerprint to `robolectric` in graphics initialization; the result is unused in the reconstructed code. `v/v0.java:15–29` chooses a Compose helper according to the same test environment marker. Neither demonstrates an app-specific gate on the native path. Native checks remain outside this audit.

## Crypto, sensitive data, accessibility and overlays

- Crypto misuse / hidden configuration: no app-specific Java key, IV, encryption or asset-decoding chain found. Native decoding remains subject to native analysis.
- Exfiltration: no app Java SMS/contact/call-log/clipboard/location/account read-to-network chain found. SDK advertising identifiers and network metadata access are present, but were not classified as app-specific exfiltration on their own.
- Accessibility / overlays: no declared services and no app-specific accessibility service or overlay abuse found. Manifest application and components are at `work/family4/dev.tracebasinmoss.routepearl/apktool/AndroidManifest.xml:32–63`.
- Permission mismatch: the manifest requests `FLASHLIGHT` at line 5, while broad Java searches found no torch/camera call. Confidence is low that this is unnecessary overall because the native code may call platform APIs. The declaration alone is not malicious behavior. Networking, advertising/referrer and vibration permissions are consistent with the bundled SDK/UI capabilities and are not family indicators by themselves.

## Input-derived extraction recommendations

An offline analyzer can discover the actual wrapper from DEX native method declarations having descriptor `(Landroid/app/Activity;Lorg/json/JSONObject;)Lorg/json/JSONObject;`, associate it with the class initializer's constant `System.loadLibrary` argument, and verify its callers. The empty constructor and process-once flag can be reported from DEX instructions. Match class names, native method names and library basenames from the supplied input, rather than hardcoding this package.

That Java evidence identifies the native target but cannot derive the response contract. Generate proof JSON only after the native analysis establishes the actual JSON keys, data encoding, size comparisons, destination class/method and required invocation signature. Unknown guards or consumers should produce `needs_review`. Preserve native size limits and distinguish them from the unrelated UI range above.

## Concrete candidate patterns for detection engineering

1. Activity startup invokes a wrapper whose native method accepts `(Activity, JSONObject)` and returns `JSONObject`; wrapper class loads an app-supplied native library. Example locations: `MainActivity.java:58`, `RuntimeConfig.java:67`, `FestDrift.java:9/15/20`. Useful triage pattern; requires native consumer evidence to become a family behavior detection.
2. A fresh empty `JSONObject` crosses that boundary; native result is parsed only for innocuous game fields, with catch-all failure converted to defaults. Locations: `RuntimeConfig.java:67–78`, `RuntimeConfigKt.java:42–57`. Correlation signal, not sufficient alone.
3. A static process-once boolean precedes coroutine dispatch to the native entry and is not reset. Location: `RuntimeConfig.java:105–112`. Explains repeated-launch testing behavior; unsuitable as a standalone maliciousness rule.

No Java-only YARA/Semgrep rule is marked validated here. Native decoded APIs plus proven response-to-loader data flow should provide the discriminating detection terms and conditions.
