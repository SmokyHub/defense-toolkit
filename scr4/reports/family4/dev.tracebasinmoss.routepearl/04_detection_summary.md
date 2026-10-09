# Family4 detection summary

See [the complete detection report](04_detection_report.md) for provenance,
commands, original-byte anchors and limits.

- `detections/yara/family4_native_loader.yar`: conservative extracted-ARM64 ELF
  rule combining the observed descriptor decoder and DEX validator. Matched the
  original sample with YARA-X 1.20.0 and legacy YARA; 24 distinct local negative
  ELFs did not match. Fifteen negatives are ARM64; this is a limited fixture and
  dependency corpus, not a measured clean-app false-positive rate.
- `detections/network_iocs/family4.md` and `.txt`: recovered native POST endpoint
  and host, with alert/monitor guidance and static provenance. Does not cover
  rotated domains or establish production payload behavior.
- No Semgrep rule was produced: the decompiled Java shows a native bootstrap,
  while the discriminating response-to-DEX behavior is native. Generic JNI and
  game-configuration patterns alone are too broad.
- The input-derived Python JNI/descriptor analyzer provides the primary contract
  recovery mechanism. The YARA rule remains compiler/ABI/topology-scoped and is
  not a whole-APK ZIP rule, a malware verdict or runtime execution proof.
