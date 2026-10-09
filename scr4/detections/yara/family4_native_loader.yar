// Surface: original, extracted little-endian ARM64 ELF; extract APK ZIP members first.
// Source: reports/family4/dev.tracebasinmoss.routepearl/04_detection_report.md,
// "Original-byte anchors"; upstream 02_native_analysis.md sections "DEX size and
// structure checks" and "Static extraction that survives selector changes".
// No domain, app/package/library name, response key, input hash or file offset is matched.
// SplitMix constants and DEX validation each have legitimate uses; require both exact
// implementation sequences plus JNI. This is a review signal, not a malware verdict.
// Compiler/register changes and changed limits can evade this deliberately narrow rule.
// Branch displacement bytes alone are wildcarded; only one original build is available.
rule SUSP_Android_Family4_Arm64NativeLoader_Oct26 {
  meta:
    author      = "APK Defense Lab"
    date        = "2026-10-09"
    description = "Detects the observed ARM64 Family4 descriptor decoder plus bounded DEX validator implementation"
    reference   = "reports/family4/dev.tracebasinmoss.routepearl/04_detection_report.md#original-byte-anchors"
    upstream    = "reports/family4/dev.tracebasinmoss.routepearl/02_native_analysis.md"
    confidence  = "medium"
    surface     = "original extracted ARM64 ELF, not compressed APK ZIP"
    validation  = "original sample matched; limited local negative corpus; see detection report"

  strings:
    $jni            = "JNI_OnLoad" ascii fullword
    // Original decoder's interleaved construction of SplitMix64 constants.
    $descriptor_mix = {
      2B B7 9C D2 0C 9A F2 F2 8B 9C A3 F2 AD 1D 00 12
      AB ED C8 F2 0B EB F7 F2
    }
    // Original unsigned 112..33554432-byte guard, then DEX magic inspection.
    $dex_size       = {
      09 40 A0 92 0A F2 9F 92 29 00 09 8B 0A C0 BF F2
      3F 01 0A EB ?3 ?? ?? 54
    }
    $dex_magic      = {
      08 00 40 39 1F 91 01 71 ?1 ?? ?? 54
      08 04 40 39 1F 95 01 71 ?1 ?? ?? 54
      08 08 40 39 1F E1 01 71 ?1 ?? ?? 54
      08 0C 40 39 1F 29 00 71
    }

  condition:
    filesize < 32MB and
    uint32(0) == 0x464c457f and uint8(4) == 2 and uint8(5) == 1 and
    uint16(18) == 183 and all of them
}
