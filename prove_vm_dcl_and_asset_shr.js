'use strict';

const LOG_PREFIX = '[VM-ASSET-TRACE]';
// VM decoding is the default. Java hooks are optional and never required for native tracing.
// frida -P '{"javaHooks":true}' enables focused Java DCL events.
// legacyProof separately enables the old bypass/synthetic-execution harness.
const traceOptions = { decodeVm: true, javaHooks: false };
let legacyProof = false;
rpc.exports = { init(stage, parameters) {
    parameters = parameters || {};
    legacyProof = parameters.legacyProof === true;
    if (parameters.decodeVm !== undefined) traceOptions.decodeVm = parameters.decodeVm === true;
    if (parameters.javaHooks !== undefined) traceOptions.javaHooks = parameters.javaHooks === true;
    startTrace();
    if (traceStarted && traceOptions.javaHooks) installOptionalJavaHooks();
} };
const scannedModules = new Set();


let targetModule = null;
let bridgeClassName = null;
let loggedSelectors = false;
let jniHooked = false;
let assetHooked = false;

let dclExecuted = false;
let inSyntheticDcl = false;
let capturedJniCtx = null;
let capturedAppCtx = null;
let rustTargetClassName = null;
let rustDclTrigger = null;

// Valid 140-byte minimal DEX (header_item + 2-entry map_list + valid SHA-1 & Adler32)
const VALID_EMPTY_DEX = [
    100, 101, 120, 10, 48, 51, 53, 0, 190, 11, 112, 217, 29, 156, 63, 136,
    115, 13, 14, 214, 202, 163, 119, 212, 82, 4, 101, 231, 50, 45, 54, 90,
    140, 0, 0, 0, 112, 0, 0, 0, 120, 86, 52, 18, 0, 0, 0, 0,
    0, 0, 0, 0, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 0, 112, 0, 0, 0,
    2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 0, 1, 0, 0, 0, 112, 0, 0, 0
];

const hookedBridgeClasses = new Set();
const inspectedAssets = new Set();
const handledLibs = new Set();
const bypassedGates = new Set();

const runtimeHints = {
    soName: null,
    entry: null,
    selector: null,
    eval: null,
    chacha: null,
    rustVmDisp: null,
    rustStrStub: null,
    rustStrWrap: null,
    rustAssetOrch: null,
    rustAssetOpen: null,
    rustDclExec: null,
    rustStateStep: null,
    jniCallers: {}
};

function formatCallerOffset(retAddr) {
    try {
        const mod = Process.findModuleByAddress(ptr(retAddr));
        return mod ? ` (caller: ${mod.name}+${ptr(retAddr).sub(mod.base)})` : '';
    } catch (_) { return ''; }
}

function runInJavaVm(fn) {
    if (typeof Java.performNow === 'function') Java.performNow(fn);
    else Java.perform(fn);
}

function logBanner(title) {
    console.log('\n================================================================================');
    console.log(`${LOG_PREFIX} ${title}`);
    console.log('================================================================================');
}

function isInTargetModule(address) {
    try { return isCandidateAppModule(Process.findModuleByAddress(ptr(address))); }
    catch (_) { return false; }
}

function isCandidateAppModule(mod) {
    if (!mod || !mod.name) return false;
    const n = mod.name;
    if (!n.startsWith('lib') || !n.endsWith('.so')) return false;
    const sysPrefixes = [
        'libart', 'libandroid', 'libc.', 'libm.', 'libdl.', 'liblog',
        'libopenjdk', 'libjavacore', 'libnativehelper', 'lib nativebridge',
        'libhoudini', 'libndk_translation', 'libwebviewchromium', 'libhwui',
        'libgui', 'libui', 'libbinder', 'libutils', 'libcutils', 'libbase',
        'libvndksupport', 'libz.', 'libsqlite', 'libssl', 'libcrypto', 'libicu',
        'libframework', 'libnetd', 'libconscrypt'
    ];
    for (let i = 0; i < sysPrefixes.length; i++) {
        if (n.startsWith(sysPrefixes[i])) return false;
    }
    if (
        mod.path &&
        (mod.path.startsWith('/system') ||
            mod.path.startsWith('/apex/') ||
            mod.path.startsWith('/vendor/') ||
            mod.path.startsWith('/product/'))
    ) {
        return false;
    }
    return true;
}

function findExportSafe(modName, exportName) {
    try {
        if (modName) {
            const m = Process.findModuleByName(modName);
            if (m && typeof m.findExportByName === 'function') {
                const p = m.findExportByName(exportName);
                if (p) return p;
            }
        }
        for (const mod of Process.enumerateModules()) {
            const address = mod.findExportByName(exportName);
            if (address) return address;
        }
    } catch (e) {
        // Ignore resolution errors
    }
    return null;
}

function findFuncStartIdx(u32, hitIdx, maxBackWords = 0x800, rBase = null, blTargetsSet = null) {
    const minIdx = Math.max(0, hitIdx - maxBackWords);
    for (let idx = hitIdx; idx >= minIdx; idx--) {
        const w = u32[idx];
        if (w === 0xd503233f || w === 0xd503237f || w === 0xd503245f) {
            return idx;
        }
        if (rBase && blTargetsSet && blTargetsSet.has(rBase.add(idx * 4).toString())) {
            return idx;
        }
        if (idx > 0) {
            const prev = u32[idx - 1];
            const prevIsBoundary =
                prev === 0xd65f03c0 ||
                prev === 0x00000000 ||
                ((prev & 0xffe0001f) >>> 0) === 0xd4200000 ||
                (prev >>> 26) === 0x05;
            if (prevIsBoundary) {
                const isSubSp = ((w & 0xff0003ff) >>> 0) === 0xd10003ff;
                const isStpPre = ((w & 0xffc003ff) >>> 0) === 0xa98003ff;
                if (isSubSp || isStpPre) {
                    return idx;
                }
            }
        }
    }
    return null;
}

function setupRustVmHooksAndDecryptStrings(mod, rxRanges, blCallers, blTargetsSet, splitmixFuncs) {
    const base = mod.base;
    let strStubAddr = null;
    let vmDispAddr = null;

    // 1. Locate the Rust bytecode VM dispatcher (SplitMix64 function), the string VM stub, and the high-fanout
    //    string wrapper by 2-hop or 3-hop `bl` call-graph fanout (independent of stub register-move instructions).
    let strWrapAddr = null;
    let strWrapMidAddr = null;
    let bestCallerCount = 0;

    const splitmixArr = Array.from(splitmixFuncs);
    for (let s = 0; s < splitmixArr.length; s++) {
        const candDisp = ptr(splitmixArr[s]);
        const dispCallers = blCallers.get(candDisp.toString()) || [];
        for (let c = 0; c < dispCallers.length; c++) {
            const stubCallSite = dispCallers[c];
            for (let r = 0; r < rxRanges.length; r++) {
                const rBase = rxRanges[r].base;
                const rEnd = rBase.add(rxRanges[r].size);
                if (stubCallSite.compare(rBase) < 0 || stubCallSite.compare(rEnd) >= 0) continue;

                const u32 = rxRanges[r].u32;
                const callIdx = stubCallSite.sub(rBase).toInt32() >>> 2;
                const stubFnIdx = findFuncStartIdx(u32, callIdx, 0x60, rBase, blTargetsSet);
                if (stubFnIdx === null) continue;

                const candStub = rBase.add(stubFnIdx * 4);
                const stubCallers = blCallers.get(candStub.toString()) || [];
                for (let sc = 0; sc < stubCallers.length; sc++) {
                    const wrapCallSite = stubCallers[sc];
                    for (let r2 = 0; r2 < rxRanges.length; r2++) {
                        const rBase2 = rxRanges[r2].base;
                        const rEnd2 = rBase2.add(rxRanges[r2].size);
                        if (wrapCallSite.compare(rBase2) < 0 || wrapCallSite.compare(rEnd2) >= 0) continue;

                        const u32_2 = rxRanges[r2].u32;
                        const wCallIdx = wrapCallSite.sub(rBase2).toInt32() >>> 2;
                        const wrapFnIdx = findFuncStartIdx(u32_2, wCallIdx, 0x60, rBase2, blTargetsSet);
                        if (wrapFnIdx === null) continue;

                        const candWrap = rBase2.add(wrapFnIdx * 4);
                        const wrapCallList = blCallers.get(candWrap.toString()) || [];
                        const cnt = wrapCallList.length;
                        if (cnt > bestCallerCount && cnt >= 20) {
                            bestCallerCount = cnt;
                            vmDispAddr = candDisp;
                            strStubAddr = candStub;
                            strWrapAddr = candWrap;
                            strWrapMidAddr = null;
                        } else if (cnt > 0 && cnt < 20) {
                            // 3-hop wrapper chain: candStub (e.g. 0xf60b0) -> candWrap (0x9b56c) -> candWrap2 (0x9948c)
                            for (let wc = 0; wc < wrapCallList.length; wc++) {
                                const wrap2CallSite = wrapCallList[wc];
                                for (let r3 = 0; r3 < rxRanges.length; r3++) {
                                    const rBase3 = rxRanges[r3].base;
                                    const rEnd3 = rBase3.add(rxRanges[r3].size);
                                    if (wrap2CallSite.compare(rBase3) < 0 || wrap2CallSite.compare(rEnd3) >= 0) continue;

                                    const u32_3 = rxRanges[r3].u32;
                                    const w2CallIdx = wrap2CallSite.sub(rBase3).toInt32() >>> 2;
                                    const wrap2FnIdx = findFuncStartIdx(u32_3, w2CallIdx, 0x60, rBase3, blTargetsSet);
                                    if (wrap2FnIdx === null) continue;

                                    const candWrap2 = rBase3.add(wrap2FnIdx * 4);
                                    const cnt2 = (blCallers.get(candWrap2.toString()) || []).length;
                                    if (cnt2 > bestCallerCount && cnt2 >= 20) {
                                        bestCallerCount = cnt2;
                                        vmDispAddr = candDisp;
                                        strStubAddr = candStub;
                                        strWrapAddr = candWrap2;
                                        strWrapMidAddr = candWrap;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (!strStubAddr || !vmDispAddr || !strWrapAddr) return false;

    const dispOff = `0x${vmDispAddr.sub(base).toString(16)}`;
    const stubOff = `0x${strStubAddr.sub(base).toString(16)}`;
    const wrapOff = `0x${strWrapAddr.sub(base).toString(16)}`;
    runtimeHints.rustVmDisp = dispOff;
    runtimeHints.rustStrStub = stubOff;
    runtimeHints.rustStrWrap = wrapOff;

    console.log(`${LOG_PREFIX} [VM Bytecode VM] Dispatcher @ ${vmDispAddr} (offset ${dispOff})`);
    console.log(`${LOG_PREFIX} [VM String VM]   VM Stub    @ ${strStubAddr} (offset ${stubOff})`);
    console.log(`${LOG_PREFIX} [VM String Wrap] Wrapper    @ ${strWrapAddr} (offset ${wrapOff}, ${bestCallerCount} callsites)`);

    // 2b. Check for an indirect descriptor-table string thunk (e.g. `ldp x9, x1, [x0]; ldr w2, [x0, #0x10]; mov x0, x9; b #strWrapAddr`).
    const descThunkSet = new Set();
    for (let r = 0; r < rxRanges.length; r++) {
        const rBase = rxRanges[r].base;
        const u32 = rxRanges[r].u32;
        for (let i = 0; i < u32.length; i++) {
            const w = u32[i];
            if ((w >>> 26) === 0x05) {
                let imm26 = w & 0x3ffffff;
                if (imm26 & 0x2000000) imm26 -= 0x4000000;
                const bTarget = rBase.add((i + imm26) * 4);
                if (bTarget.equals(strWrapAddr) || (strWrapMidAddr && bTarget.equals(strWrapMidAddr))) {
                    const thunkIdx = findFuncStartIdx(u32, i, 8, rBase, blTargetsSet);
                    if (thunkIdx !== null && i - thunkIdx <= 6) {
                        for (let k = thunkIdx; k < i; k++) {
                            // ldp xRt, x1, [x0]
                            if (((u32[k] & 0xffc07fe0) >>> 0) === 0xa9400400) {
                                const thunkAddr = rBase.add(thunkIdx * 4);
                                descThunkSet.add(thunkAddr.toString());
                                console.log(
                                    `${LOG_PREFIX} [VM String Desc] Thunk      @ ${thunkAddr} (offset 0x${thunkAddr.sub(base).toString(16)})`
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Decode all `bl #strWrapAddr` (plus mid-wrapper & descriptor-thunk) callsites and invoke `strStubAddr` live.
    const strStubFn = new NativeFunction(strStubAddr, 'void', ['pointer', 'uint64', 'uint32', 'pointer']);
    const MAX_DEC_LEN = 8192;
    const outBuf = Memory.alloc(MAX_DEC_LEN);
    const allCallEntries = [];
    const wrapCallers = blCallers.get(strWrapAddr.toString()) || [];
    for (let i = 0; i < wrapCallers.length; i++) {
        allCallEntries.push({ site: wrapCallers[i], isDesc: false });
    }
    if (strWrapMidAddr) {
        const midCallers = blCallers.get(strWrapMidAddr.toString()) || [];
        for (let i = 0; i < midCallers.length; i++) {
            allCallEntries.push({ site: midCallers[i], isDesc: false });
        }
    }
    descThunkSet.forEach((thunkStr) => {
        const thunkCallers = blCallers.get(thunkStr) || [];
        for (let i = 0; i < thunkCallers.length; i++) {
            allCallEntries.push({ site: thunkCallers[i], isDesc: true });
        }
    });

    const decryptedCache = new Map();
    const fnByString = new Map();
    let cfgPathStr = null;

    const interestingStrings = new Set([
        'dalvik/system/InMemoryDexClassLoader',
        '(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V',
        'java/nio/ByteBuffer',
        '([B)Ljava/nio/ByteBuffer;',
        'getClassLoader',
        'loadClass',
        'loadRes',
        '()Landroid/content/res/AssetManager;',
        'currentActivityThread',
        'currentApplication',
        '/proc/self/maps',
        '/proc/self/status',
        'TracerPid:',
        '/dev/qemu_pipe',
        '/sys/fs/selinux/enforce',
        '/system/framework/XposedBridge.jar',
        'ro.hardware',
        'cutf_cvm',
        'hook_frida',
        'hook_frida_port'
    ]);

    for (let c = 0; c < allCallEntries.length; c++) {
        const callSite = allCallEntries[c].site;
        const isDescCall = allCallEntries[c].isDesc;
        for (let r = 0; r < rxRanges.length; r++) {
            const rBase = rxRanges[r].base;
            const rEnd = rBase.add(rxRanges[r].size);
            if (callSite.compare(rBase) < 0 || callSite.compare(rEnd) >= 0) continue;

            const u32 = rxRanges[r].u32;
            const idx = callSite.sub(rBase).toInt32() >>> 2;
            const regPtrs = new Array(32).fill(null);
            let w1Len = null;
            let w2Key = 0;

            for (let j = Math.max(0, idx - 24); j < idx; j++) {
                const w = u32[j];
                const pc = rBase.add(j * 4);
                const rd = w & 0x1f;

                if (((w & 0x9f000000) >>> 0) === 0x10000000) {
                    // adr xRd, #imm21
                    let imm21 = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
                    if (imm21 & 0x100000) imm21 -= 0x200000;
                    regPtrs[rd] = pc.add(imm21);
                } else if (((w & 0x9f000000) >>> 0) === 0x90000000) {
                    // adrp xRd, #imm21
                    let imm21 = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
                    if (imm21 & 0x100000) imm21 -= 0x200000;
                    const pageBase = pc.and(ptr('0xfffffffffffff000'));
                    regPtrs[rd] = pageBase.add(imm21 * 4096);
                } else if (((w & 0xff800000) >>> 0) === 0x91000000) {
                    // add xRd, xRn, #imm12
                    const rn = (w >>> 5) & 0x1f;
                    let imm12 = (w >>> 10) & 0xfff;
                    if ((w >>> 22) & 1) imm12 <<= 12;
                    if (regPtrs[rn] !== null) {
                        regPtrs[rd] = regPtrs[rn].add(imm12);
                    }
                } else if (((w & 0xffe0ffe0) >>> 0) === 0xaa0003e0) {
                    // mov xRd, xRm (orr xRd, xzr, xRm)
                    const rm = (w >>> 16) & 0x1f;
                    regPtrs[rd] = regPtrs[rm];
                } else if (((w & 0xff80001f) >>> 0) === 0x52800001) {
                    // movz w1, #imm16
                    w1Len = (w >>> 5) & 0xffff;
                } else if (((w & 0xff80001f) >>> 0) === 0x52800002) {
                    // movz w2, #imm16, lsl #(hw*16)
                    const hw = (w >>> 21) & 3;
                    w2Key = (((w >>> 5) & 0xffff) << (hw * 16)) >>> 0;
                } else if (((w & 0xff80001f) >>> 0) === 0x72800002) {
                    // movk w2, #imm16, lsl #(hw*16)
                    const hw = (w >>> 21) & 3;
                    const mask = (~(0xffff << (hw * 16))) >>> 0;
                    w2Key = ((w2Key & mask) | (((w >>> 5) & 0xffff) << (hw * 16))) >>> 0;
                }
            }

            let x0Ptr = regPtrs[0];
            if (isDescCall && x0Ptr !== null) {
                try {
                    let rawPtr = x0Ptr.readPointer();
                    if (rawPtr.compare(base) < 0 && rawPtr.compare(ptr(mod.size)) < 0) {
                        rawPtr = base.add(rawPtr);
                    }
                    w1Len = Number(x0Ptr.add(8).readU64());
                    w2Key = x0Ptr.add(16).readU32() >>> 0;
                    x0Ptr = rawPtr;
                } catch (e) {
                    x0Ptr = null;
                }
            }

            if (x0Ptr !== null && w1Len !== null && w1Len >= 1 && w1Len <= MAX_DEC_LEN && w2Key !== 0) {
                const cacheKey = `${x0Ptr.toString()}:${w1Len}:${w2Key}`;
                let text = decryptedCache.get(cacheKey);
                if (text === undefined) {
                    try {
                        strStubFn(x0Ptr, w1Len, w2Key, outBuf);
                        text = outBuf.readUtf8String(w1Len);
                        decryptedCache.set(cacheKey, text);
                        const relOff = `0x${x0Ptr.sub(base).toString(16)}`;
                        if (
                            interestingStrings.has(text) ||
                            text.endsWith('.cfg') ||
                            text.startsWith('https://') ||
                            text.startsWith('com.')
                        ) {
                            console.log(
                                `${LOG_PREFIX} [Decrypted VM Str] [decoder-invoked] module=${mod.name} rodata=${relOff} len=${w1Len} key=0x${w2Key.toString(16).padStart(8, '0')} -> "${text}"`
                            );
                        }
                    } catch (e) {
                        text = null;
                    }
                }
                if (text) {
                    const enclosingIdx = findFuncStartIdx(u32, idx, 0x800, rBase, blTargetsSet);
                    if (enclosingIdx !== null) {
                        const enclosingFn = rBase.add(enclosingIdx * 4);
                        fnByString.set(text, enclosingFn);
                        if (text.endsWith('.cfg')) {
                            cfgPathStr = text;
                            fnByString.set('__cfg_path__', enclosingFn);
                        }
                        if (text.startsWith('com.') && text.indexOf('.') !== text.lastIndexOf('.')) {
                            rustTargetClassName = text;
                        }
                    }
                }
            }
        }
    }

    // String recovery above is independent of the legacy bypass/proof routines below.
    if (!legacyProof) return true;

    // 4. Attach runtime filter on strStubAddr to sanitize anti-Frida/emulator needle strings in-place.
    const sanitizedNeedles = new Set([
        'frida',
        'xposed',
        ':69a2',
        'ranchu',
        'goldfish',
        'cutf_cvm',
        'cuttlefish_pipe',
        ' (deleted)',
        '/data/adb/modules/',
        'libhoudini.so',
        'libndk_translation.so'
    ]);

    Interceptor.attach(strStubAddr, {
        onEnter(args) {
            this.len = args[1].toInt32();
            this.outPtr = args[3];
        },
        onLeave() {
            if (this.len >= 4 && this.len <= 32 && this.outPtr && !this.outPtr.isNull()) {
                try {
                    const s = this.outPtr.readUtf8String(this.len);
                    if (sanitizedNeedles.has(s)) {
                        const replacement = 'z'.repeat(this.len);
                        this.outPtr.writeUtf8String(replacement);
                    }
                } catch (e) {
                    // Ignore non-UTF8 buffers
                }
            }
        }
    });

    // 5. Resolve orchestrator (supporting both monolithic 3-arg and split outer-3-arg + inner-6-arg layouts),
    //    asset reader, DCL executor, state-machine step, and anti-analysis gate functions.
    function findEnclosingFnOfCallsite(callSite, maxBack = 0x400) {
        for (let r = 0; r < rxRanges.length; r++) {
            const rBase = rxRanges[r].base;
            const rEnd = rBase.add(rxRanges[r].size);
            if (callSite.compare(rBase) >= 0 && callSite.compare(rEnd) < 0) {
                const u32 = rxRanges[r].u32;
                const callIdx = callSite.sub(rBase).toInt32() >>> 2;
                const fnIdx = findFuncStartIdx(u32, callIdx, maxBack, rBase, blTargetsSet);
                return fnIdx !== null ? rBase.add(fnIdx * 4) : null;
            }
        }
        return null;
    }

    function hasShortRetWithin(fnAddr, maxWords = 0x90) {
        for (let r = 0; r < rxRanges.length; r++) {
            const rBase = rxRanges[r].base;
            const rEnd = rBase.add(rxRanges[r].size);
            if (fnAddr.compare(rBase) >= 0 && fnAddr.compare(rEnd) < 0) {
                const u32 = rxRanges[r].u32;
                const startIdx = fnAddr.sub(rBase).toInt32() >>> 2;
                const endIdx = Math.min(u32.length, startIdx + maxWords);
                for (let k = startIdx; k < endIdx; k++) {
                    if (u32[k] === 0xd65f03c0) return true;
                }
            }
        }
        return false;
    }

    let assetOrchFn = fnByString.get('__cfg_path__') || fnByString.get('currentActivityThread') || null;
    let innerAssetOrchFn = null;
    const dclExecFn = fnByString.get('dalvik/system/InMemoryDexClassLoader') || null;
    const assetOpenFn = fnByString.get('()Landroid/content/res/AssetManager;') || null;

    let stateStepFn = null;
    if (assetOrchFn) {
        const orchCallers = blCallers.get(assetOrchFn.toString()) || [];
        if (orchCallers.length > 0) {
            const callerFn = findEnclosingFnOfCallsite(orchCallers[0], 0x400);
            if (callerFn) {
                // Check if callerFn is a split outer 3-arg JSON parser (short < 0x90 words) called by stateStepFn
                const grandCallers = blCallers.get(callerFn.toString()) || [];
                if (grandCallers.length === 1 && hasShortRetWithin(callerFn, 0x90)) {
                    const grandCallerFn = findEnclosingFnOfCallsite(grandCallers[0], 0x400);
                    if (grandCallerFn) {
                        innerAssetOrchFn = assetOrchFn;
                        assetOrchFn = callerFn;
                        stateStepFn = grandCallerFn;
                    }
                }
                if (!stateStepFn) {
                    stateStepFn = callerFn;
                }
            }
        }
    }

    if (assetOrchFn) {
        runtimeHints.rustAssetOrch = `0x${assetOrchFn.sub(base).toString(16)}`;
        console.log(`${LOG_PREFIX} [VM Asset+DCL]   Orchestrator @ ${assetOrchFn} (offset ${runtimeHints.rustAssetOrch})`);
    }
    if (innerAssetOrchFn) {
        const innerOff = `0x${innerAssetOrchFn.sub(base).toString(16)}`;
        console.log(`${LOG_PREFIX} [VM Asset+DCL]   Inner Pipe   @ ${innerAssetOrchFn} (offset ${innerOff})`);
    }
    if (assetOpenFn) {
        runtimeHints.rustAssetOpen = `0x${assetOpenFn.sub(base).toString(16)}`;
        console.log(`${LOG_PREFIX} [VM Asset Open]  JNI Helper   @ ${assetOpenFn} (offset ${runtimeHints.rustAssetOpen})`);
    }
    if (dclExecFn) {
        runtimeHints.rustDclExec = `0x${dclExecFn.sub(base).toString(16)}`;
        console.log(`${LOG_PREFIX} [VM DCL Loader]  InMemoryDCL  @ ${dclExecFn} (offset ${runtimeHints.rustDclExec})`);
    }
    if (stateStepFn) {
        runtimeHints.rustStateStep = `0x${stateStepFn.sub(base).toString(16)}`;
        console.log(`${LOG_PREFIX} [VM State Mach]  Step Driver  @ ${stateStepFn} (offset ${runtimeHints.rustStateStep})`);
    }

    // 6. Discover and bypass all anti-analysis / anti-Frida / anti-emulator gates in stateStepFn + watchdog.
    const gateFnSet = new Set();
    const nonGateFns = new Set();
    if (assetOrchFn) nonGateFns.add(assetOrchFn.toString());
    if (innerAssetOrchFn) nonGateFns.add(innerAssetOrchFn.toString());
    if (dclExecFn) nonGateFns.add(dclExecFn.toString());
    if (assetOpenFn) nonGateFns.add(assetOpenFn.toString());
    if (stateStepFn) nonGateFns.add(stateStepFn.toString());
    const curAppFn = fnByString.get('currentApplication');
    if (curAppFn) nonGateFns.add(curAppFn.toString());

    if (stateStepFn) {
        for (let r = 0; r < rxRanges.length; r++) {
            const rBase = rxRanges[r].base;
            const rEnd = rBase.add(rxRanges[r].size);
            if (stateStepFn.compare(rBase) < 0 || stateStepFn.compare(rEnd) >= 0) continue;

            const u32 = rxRanges[r].u32;
            const stepIdx = stateStepFn.sub(rBase).toInt32() >>> 2;
            const maxStepIdx = Math.min(u32.length - 6, stepIdx + 0x160);

            for (let i = stepIdx; i < maxStepIdx; i++) {
                const w = u32[i];
                if (w === 0xd65f03c0) break;
                if ((w >>> 26) === 0x25) {
                    let imm26 = w & 0x3ffffff;
                    if (imm26 & 0x2000000) imm26 -= 0x4000000;
                    const targetAddr = rBase.add((i + imm26) * 4);
                    if (nonGateFns.has(targetAddr.toString())) continue;

                    const w1 = u32[i + 1];
                    const w2 = u32[i + 2];

                    const isTbnzW0 = ((w1 & 0xff00001f) >>> 0) === 0x37000000;
                    const isTbzErr =
                        ((w1 & 0xff00001f) >>> 0) === 0x36000000 &&
                        ((w2 & 0xff800000) >>> 0) === 0x52800000 &&
                        ((w2 >>> 5) & 0xffff) <= 2;

                    // Jump-table indexed by w0 within i+1..i+4: `ldr xRd, [xRn, w0, uxtw #3]; br xRd`
                    // (excluding state 3 = context_error and state 7 = authentication_error)
                    let isJumpTableW0 = false;
                    let isNonGateState = false;
                    for (let m = 1; m <= 4; m++) {
                        const wm = u32[i + m];
                        if (((wm & 0xffe00000) >>> 0) === 0x52800000) {
                            const stImm = (wm >>> 5) & 0xffff;
                            if (stImm === 3 || stImm === 7) isNonGateState = true;
                        }
                        if (((wm & 0xfffffc00) >>> 0) === 0xf8605800) {
                            isJumpTableW0 = true;
                        }
                    }
                    if (isNonGateState) isJumpTableW0 = false;

                    if (isTbnzW0 || isTbzErr || isJumpTableW0) {
                        gateFnSet.add(targetAddr.toString());
                        // Also check if targetAddr is a short wrapper (< 24 insns) with a tail-call b/bl (e.g. 0xb31d0 -> 0x9b920 + 0x9c92c)
                        if (targetAddr.compare(rBase) >= 0 && targetAddr.compare(rEnd) < 0) {
                            const tIdx = targetAddr.sub(rBase).toInt32() >>> 2;
                            let retIdx = -1;
                            for (let k = tIdx; k < Math.min(u32.length, tIdx + 24); k++) {
                                if (u32[k] === 0xd65f03c0) {
                                    retIdx = k;
                                    break;
                                }
                            }
                            if (retIdx !== -1) {
                                for (let k = tIdx; k < retIdx; k++) {
                                    const wk = u32[k];
                                    const top6 = wk >>> 26;
                                    if (top6 === 0x05 || top6 === 0x25) {
                                        // Skip helper calls preceded by `add x0, x0, #imm` (e.g. atomic/Arc field getters)
                                        const prevW = k > tIdx ? u32[k - 1] : 0;
                                        if (top6 === 0x25 && ((prevW & 0xffc003ff) >>> 0) === 0x91000000) {
                                            continue;
                                        }
                                        let immk = wk & 0x3ffffff;
                                        if (immk & 0x2000000) immk -= 0x4000000;
                                        const subTarget = rBase.add((k + immk) * 4).toString();
                                        if (!nonGateFns.has(subTarget)) {
                                            gateFnSet.add(subTarget);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    gateFnSet.forEach((gateAddrStr) => {
        const gateAddr = ptr(gateAddrStr);
        const gateOff = `0x${gateAddr.sub(base).toString(16)}`;
        try {
            Interceptor.replace(
                gateAddr,
                new NativeCallback(
                    function () {
                        if (!bypassedGates.has(gateOff)) {
                            bypassedGates.add(gateOff);
                            console.log(`${LOG_PREFIX} [Anti-Analysis Gate] Bypassed check @ ${gateAddr} (offset ${gateOff}) -> forced 0`);
                        }
                        return 0;
                    },
                    'uint32',
                    []
                )
            );
        } catch (e) {
            // Fallback to onLeave if replace fails
            Interceptor.attach(gateAddr, {
                onLeave(retval) {
                    if (!bypassedGates.has(gateOff)) {
                        bypassedGates.add(gateOff);
                        console.log(`${LOG_PREFIX} [Anti-Analysis Gate] Bypassed check @ ${gateAddr} (offset ${gateOff}) -> forced 0`);
                    }
                    retval.replace(0);
                }
            });
        }
    });

    // 7. Dynamically extract JSON activation schema (outerKey, flagKey, cipherKey, container type, keyLen)
    //    from the first 0x1c0 bytes of assetOrchFn (and innerAssetOrchFn if split), then hook orchestrator, assetOpenFn, and dclExecFn.
    let outerJsonKey = 'data';
    let flagJsonKey = 'isE';
    let cipherJsonKey = 'aesKey';
    let outerIsArray = true;
    let expectedKeyLen = 16;

    if (assetOrchFn) {
        try {
            const orchWords = new Uint32Array(assetOrchFn.readByteArray(0x1c0));
            const extractedKeys = [];
            let curPtr0 = null;
            let curPage0 = null;
            let curLen1 = null;
            let curPtr1 = null;
            let curPage1 = null;
            let curLen2 = null;

            for (let i = 0; i < orchWords.length; i++) {
                const w = orchWords[i];
                const pc = assetOrchFn.add(i * 4);

                if (((w & 0x9f00001f) >>> 0) === 0x10000000) {
                    let imm21 = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
                    if (imm21 & 0x100000) imm21 -= 0x200000;
                    curPtr0 = pc.add(imm21);
                } else if (((w & 0x9f00001f) >>> 0) === 0x10000001) {
                    let imm21 = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
                    if (imm21 & 0x100000) imm21 -= 0x200000;
                    curPtr1 = pc.add(imm21);
                } else if (((w & 0x9f00001f) >>> 0) === 0x90000000) {
                    let imm21 = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
                    if (imm21 & 0x100000) imm21 -= 0x200000;
                    curPage0 = pc.and(ptr('0xfffffffffffff000')).add(imm21 * 4096);
                } else if (((w & 0x9f00001f) >>> 0) === 0x90000001) {
                    let imm21 = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
                    if (imm21 & 0x100000) imm21 -= 0x200000;
                    curPage1 = pc.and(ptr('0xfffffffffffff000')).add(imm21 * 4096);
                } else if (((w & 0xffc003ff) >>> 0) === 0x91000000 && curPage0 !== null) {
                    let imm12 = (w >>> 10) & 0xfff;
                    if ((w >>> 22) & 1) imm12 <<= 12;
                    curPtr0 = curPage0.add(imm12);
                } else if (((w & 0xffc003ff) >>> 0) === 0x91000021 && curPage1 !== null) {
                    let imm12 = (w >>> 10) & 0xfff;
                    if ((w >>> 22) & 1) imm12 <<= 12;
                    curPtr1 = curPage1.add(imm12);
                } else if (((w & 0xff80001f) >>> 0) === 0x52800001) {
                    curLen1 = (w >>> 5) & 0xffff;
                } else if (((w & 0xff80001f) >>> 0) === 0x52800002) {
                    curLen2 = (w >>> 5) & 0xffff;
                } else if ((w >>> 26) === 0x25) {
                    const candPtr = curPtr0 !== null && curLen1 !== null ? curPtr0 : curPtr1;
                    const candLen = curPtr0 !== null && curLen1 !== null ? curLen1 : curLen2;
                    if (candPtr !== null && candLen !== null && candLen >= 2 && candLen <= 24 && extractedKeys.length < 3) {
                        try {
                            const s = candPtr.readUtf8String(candLen);
                            if (s && /^[A-Za-z0-9_]+$/.test(s)) {
                                extractedKeys.push(s);
                            }
                        } catch (e) {
                            // Ignore
                        }
                    }
                    curPtr0 = null;
                    curPage0 = null;
                    curLen1 = null;
                    curPtr1 = null;
                    curPage1 = null;
                    curLen2 = null;
                } else if (extractedKeys.length === 1 && ((w & 0xffc003ff) >>> 0) === 0x7100011f) {
                    // cmp w8, #imm12 right after outerKey lookup (4 = serde_json::Value::Array, 5 = Value::Object)
                    const disc = (w >>> 10) & 0xfff;
                    if (disc === 4) outerIsArray = true;
                    else if (disc === 5) outerIsArray = false;
                } else if (extractedKeys.length >= 3 && ((w & 0xffc0001f) >>> 0) === 0xf100001f) {
                    // cmp xRn, #imm12 for cipherKey length check (16, 24, or 32)
                    const klen = (w >>> 10) & 0xfff;
                    if (klen === 16 || klen === 24 || klen === 32) {
                        expectedKeyLen = klen;
                    }
                }
            }

            if (innerAssetOrchFn) {
                const innerWords = new Uint32Array(innerAssetOrchFn.readByteArray(0x60));
                for (let i = 0; i < innerWords.length; i++) {
                    const w = innerWords[i];
                    if (((w & 0xffc0001f) >>> 0) === 0xf100001f) {
                        const klen = (w >>> 10) & 0xfff;
                        if (klen === 16 || klen === 24 || klen === 32) {
                            expectedKeyLen = klen;
                            break;
                        }
                    }
                }
            }

            if (extractedKeys.length >= 3) {
                outerJsonKey = extractedKeys[0];
                flagJsonKey = extractedKeys[1];
                cipherJsonKey = extractedKeys[2];
                console.log(
                    `${LOG_PREFIX} [VM JSON Schema] Extracted keys: outer="${outerJsonKey}" (${outerIsArray ? 'Array' : 'Object'}), flag="${flagJsonKey}", key="${cipherJsonKey}" (len=${expectedKeyLen})`
                );
            }
        } catch (e) {
            // Keep default schema keys
        }
    }

    const dummyKeyStr = '0123456789abcdef0123456789abcdef'.substring(0, expectedKeyLen);
    const innerObj = {};
    innerObj[flagJsonKey] = 1;
    innerObj[cipherJsonKey] = dummyKeyStr;
    const outerObj = {};
    outerObj[outerJsonKey] = outerIsArray ? [innerObj] : innerObj;
    const synthJson = JSON.stringify(outerObj);
    const synthBuf = Memory.allocUtf8String(synthJson);
    const dummyDex = Memory.alloc(VALID_EMPTY_DEX.length);
    dummyDex.writeByteArray(VALID_EMPTY_DEX);
    const callAssetOrch = assetOrchFn ? new NativeFunction(assetOrchFn, 'void', ['pointer', 'pointer', 'uint64']) : null;
    const callDclExec = dclExecFn
        ? new NativeFunction(dclExecFn, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'uint64', 'pointer', 'uint64'])
        : null;
    let inSyntheticOrch = false;

    if (callDclExec) {
        rustDclTrigger = function () {
            if (!inSyntheticOrch || dclExecuted || !capturedJniCtx || !capturedAppCtx) return;
            inSyntheticDcl = true;
            try {
                callDclExec(
                    capturedJniCtx,
                    capturedAppCtx,
                    capturedAppCtx,
                    dummyDex,
                    VALID_EMPTY_DEX.length,
                    synthBuf,
                    synthJson.length
                );
            } catch (e) {
                console.log(`${LOG_PREFIX} Note during native DCL invocation: ${e}`);
            } finally {
                inSyntheticDcl = false;
            }
        };
    }

    if (assetOrchFn) {
        Interceptor.attach(assetOrchFn, {
            onEnter(args) {
                const jsonPtr = args[1];
                const jsonLen = args[2].toInt32();
                if (!jsonPtr.isNull() && jsonLen > 0 && jsonLen < 4096) {
                    try {
                        const jsonStr = jsonPtr.readUtf8String(jsonLen);
                        console.log(`${LOG_PREFIX} [Native Asset Orch] ${runtimeHints.rustAssetOrch} input JSON: ${jsonStr}`);
                        if (jsonStr.indexOf(`"${cipherJsonKey}"`) === -1) {
                            inSyntheticOrch = true;
                            console.log(
                                `${LOG_PREFIX} [Native Asset Orch] Decoy/offline C2 JSON lacks "${cipherJsonKey}" -> substituting ${synthJson}`
                            );
                            args[1] = synthBuf;
                            args[2] = ptr(synthJson.length);
                        }
                    } catch (e) {
                        // Ignore
                    }
                }
            },
            onLeave() {
                inSyntheticOrch = false;
            }
        });
    }

    if (assetOpenFn) {
        Interceptor.attach(assetOpenFn, {
            onEnter(args) {
                capturedJniCtx = args[0];
                capturedAppCtx = args[1];
                const pathPtr = args[2];
                const pathLen = args[3].toInt32();
                if (!pathPtr.isNull() && pathLen > 0 && pathLen < 256) {
                    try {
                        const assetPath = pathPtr.readUtf8String(pathLen);
                        console.log(`${LOG_PREFIX} [Native Asset Read] ${runtimeHints.rustAssetOpen}("${assetPath}")`);
                    } catch (e) {
                        // Ignore read errors
                    }
                }
            }
        });
    }

    if (dclExecFn) {
        Interceptor.attach(dclExecFn, {
            onEnter(args) {
                dclExecuted = true;
                const dexLen = args[4].toInt32();
                logBanner(`SIGNAL: NATIVE DCL EXECUTOR (${runtimeHints.rustDclExec}) INVOKED (DEX size=${dexLen} bytes)`);
            }
        });
    }

    // 8. Hook stateStepFn (0x21c34) to observe state transitions and trigger native asset+DCL proof if C2 is offline.
    if (stateStepFn && callAssetOrch) {
        let triggeredFallback = false;

        Interceptor.attach(stateStepFn, {
            onEnter(args) {
                this.stateStruct = args[0];
                this.ctxPtr = args[1];
            },
            onLeave() {
                let outState = -1;
                try {
                    outState = this.stateStruct.add(0x48).readU32();
                } catch (e) {
                    return;
                }

                if (outState >= 0 && outState < 8 && !dclExecuted && !triggeredFallback && !this.ctxPtr.isNull()) {
                    triggeredFallback = true;
                    const statusNames = ['ok', 'blocked', 'empty', 'context_error', 'net_error', 'http_error', 'error', 'authentication_error'];
                    const statusName = statusNames[outState] || `state_${outState}`;
                    logBanner(`C2 STATE MACHINE ENDED WITH "${statusName}" — TRIGGERING NATIVE ASSET & DCL PIPELINE`);

                    inSyntheticOrch = true;
                    try {
                        callAssetOrch(this.ctxPtr, synthBuf, synthJson.length);
                    } catch (e) {
                        console.log(`${LOG_PREFIX} Note during native orchestrator invocation: ${e}`);
                    } finally {
                        inSyntheticOrch = false;
                    }
                }
            }
        });
    }

    return true;
}

// Pure recovery of the reviewed lowbias32/ciphertext-feedback string VM.
// Arguments come from ARM64 callsites, not a package/offset table. No app code is called.
function decodeFeedbackString(bytes, key) {
    let state = key >>> 0;
    let text = '';
    for (let i = 0; i < bytes.length; i++) {
        state = Math.imul(state ^ (state >>> 16), 0x7feb352d) >>> 0;
        state = Math.imul(state ^ (state >>> 15), 0x846ca68b) >>> 0;
        state = (state ^ (state >>> 16)) >>> 0;
        text += String.fromCharCode(bytes[i] ^ (state >>> 24));
        state = (state + 0x9e3779b9 + bytes[i]) >>> 0;
    }
    return text;
}

function recoverVmCallArguments(words, index, rangeBase) {
    const regs = new Array(32).fill(null);
    for (let j = Math.max(0, index - 24); j < index; j++) {
        const w = words[j], rd = w & 31, rn = (w >>> 5) & 31;
        const pc = rangeBase + j * 4;
        const adr = (w & 0x9f000000) >>> 0;
        if (adr === 0x10000000 || adr === 0x90000000) {
            let imm = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
            if (imm & 0x100000) imm -= 0x200000;
            regs[rd] = adr === 0x90000000 ? Math.floor(pc / 4096) * 4096 + imm * 4096 : pc + imm;
        } else if (((w & 0xff800000) >>> 0) === 0x91000000) {
            regs[rd] = regs[rn] === null ? null : regs[rn] + ((w >>> 10) & 0xfff) * ((w >>> 22) & 1 ? 4096 : 1);
        } else if (((w & 0xffe0ffe0) >>> 0) === 0xaa0003e0) {
            regs[rd] = regs[(w >>> 16) & 31];
        } else if (((w & 0x7f800000) >>> 0) === 0x52800000) {
            const shift = ((w >>> 21) & 3) * 16;
            regs[rd] = shift > 16 ? null : (((w >>> 5) & 0xffff) * Math.pow(2, shift)) >>> 0;
        } else if (((w & 0x7f800000) >>> 0) === 0x72800000) {
            const shift = ((w >>> 21) & 3) * 16;
            regs[rd] = shift > 16 || regs[rd] === null ? null :
                ((regs[rd] & ~(0xffff << shift)) | (((w >>> 5) & 0xffff) << shift)) >>> 0;
        } else if ((w >>> 26) === 0x25 || ((w & 0xfffffc1f) >>> 0) === 0xd63f0000) {
            // A previous call invalidates caller-saved values; never recycle its arguments.
            for (let r = 0; r < 19; r++) regs[r] = null;
        } else if ((w >>> 26) === 0x05 || ((w & 0xff000010) >>> 0) === 0x54000000 ||
                   ((w & 0x7e000000) >>> 0) === 0x34000000 ||
                   ((w & 0x7e000000) >>> 0) === 0x36000000) {
            // Do not pretend to resolve arguments across unknown control flow.
            regs.fill(null);
        } else if ((w & 0x0a000000) === 0x08000000) {
            // Loads overwrite destinations. Stores do not (except writeback, unsupported here).
            if (w & 0x00400000) {
                regs[rd] = null;
                if ((w & 0x3a000000) === 0x28000000) regs[(w >>> 10) & 31] = null;
            }
        } else if ((w & 0x1c000000) === 0x10000000 || (w & 0x0e000000) === 0x0a000000) {
            regs[rd] = null; // unmodelled integer operation
        }
    }
    return regs.slice(0, 3);
}

function recoverFeedbackVmStrings(mod, rxRanges) {
    const moduleBase = Number(mod.base.toString()), moduleEnd = moduleBase + mod.size;
    const groups = new Map();
    for (const range of rxRanges) {
        const words = range.u32, rangeBase = Number(range.base.toString());
        for (let i = 0; i < words.length; i++) {
            const w = words[i];
            if ((w >>> 26) !== 0x25) continue;
            const [address, length, key] = recoverVmCallArguments(words, i, rangeBase);
            if (address === null || length === null || key === null || length < 4 || length > 8192 ||
                address < moduleBase || address + length > moduleEnd) continue;
            let imm = w & 0x3ffffff;
            if (imm & 0x2000000) imm -= 0x4000000;
            const callee = rangeBase + (i + imm) * 4;
            if (callee < moduleBase || callee >= moduleEnd) continue;
            try {
                const bytes = new Uint8Array(ptr(address).readByteArray(length));
                const text = decodeFeedbackString(bytes, key);
                if (!/^[\x20-\x7e]+$/.test(text)) continue;
                let group = groups.get(callee);
                if (!group) { group = new Map(); groups.set(callee, group); }
                group.set(address + ':' + length + ':' + key, { address, length, key, text, site: rangeBase + i * 4 });
            } catch (_) { /* Unmapped or unreadable source: skip. */ }
        }
    }
    let recovered = 0;
    for (const [callee, group] of groups) {
        const strings = Array.from(group.values());
        // Demand multiple independently decoded long strings and a Java class/signature.
        // Random printable short bytes and selector constants are not VM evidence.
        if (strings.filter(x => x.length >= 12).length < 3 ||
            !strings.some(x => /^(?:java\/|dalvik\/|android\/|\(.*\)L)/.test(x.text))) continue;
        console.log(`${LOG_PREFIX} [VM string decoder] ${mod.name}+0x${(callee - moduleBase).toString(16)} transform=lowbias32-feedback recovered=${strings.length}`);
        for (const item of strings) {
            recovered++;
            if (!/ClassLoader|DexFile|DexPathList|ByteBuffer|loadClass|loadDex|loadRes|getAssets|getClassLoader|AssetManager|\.cfg$|\.dat$|\.enc$|^https?:|^com[./]|^\(/.test(item.text)) continue;
            console.log(`${LOG_PREFIX} [Decrypted VM Str] [static-recovered] module=${mod.name} callsite=0x${(item.site - moduleBase).toString(16)} rodata=0x${(item.address - moduleBase).toString(16)} len=${item.length} key=0x${item.key.toString(16)} -> ${JSON.stringify(item.text)}`);
        }
    }
    return recovered;
}

function inspectMappedNativeVmModule(mod) {
    if (!traceOptions.decodeVm || Process.arch !== 'arm64' || !mod || !isCandidateAppModule(mod)) return;
    const moduleKey = mod.path + '@' + mod.base;
    if (scannedModules.has(moduleKey)) return;
    scannedModules.add(moduleKey);

    try {
        const base = mod.base;
        const rawRxRanges = mod.enumerateRanges('r-x');
        const rxRanges = [];
        const selectorCandidates = [];
        const splitmixFuncs = new Set();
        const blCallers = new Map();
        const blTargetsSet = new Set();
        let chachaFnAddr = null;

        // Pass 1: Read r-x ranges and build a complete `bl` call-graph map (`blCallers` & `blTargetsSet`).
        for (let r = 0; r < rawRxRanges.length; r++) {
            const rBase = rawRxRanges[r].base;
            const rSize = rawRxRanges[r].size;
            let rawBuf = null;
            try {
                rawBuf = rBase.readByteArray(rSize);
            } catch (e) {
                continue;
            }
            if (!rawBuf) continue;

            const u32 = new Uint32Array(rawBuf);
            rxRanges.push({ base: rBase, size: rSize, u32 });

            for (let i = 0; i < u32.length; i++) {
                const w = u32[i];
                if ((w >>> 26) === 0x25) {
                    let imm26 = w & 0x3ffffff;
                    if (imm26 & 0x2000000) imm26 -= 0x4000000;
                    const target = rBase.add((i + imm26) * 4);
                    const targetStr = target.toString();
                    blTargetsSet.add(targetStr);
                    let list = blCallers.get(targetStr);
                    if (!list) {
                        list = [];
                        blCallers.set(targetStr, list);
                    }
                    list.push(rBase.add(i * 4));
                }
            }
        }

        const recovered = recoverFeedbackVmStrings(mod, rxRanges);
        if (recovered > 0 && !legacyProof) return;

        // Pass 2: Scan for JSON selector decoders, SplitMix64 VM dispatchers/evaluators, and ChaCha20 decryptors.
        for (let r = 0; r < rxRanges.length; r++) {
            const rBase = rxRanges[r].base;
            const u32 = rxRanges[r].u32;
            const nWords = u32.length;

            for (let i = 0; i < nWords - 16; i++) {
                const w = u32[i];
                const wNext = u32[i + 1];

                if (((w & 0xffffffe0) >>> 0) === 0xf9000020 && (wNext === 0xd65f03c0 || wNext === 0xd65f0fff)) {
                    const fnIdx = findFuncStartIdx(u32, i, 0x80, rBase, blTargetsSet);
                    if (fnIdx !== null) {
                        let hasBl = false;
                        for (let p = fnIdx; p < i; p++) {
                            if ((u32[p] >>> 26) === 0x25) {
                                hasBl = true;
                                break;
                            }
                        }
                        if (!hasBl) {
                            const fnAddr = rBase.add(fnIdx * 4);
                            if (!selectorCandidates.some((x) => x.equals(fnAddr))) {
                                selectorCandidates.push(fnAddr);
                            }
                        }
                    }
                }

                if (((w & 0xffffffe0) >>> 0) === 0xf2f7eb00) {
                    const fnIdx = findFuncStartIdx(u32, i, 0x200, rBase, blTargetsSet);
                    if (fnIdx !== null) {
                        splitmixFuncs.add(rBase.add(fnIdx * 4).toString());
                    }
                }

                if (((w & 0xffffffe0) >>> 0) === 0x528f0ca0 && chachaFnAddr === null) {
                    for (let k = 0; k < 16; k++) {
                        if (((u32[i + k] & 0xffffffe0) >>> 0) === 0x72ac2e00) {
                            const fnIdx = findFuncStartIdx(u32, i, 0x400, rBase, blTargetsSet);
                            if (fnIdx !== null) {
                                chachaFnAddr = rBase.add(fnIdx * 4);
                            }
                            break;
                        }
                    }
                }
            }
        }

        if (selectorCandidates.length === 0 && splitmixFuncs.size === 0 && chachaFnAddr === null) {
            return;
        }


        logBanner(`SCANNING NATIVE VM DECODER CANDIDATES IN ${mod.name}`);
        runtimeHints.soName = mod.name;

        if (Process.arch === 'arm64') {
            const outPtr = Memory.alloc(64);
            for (let c = 0; c < selectorCandidates.length; c++) {
                const fnAddr = selectorCandidates[c];
                try {
                    const decodeFn = new NativeFunction(fnAddr, 'uint8', ['uint64', 'pointer']);
                    const selectors = [];
                    let ok = true;
                    for (let idx = 0; idx < 32; idx++) {
                        outPtr.writeU64(0);
                        const res = decodeFn(idx, outPtr);
                        if (res === 1) {
                            const val = outPtr.readS64().toNumber();
                            if (val >= 1 && val <= 10000000) {
                                selectors.push(val.toString());
                            } else {
                                ok = false;
                                break;
                            }
                        } else if (res === 0 && selectors.length >= 8) {
                            break;
                        } else {
                            ok = false;
                            break;
                        }
                    }
                    if (ok && selectors.length >= 8) {
                        const selOff = `0x${fnAddr.sub(base).toString(16)}`;
                        runtimeHints.selector = selOff;
                        console.log(`${LOG_PREFIX} [ELF JSON Decoder] Function @ ${fnAddr} (offset ${selOff})`);
                        console.log(`${LOG_PREFIX} [ELF JSON Keys]    Selector [0] (Outer Key): "${selectors[0]}"`);
                        if (selectors.length > 2) {
                            console.log(`${LOG_PREFIX} [ELF JSON Keys]    Selector [2] (AES Key)  : "${selectors[2]}" (32-byte key array)`);
                            console.log(`${LOG_PREFIX} [ELF JSON Keys]    14 Config String Keys   : ${JSON.stringify(selectors.filter((_, idx) => idx !== 0 && idx !== 2))}`);
                        }
                        break;
                    }
                } catch (e) {
                    // Continue trying candidates
                }
            }
        }

        if (chachaFnAddr !== null) {
            const chachaOff = `0x${chachaFnAddr.sub(base).toString(16)}`;
            runtimeHints.chacha = chachaOff;
            console.log(`${LOG_PREFIX} [ELF ChaCha20 Fn]  Function @ ${chachaFnAddr} (offset ${chachaOff})`);

            let syscallFnAddr = null;
            for (let r = 0; r < rxRanges.length && syscallFnAddr === null; r++) {
                const rBase = rxRanges[r].base;
                const u32 = rxRanges[r].u32;
                for (let i = 0; i < u32.length; i++) {
                    const w = u32[i];
                    if ((w >>> 26) === 0x25) {
                        let imm26 = w & 0x3ffffff;
                        if (imm26 & 0x2000000) imm26 -= 0x4000000;
                        const target = rBase.add((i + imm26) * 4);
                        if (target.equals(chachaFnAddr)) {
                            const fnIdx = findFuncStartIdx(u32, i, 0x600, rBase, blTargetsSet);
                            if (fnIdx !== null) syscallFnAddr = rBase.add(fnIdx * 4);
                            break;
                        }
                    }
                }
            }

            let evalFnAddr = null;
            if (syscallFnAddr !== null) {
                const sysBuf = syscallFnAddr.readByteArray(0x1800);
                if (sysBuf) {
                    const sysU32 = new Uint32Array(sysBuf);
                    for (let i = 0; i < sysU32.length; i++) {
                        const w = sysU32[i];
                        if (i > 0 && (w === 0xd503233f || w === 0xd503237f)) break;
                        if ((w >>> 26) === 0x25) {
                            let imm26 = w & 0x3ffffff;
                            if (imm26 & 0x2000000) imm26 -= 0x4000000;
                            const target = syscallFnAddr.add((i + imm26) * 4);
                            if (splitmixFuncs.has(target.toString())) {
                                evalFnAddr = target;
                                break;
                            }
                        }
                    }
                }
            }

            if (evalFnAddr !== null) {
                const evalOff = `0x${evalFnAddr.sub(base).toString(16)}`;
                runtimeHints.eval = evalOff;
                console.log(`${LOG_PREFIX} [ELF VM Eval Fn]   Function @ ${evalFnAddr} (offset ${evalOff})`);

                if (Process.arch === 'arm64') {
                    const evalFn = new NativeFunction(evalFnAddr, 'uint64', ['pointer', 'uint16']);
                    const chachaFn = new NativeFunction(chachaFnAddr, 'uint8', ['uint32', 'uint32', 'pointer', 'pointer']);

                    const zeroCtx = Memory.alloc(0x4000);
                    const strBuf = Memory.alloc(128);
                    const lenBuf = Memory.alloc(16);

                    const vmConsts = new Set();
                    for (let i = 0; i < 160; i++) {
                        const val = evalFn(zeroCtx, 0x8000 | i);
                        vmConsts.add(val.and(0xffffffff).toNumber() >>> 0);
                    }

                    const constArr = Array.from(vmConsts);
                    const smallSlots = constArr.filter((c) => c >= 0 && c <= 0x200).sort((a, b) => a - b);
                    const candidateKeys = constArr.concat([0]);

                    for (let sIdx = 0; sIdx < smallSlots.length; sIdx++) {
                        const slot = smallSlots[sIdx];
                        for (let kIdx = 0; kIdx < candidateKeys.length; kIdx++) {
                            const key = candidateKeys[kIdx];
                            lenBuf.writeU64(0);
                            const ok = chachaFn(slot, key, strBuf, lenBuf);
                            if (ok === 1) {
                                const strLen = lenBuf.readU64().toNumber();
                                if (strLen >= 1 && strLen <= 100) {
                                    const text = strBuf.readUtf8String(strLen);
                                    console.log(
                                        `${LOG_PREFIX} [Decrypted VM Slot] [decoder-invoked] module=${mod.name} slot=0x${slot.toString(16)} (dyn_key=0x${key.toString(16).padStart(8, '0')}) -> "${text}"`
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        } else if (splitmixFuncs.size > 0 && Process.arch === 'arm64') {
            setupRustVmHooksAndDecryptStrings(mod, rxRanges, blCallers, blTargetsSet, splitmixFuncs);
        }
    } catch (e) {
        console.log(`${LOG_PREFIX} Note during ELF VM scan: ${e}`);
    }
}

function parseAndLogAssetHeader(assetName, hdrBytes, forceLogUnknown = false) {
    if (!hdrBytes || hdrBytes.length < 24) return false;
    let magic = '';
    for (let m = 0; m < Math.min(8, hdrBytes.length); m++) {
        const b = hdrBytes[m] & 0xff;
        if (b >= 32 && b < 127) magic += String.fromCharCode(b);
    }

    if (magic === 'MLDXGCM1' && hdrBytes.length >= 64) {
        const version = (((hdrBytes[8] & 0xff) << 24) | ((hdrBytes[9] & 0xff) << 16) | ((hdrBytes[10] & 0xff) << 8) | (hdrBytes[11] & 0xff)) >>> 0;
        const flags = (((hdrBytes[12] & 0xff) << 24) | ((hdrBytes[13] & 0xff) << 16) | ((hdrBytes[14] & 0xff) << 8) | (hdrBytes[15] & 0xff)) >>> 0;
        const dexSize = (((hdrBytes[16] & 0xff) << 24) | ((hdrBytes[17] & 0xff) << 16) | ((hdrBytes[18] & 0xff) << 8) | (hdrBytes[19] & 0xff)) >>> 0;

        let digestHex = '';
        for (let s = 20; s < 52; s++) digestHex += (hdrBytes[s] & 0xff).toString(16).padStart(2, '0');
        let ivHex = '';
        for (let v = 52; v < 64; v++) ivHex += (hdrBytes[v] & 0xff).toString(16).padStart(2, '0');

        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Path             : assets/${assetName}`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Magic            : "MLDXGCM1" (AES-256-GCM, v=${version}, flags=${flags})`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Expected DEX Sz  : ${dexSize} bytes`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Header Digest    : ${digestHex}`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] 12-Byte GCM IV   : ${ivHex}`);
        return true;
    } else if (magic === 'RSPAK01') {
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Path             : assets/${assetName}`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Magic            : "RSPAK01" (AES-256-GCM / HKDF container)`);
        return true;
    } else if (assetName.endsWith('.dat') && (hdrBytes[4] & 0xff) === 0x01 && (hdrBytes[5] & 0xff) === 0x03) {
        const hdrSkip = 16 + ((hdrBytes[6] & 0xff) | ((hdrBytes[7] & 0xff) << 8));
        const chunkPayloadLen =
            ((hdrBytes[8] & 0xff) |
                ((hdrBytes[9] & 0xff) << 8) |
                ((hdrBytes[10] & 0xff) << 16) |
                ((hdrBytes[11] & 0xff) << 24)) >>>
            0;
        let hexPreview = '';
        for (let i = 0; i < Math.min(24, hdrBytes.length); i++) hexPreview += (hdrBytes[i] & 0xff).toString(16).padStart(2, '0');
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Path             : assets/${assetName}`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Format           : Mode-0 Chunked Container (tag=0103, dataOffset=${hdrSkip}, sliceLen=${chunkPayloadLen} bytes)`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] First 24B (Hex)  : ${hexPreview}`);
        return true;
    } else if (assetName.endsWith('.cfg') || assetName.endsWith('.dat') || forceLogUnknown) {
        let nonceHex = '';
        for (let i = 0; i < 8; i++) nonceHex += (hdrBytes[i] & 0xff).toString(16).padStart(2, '0');
        let hexPreview = '';
        for (let i = 0; i < Math.min(32, hdrBytes.length); i++) hexPreview += (hdrBytes[i] & 0xff).toString(16).padStart(2, '0');
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Path             : assets/${assetName}`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] Format           : Keyed VM Container (8B Nonce=${nonceHex}, obfTag=0x${(hdrBytes[8] & 0xff).toString(16).padStart(2, '0')})`);
        console.log(`${LOG_PREFIX} [Encrypted Asset Header] First 32B (Hex)  : ${hexPreview}`);
        return true;
    }
    return false;
}

let inAssetInspect = false;

/**
 * Reads 64 bytes using 0-arg InputStream.read() so Frida 17.x gets primitive int values
 * directly instead of relying on in-place Java byte[] array mutation.
 */
function readHeaderBytesSafe(ins, count = 64) {
    const out = [];
    const readOne = ins.read.overload();
    for (let i = 0; i < count; i++) {
        const b = readOne.call(ins);
        if (b < 0) break;
        out.push(b & 0xff);
    }
    return out;
}

function inspectEncryptedAssets(ctxOrAssets, specificAssetName = null) {
    if (inAssetInspect || !ctxOrAssets) return;
    inAssetInspect = true;
    try {
        const assets = typeof ctxOrAssets.getAssets === 'function' ? ctxOrAssets.getAssets() : ctxOrAssets;
        const candidates = [];

        if (specificAssetName) {
            candidates.push(specificAssetName);
            const slashIdx = specificAssetName.lastIndexOf('/');
            if (slashIdx > 0) {
                const parentDir = specificAssetName.substring(0, slashIdx);
                const siblingEntries = assets.list(parentDir);
                if (siblingEntries && siblingEntries.length > 0) {
                    for (let j = 0; j < siblingEntries.length; j++) {
                        const siblingPath = `${parentDir}/${siblingEntries[j]}`;
                        if (siblingPath !== specificAssetName) {
                            candidates.push(siblingPath);
                        }
                    }
                }
            }
        } else {
            const rootEntries = assets.list('');
            if (rootEntries) {
                for (let i = 0; i < rootEntries.length; i++) {
                    const entry = rootEntries[i];
                    if (entry === 'images' || entry === 'webkit' || entry === 'geoid_map' || entry === 'dexopt') continue;
                    const subEntries = assets.list(entry);
                    if (subEntries && subEntries.length > 0) {
                        for (let j = 0; j < subEntries.length; j++) {
                            candidates.push(`${entry}/${subEntries[j]}`);
                        }
                    } else {
                        candidates.push(entry);
                    }
                }
            }
        }

        for (let c = 0; c < candidates.length; c++) {
            const path = candidates[c];
            if (inspectedAssets.has(path)) continue;
            try {
                const ins = assets.open(path);
                const hdr = readHeaderBytesSafe(ins, 64);
                ins.close();
                if (hdr.length >= 24) {
                    inspectedAssets.add(path);
                    parseAndLogAssetHeader(
                        path,
                        hdr,
                        specificAssetName !== null || path.endsWith('.enc') || path.endsWith('.cfg') || path.endsWith('.dat')
                    );
                }
            } catch (e) {
                // Not a regular file or cannot open
            }
        }
    } catch (err) {
        // Ignore asset scan errors
    } finally {
        inAssetInspect = false;
    }
}

function readStackJsonSelectors(sp) {
    if (!sp) return null;
    const scanBytes = 0x1400;
    for (let offset = 0; offset <= scanBytes - 0x280; offset += 8) {
        const candidate = sp.add(offset);
        let valid = true;
        const keys = [];
        try {
            for (let i = 0; i < 16; i++) {
                const strPtr = candidate.add(i * 32);
                const lenVal = Number(candidate.add(0x200 + i * 8).readU64());
                if (lenVal < 1 || lenVal > 19) {
                    valid = false;
                    break;
                }
                let s = '';
                for (let c = 0; c < lenVal; c++) {
                    const b = strPtr.add(c).readU8();
                    if (b < 0x30 || b > 0x39) {
                        valid = false;
                        break;
                    }
                    s += String.fromCharCode(b);
                }
                if (!valid || strPtr.add(lenVal).readU8() !== 0) {
                    valid = false;
                    break;
                }
                keys.push(s);
            }
        } catch (e) {
            valid = false;
        }
        if (valid && keys.length === 16) return keys;
    }
    return null;
}

function hookBridgeClassBySignatures(className) {
    if (!className || hookedBridgeClasses.has(className)) return;

    runInJavaVm(() => {
        try {
            const cls = Java.use(className);
            const jClass = cls.class;
            const methods = jClass.getDeclaredMethods();

            let decryptMethodName = null;
            let cacheReadMethodName = null;

            for (let i = 0; i < methods.length; i++) {
                const m = methods[i];
                const mName = m.getName();
                const paramTypes = m.getParameterTypes();
                const sig = Array.from(paramTypes).map((t) => t.getName()).join(',');

                if (sig === 'android.content.Context,[B') {
                    decryptMethodName = mName;
                } else if (sig === 'android.content.Context,android.content.SharedPreferences,java.lang.String') {
                    cacheReadMethodName = mName;
                }
            }

            if (!decryptMethodName && !cacheReadMethodName) return;

            hookedBridgeClasses.add(className);
            logBanner(`HOOKED NATIVE BRIDGE CLASS BY SIGNATURE: ${className}`);
            if (cacheReadMethodName) {
                console.log(`${LOG_PREFIX} [Signature Match] Cache Reader Method   : ${className}.${cacheReadMethodName}(Context, SharedPreferences, String)`);
            }
            if (decryptMethodName) {
                console.log(`${LOG_PREFIX} [Signature Match] Asset Decryptor Method: ${className}.${decryptMethodName}(Context, byte[])`);
            }

            if (decryptMethodName && cls[decryptMethodName]) {
                cls[decryptMethodName].overloads.forEach((ov) => {
                    ov.implementation = function (ctx, keyBytes) {
                        logBanner(`SIGNAL: ${className}.${decryptMethodName}(Context, byte[]) INVOKED`);
                        inspectEncryptedAssets(ctx);
                        return ov.call(this, ctx, keyBytes);
                    };
                });
            }

            if (cacheReadMethodName && cls[cacheReadMethodName]) {
                cls[cacheReadMethodName].overloads.forEach((ov) => {
                    ov.implementation = function (ctx, prefs, outerKey) {
                        console.log(`${LOG_PREFIX} [Cache Lookup] ${className}.${cacheReadMethodName}(ctx, prefs, outerKey="${outerKey}")`);
                        if (legacyProof && decryptMethodName && cls[decryptMethodName]) {
                            try {
                                const dummyKey = Java.array('byte', new Array(32).fill(0));
                                cls[decryptMethodName](ctx, dummyKey);
                            } catch (e) {
                                // Ignore expected GCM tag mismatch on dummy key
                            }
                        }
                        return ov.call(this, ctx, prefs, outerKey);
                    };
                });
            }
        } catch (e) {
            console.log(`${LOG_PREFIX} Note while reflecting ${className}: ${e}`);
        }
    });
}

function installJniTraceHooks(envHandle) {
    if (jniHooked) return;
    jniHooked = true;

    const handle = envHandle.readPointer();

    const IDX_FIND_CLASS = 6;
    const IDX_GET_METHOD_ID = 33;
    const IDX_GET_STATIC_METHOD_ID = 113;
    const IDX_NEW_STRING_UTF = 167;
    const IDX_REGISTER_NATIVES = 215;
    const IDX_GET_STRING_REGION = 220;
    const IDX_GET_DIRECT_BUFFER_ADDRESS = 230;

    const findClassPtr = handle.add(IDX_FIND_CLASS * Process.pointerSize).readPointer();
    const getMethodIdPtr = handle.add(IDX_GET_METHOD_ID * Process.pointerSize).readPointer();
    const getStaticMethodIdPtr = handle.add(IDX_GET_STATIC_METHOD_ID * Process.pointerSize).readPointer();
    const newStringUtfPtr = handle.add(IDX_NEW_STRING_UTF * Process.pointerSize).readPointer();
    const registerNativesPtr = handle.add(IDX_REGISTER_NATIVES * Process.pointerSize).readPointer();
    const getStringRegionPtr = handle.add(IDX_GET_STRING_REGION * Process.pointerSize).readPointer();
    const getDirectBufAddrPtr = handle.add(IDX_GET_DIRECT_BUFFER_ADDRESS * Process.pointerSize).readPointer();

    Interceptor.attach(registerNativesPtr, {
        onEnter(args) {
            if (!targetModule && this.returnAddress) {
                const m = Process.findModuleByAddress(this.returnAddress);
                if (isCandidateAppModule(m)) {
                    targetModule = m;
                }
            }
            if (!isInTargetModule(this.returnAddress)) return;

            const methodsPtr = args[2];
            const nMethods = args[3].toInt32();
            logBanner(`RegisterNatives (${nMethods} methods)${formatCallerOffset(this.returnAddress)}`);

            if (nMethods > 0 && !methodsPtr.isNull()) {
                const entry0Name = methodsPtr.readPointer().readUtf8String();
                const entry0Sig = methodsPtr.add(Process.pointerSize).readPointer().readUtf8String();
                const entry0Fn = methodsPtr.add(Process.pointerSize * 2).readPointer();
                const entryOff = `0x${entry0Fn.sub((Process.findModuleByAddress(entry0Fn) || targetModule).base).toString(16)}`;
                runtimeHints.entry = entryOff;
                console.log(`${LOG_PREFIX} Primary Native Entry [0]: ${entry0Name}${entry0Sig} @ offset ${entryOff}`);
                for (let i = 1; i < Math.min(nMethods, 256); i++) {
                    const entry = methodsPtr.add(i * Process.pointerSize * 3);
                    console.log(`${LOG_PREFIX} [RegisterNatives] ${entry.readPointer().readUtf8String()}${entry.add(Process.pointerSize).readPointer().readUtf8String()} @ ${entry.add(2 * Process.pointerSize).readPointer()}`);
                }
            }
        }
    });

    Interceptor.attach(getStringRegionPtr, {
        onEnter() {
            if (!isInTargetModule(this.returnAddress) || loggedSelectors) return;
            const callerOff = `0x${ptr(this.returnAddress).sub(Process.findModuleByAddress(this.returnAddress).base).toString(16)}`;
            runtimeHints.jniCallers.GetStringRegion = callerOff;
            const found = readStackJsonSelectors(this.context.sp);
            if (found) {
                loggedSelectors = true;
                logBanner(`OBSERVED 16 DECODED JSON SELECTOR KEYS ON NATIVE STACK${formatCallerOffset(this.returnAddress)}`);
                console.log(`${LOG_PREFIX} Outer Object Selector [0] : "${found[0]}"`);
                console.log(`${LOG_PREFIX} AES-256 Key Array     [2] : "${found[2]}"`);
                console.log(`${LOG_PREFIX} 14 Config String Keys     : ${JSON.stringify(found.filter((_, i) => i !== 0 && i !== 2))}`);
            }
        }
    });

    Interceptor.attach(findClassPtr, {
        onEnter(args) {
            if (!isInTargetModule(this.returnAddress)) return;
            const clsName = args[1].isNull() ? '' : args[1].readUtf8String();
            console.log(`${LOG_PREFIX} [Native JNIEnv->FindClass]          "${clsName}"${formatCallerOffset(this.returnAddress)}`);
        }
    });

    Interceptor.attach(getStaticMethodIdPtr, {
        onEnter(args) {
            if (!isInTargetModule(this.returnAddress)) return;
            const name = args[2].isNull() ? '' : args[2].readUtf8String();
            const sig = args[3].isNull() ? '' : args[3].readUtf8String();
            const callerOff = `0x${ptr(this.returnAddress).sub(Process.findModuleByAddress(this.returnAddress).base).toString(16)}`;
            runtimeHints.jniCallers[name] = callerOff;
            console.log(`${LOG_PREFIX} [Native JNIEnv->GetStaticMethodID]  ${name}${sig}${formatCallerOffset(this.returnAddress)}`);
            if (traceOptions.javaHooks && sig.indexOf('Landroid/content/Context;') !== -1 && bridgeClassName) {
                installAssetHooks();
                hookBridgeClassBySignatures(bridgeClassName);
            }
        }
    });

    Interceptor.attach(getMethodIdPtr, {
        onEnter(args) {
            if (!isInTargetModule(this.returnAddress)) return;
            const name = args[2].isNull() ? '' : args[2].readUtf8String();
            const sig = args[3].isNull() ? '' : args[3].readUtf8String();
            console.log(`${LOG_PREFIX} [Native JNIEnv->GetMethodID]        ${name}${sig}${formatCallerOffset(this.returnAddress)}`);
        }
    });

    Interceptor.attach(newStringUtfPtr, {
        onEnter(args) {
            if (!isInTargetModule(this.returnAddress) || args[1].isNull()) return;
            try {
                const str = args[1].readUtf8String();
                if (
                    str.endsWith('.cfg') ||
                    str.endsWith('.dat') ||
                    str.endsWith('.enc') ||
                    str.startsWith('https://') ||
                    str === rustTargetClassName || /ClassLoader|DexFile|ByteBuffer|loadClass/.test(str)
                ) {
                    console.log(`${LOG_PREFIX} [Native JNIEnv->NewStringUTF]       "${str}"${formatCallerOffset(this.returnAddress)}`);
                }
            } catch (e) {
                // Ignore
            }
        }
    });

    Interceptor.attach(getDirectBufAddrPtr, {
        onEnter() {
            this.fromTarget = isInTargetModule(this.returnAddress);
            this.retAddr = this.returnAddress;
        },
        onLeave(retval) {
            if (this.fromTarget) {
                console.log(`${LOG_PREFIX} [Native JNIEnv->GetDirectBufferAddress] -> ${retval}${formatCallerOffset(this.retAddr)}`);
            }
        }
    });

    for (const [label, index] of [['GetFieldID', 94], ['GetStaticFieldID', 144]]) {
        try {
            Interceptor.attach(handle.add(index * Process.pointerSize).readPointer(), {
                onEnter(args) {
                    if (!isInTargetModule(this.returnAddress)) return;
                    console.log(`${LOG_PREFIX} [Native JNIEnv->${label}] ${args[2].readUtf8String()} ${args[3].readUtf8String()}${formatCallerOffset(this.returnAddress)}`);
                }
            });
        } catch (e) { console.log(`${LOG_PREFIX} [Hook unavailable] ${label}: ${e}`); }
    }

    const aassetOpen = findExportSafe('libandroid.so', 'AAssetManager_open');
    if (aassetOpen) {
        Interceptor.attach(aassetOpen, {
            onEnter(args) {
                if (!isInTargetModule(this.returnAddress)) return;
                const fname = args[1].isNull() ? '' : args[1].readUtf8String();
                const mode = args[2].toInt32();
                console.log(`${LOG_PREFIX} [SIGNAL - NDK AAssetManager_open] "${fname}" (mode=${mode})${formatCallerOffset(this.returnAddress)}`);
            }
        });
    }
}

function installAssetHooks() {
    if (assetHooked) return;
    assetHooked = true;

    runInJavaVm(() => {
        try {
            const AssetManager = Java.use('android.content.res.AssetManager');
            AssetManager.open.overload('java.lang.String').implementation = function (fileName) {
                if (!inAssetInspect) {
                    console.log(`${LOG_PREFIX} [SIGNAL - AssetManager.open]      "${fileName}"`);
                    inspectEncryptedAssets(this, fileName);
                }
                return this.open(fileName);
            };
            AssetManager.open.overload('java.lang.String', 'int').implementation = function (fileName, mode) {
                if (!inAssetInspect) {
                    console.log(`${LOG_PREFIX} [SIGNAL - AssetManager.open]      "${fileName}" (mode=${mode})`);
                    inspectEncryptedAssets(this, fileName);
                }
                const res = this.open(fileName, mode);
                if (!inAssetInspect && rustDclTrigger && !dclExecuted) {
                    rustDclTrigger();
                }
                return res;
            };
        } catch (e) {
            // Ignore if overload unavailable
        }

        try {
            const URL = Java.use('java.net.URL');
            URL.$init.overload('java.lang.String').implementation = function (urlStr) {
                console.log(`${LOG_PREFIX} [SIGNAL - Network URL]            "${urlStr}"`);
                return this.$init(urlStr);
            };
        } catch (e) {
            // Ignore
        }

        installClassLoaderHooks();

    });
}

function brief(value, limit = 700) {
    try {
        const text = String(value);
        return text.length > limit ? text.slice(0, limit) + `… [${text.length} chars]` : text;
    } catch (_) { return '<unavailable>'; }
}

// These hooks use public Java/JNI APIs and do not depend on package names or ELF offsets.
function describeLoader(loader) {
    if (!loader) return '<bootstrap/null>';
    try { return brief(loader.toString()); }
    catch (_) { return loader.$className || '<unavailable>'; }
}

function installClassLoaderHooks() {
    for (const name of ['dalvik.system.DexClassLoader', 'dalvik.system.InMemoryDexClassLoader',
        'dalvik.system.DelegateLastClassLoader']) {
        try {
            const cls = Java.use(name);
            for (const ov of cls.$init.overloads) {
                ov.implementation = function () {
                    const args = Array.from(arguments);
                    if (isInstalledApkPath(args[0])) return ov.apply(this, args);
                    const signature = ov.argumentTypes.map(t => t.className).join(', ');
                    console.log(`${LOG_PREFIX} [SIGNAL - ${name.split('.').pop()}] <init>(${signature})`);
                    args.forEach((arg, i) => {
                        const type = ov.argumentTypes[i].className;
                        if (type === 'java.nio.ByteBuffer') {
                            console.log(`${LOG_PREFIX} [DEX buffer] capacity=${arg ? arg.capacity() : 0} remaining=${arg ? arg.remaining() : 0}`);
                        } else if (type === '[Ljava.nio.ByteBuffer;') {
                            console.log(`${LOG_PREFIX} [DEX buffers] count=${arg ? arg.length : 0}`);
                        } else if (type === 'java.lang.String' || type === 'java.lang.ClassLoader') {
                            if (type === 'java.lang.String') console.log(`${LOG_PREFIX} [Loader argument ${i}] ${brief(arg)}`);
                        }
                    });
                    try {
                        const result = ov.apply(this, args);
                        console.log(`${LOG_PREFIX} [ClassLoader constructed] ${this.$className}`);
                        return result;
                    } catch (e) {
                        console.log(`${LOG_PREFIX} [ClassLoader constructor threw] ${e}`);
                        throw e;
                    }
                };
            }
        } catch (e) { console.log(`${LOG_PREFIX} [Hook unavailable] ${name}: ${e}`); }
    }
    // Both overloads are needed: native and Java callers may use the resolve flag.
    const ClassLoader = Java.use('java.lang.ClassLoader');
    for (const ov of ClassLoader.loadClass.overloads) {
        ov.implementation = function () {
            const args = Array.from(arguments);
            const name = String(args[0]);
            const kind = this.$className || '';
            const relevant = /(?:InMemoryDex|Dex|DelegateLast)ClassLoader$/.test(kind) || name === rustTargetClassName;
            if (relevant) console.log(`${LOG_PREFIX} [SIGNAL - DCL loadClass] "${name}" via ${this.$className}`);
            if (legacyProof && inSyntheticDcl && name === rustTargetClassName) return null;
            try {
                const result = ov.apply(this, args);
                if (relevant) console.log(`${LOG_PREFIX} [DCL loadClass returned] "${name}"`);
                return result;
            } catch (e) {
                if (relevant) console.log(`${LOG_PREFIX} [DCL loadClass threw] "${name}": ${e}`);
                throw e;
            }
        };
    }
    // File-backed DEX and additions to an existing PathClassLoader bypass constructors.
    for (const [className, method] of [['dalvik.system.DexFile', 'loadDex'],
        ['dalvik.system.BaseDexClassLoader', 'addDexPath']]) {
        try {
            const cls = Java.use(className);
            for (const ov of cls[method].overloads) {
                ov.implementation = function () {
                    if (isInstalledApkPath(arguments[0])) return ov.apply(this, arguments);
                    console.log(`${LOG_PREFIX} [SIGNAL - ${className}.${method}] ${Array.from(arguments).map((arg, i) => ov.argumentTypes[i].className.startsWith('[') ? ov.argumentTypes[i].className + '[count=' + (arg ? arg.length : 0) + ']' : brief(arg)).join(', ')}`);
                    return ov.apply(this, arguments);
                };
            }
        } catch (e) { console.log(`${LOG_PREFIX} [Hook unavailable] ${className}.${method}: ${e}`); }
    }
    console.log(`${LOG_PREFIX} [Ready] Class-loader hooks installed`);
}

function isInstalledApkPath(value) {
    if (typeof value !== 'string' && !(value && value.$className === 'java.lang.String')) return false;
    const paths = String(value).split(':');
    return paths.length > 0 && paths.every(path =>
        /^(?:\/data\/app\/|\/system\/|\/system_ext\/|\/apex\/|\/product\/)/.test(path) &&
        /\.(?:apk|jar)$/.test(path));
}

let moduleObserver = null;
const onLoadHooks = new Set();
function withNativeEnv(vm, attach, callback) {
    const table = vm.readPointer();
    const out = Memory.alloc(Process.pointerSize);
    const getEnv = new NativeFunction(table.add(6 * Process.pointerSize).readPointer(), 'int', ['pointer', 'pointer', 'int']);
    let status = getEnv(vm, out, 0x00010006);
    let attached = false;
    if (status === -2 && attach) {
        const attachThread = new NativeFunction(table.add(4 * Process.pointerSize).readPointer(), 'int', ['pointer', 'pointer', 'pointer']);
        status = attachThread(vm, out, ptr(0));
        attached = status === 0;
    }
    try {
        if (status === 0) callback(out.readPointer());
        else console.log(`${LOG_PREFIX} [JNI pending] GetEnv=${status}`);
    } finally {
        if (attached) new NativeFunction(table.add(5 * Process.pointerSize).readPointer(), 'int', ['pointer'])(vm);
    }
}

function installNativeJniFromVm(vm, attach = false) {
    if (jniHooked) return;
    try { withNativeEnv(vm, attach, installJniTraceHooks); }
    catch (e) { console.log(`${LOG_PREFIX} [JNI unavailable] ${e}`); }
}

function hookNativeOnLoad(mod, address) {
    const key = address.toString();
    if (onLoadHooks.has(key)) return;
    onLoadHooks.add(key);
    Interceptor.attach(address, {
        onEnter(args) {
            targetModule = mod;
            installNativeJniFromVm(args[0]);
            console.log(`${LOG_PREFIX} [JNI_OnLoad] ${mod.name}+${address.sub(mod.base)}`);
            inspectMappedNativeVmModule(mod);
        }
    });
}

function installModuleObserver() {
    const seen = new Set();
    function observe(mod) {
        if (!isCandidateAppModule(mod)) return;
        const key = mod.path + '@' + mod.base;
        if (seen.has(key)) return;
        seen.add(key);
        const entry = mod.findExportByName('JNI_OnLoad');
        if (!entry) return;
        try { hookNativeOnLoad(mod, entry); }
        catch (e) { console.log(`${LOG_PREFIX} [Native hook unavailable] ${mod.name}: ${e}`); }
        // Late attach support; defer work outside the linker's module notification.
        setImmediate(() => inspectMappedNativeVmModule(mod));
    }
    if (typeof Process.attachModuleObserver === 'function') {
        moduleObserver = Process.attachModuleObserver({ onAdded(mod) { setImmediate(() => observe(mod)); } });
    } else {
        Process.enumerateModules().forEach(observe);
        moduleObserver = setInterval(() => Process.enumerateModules().forEach(observe), 1000);
    }
    // Also catch dlsym-based JNI lookup before the app enters JNI_OnLoad.
    const dlsym = findExportSafe('libdl.so', 'dlsym');
    if (dlsym) Interceptor.attach(dlsym, {
        onEnter(args) {
            this.onLoad = false;
            try { this.onLoad = args[1].readUtf8String() === 'JNI_OnLoad'; } catch (_) {}
        },
        onLeave(result) {
            if (!this.onLoad || result.isNull()) return;
            const mod = Process.findModuleByAddress(result);
            if (isCandidateAppModule(mod)) hookNativeOnLoad(mod, result);
        }
    });
}

function installExistingVmHooks() {
    if (jniHooked) return;
    const getVms = findExportSafe('libart.so', 'JNI_GetCreatedJavaVMs');
    if (!getVms) return;
    try {
        const vmOut = Memory.alloc(Process.pointerSize);
        const count = Memory.alloc(4);
        const status = new NativeFunction(getVms, 'int', ['pointer', 'int', 'pointer'])(vmOut, 1, count);
        if (status === 0 && count.readS32() > 0) installNativeJniFromVm(vmOut.readPointer(), true);
    } catch (e) { console.log(`${LOG_PREFIX} [Existing VM unavailable] ${e}`); }
}

function initTrace() {
    console.log(`${LOG_PREFIX} [Environment] Frida=${typeof Frida !== 'undefined' ? Frida.version : 'unknown'} arch=${Process.arch} pointerSize=${Process.pointerSize}`);
    if (Process.arch !== 'arm64') console.log(`${LOG_PREFIX} [Coverage] VM instruction decoder requires native ARM64; JNI string observation remains enabled. Translated ARM code is not supported.`);
    installModuleObserver();
    setTimeout(installExistingVmHooks, 1000);
    console.log(`${LOG_PREFIX} [Ready] Native tracing installed; decodeVm=${traceOptions.decodeVm}; javaHooks=${traceOptions.javaHooks}`);
    installOptionalJavaHooks();
}

let javaHooksScheduled = false;
function installOptionalJavaHooks() {
    if (!traceOptions.javaHooks || javaHooksScheduled) return;
    javaHooksScheduled = true;
    if (typeof Java === 'undefined') {
        console.log(`${LOG_PREFIX} [Java unavailable] Use the Frida CLI or bundle frida-java-bridge. Native tracing is active.`);
        return;
    }
    // Never perform synchronous Java bridge initialization before native setup.
    setTimeout(() => {
        console.log(`${LOG_PREFIX} [Java pending] Waiting for Java.perform`);
        try {
            Java.perform(() => {
                installAssetHooks();
                console.log(`${LOG_PREFIX} [Java ready] Focused DCL hooks installed`);
            });
        } catch (e) { console.log(`${LOG_PREFIX} [Java unavailable] ${e}`); }
    }, 250);
}

let traceStarted = false;
function startTrace() {
    if (traceStarted) return;
    traceStarted = true;
    logBanner('STARTING NATIVE VM STRING & ASSET TRACE');
    try { initTrace(); }
    catch (e) { console.log(`${LOG_PREFIX} [Startup error] ${e.stack || e}`); }
}
// CLI/Gadget calls init with parameters. Raw create_script users get the same defaults.
setImmediate(() => setTimeout(startTrace, 100));
