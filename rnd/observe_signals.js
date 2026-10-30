/* Observation only: no forced checks, changed returns, or payload loading.
 * ARM64 libdou.so SHA256 064c4059f952feab256363ff917fe2ff0c20613dfc53c034068b3d6724b48776.
 * Ghidra project image-base delta: 0x100000. Java methods have NO native Ghidra VA.
 * Run with Frida CLI (provides Java bridge); see README.md for scope and limitations.
 */
'use strict';
let sequence = 0;
const counts = {}, listeners = [], nativeSeen = new Set(), javaSeen = new Set();
function event(kind, fields = {}) {
  counts[kind] = (counts[kind] || 0) + 1;
  send({sequence: ++sequence, time: Date.now(), thread: Process.getCurrentThreadId(), kind, ...fields});
}
function safeString(x) { try { return x === null ? null : String(x).slice(0, 512); } catch (_) { return '<unreadable>'; } }
function nativeLocation(m, offset) {
  return {module: m.name, elf_va: '0x' + offset.toString(16),
    ghidra_va: '0x' + (offset + 0x100000).toString(16), runtime: m.base.add(offset).toString()};
}
const nativeTargets = [
  ['JNI_OnLoad', 0x694f0, 'ff8304d1fd7b0da9fc7300f9f85f0fa9'],
  ['initEnv_EMPTY', 0x69998, 'c0035fd6'],
  ['global_strings_constructor', 0x6d3e4, 'fd7bbda9f65701a9f44f02a9fd030091']
];
const moduleObserver = Process.attachModuleObserver({onAdded(m) {
  if (m.name !== 'libdou.so' || nativeSeen.has(m.base.toString())) return;
  nativeSeen.add(m.base.toString());
  if (Process.arch !== 'arm64') { event('native.refused', {reason:'ARM64 offsets only'}); return; }
  // Check every fingerprint before installing any offset-based hooks; also verify hash externally.
  for (const [name, off, expected] of nativeTargets) {
    const actual = Array.from(new Uint8Array(m.base.add(off).readByteArray(expected.length / 2)))
      .map(x => x.toString(16).padStart(2, '0')).join('');
    if (actual !== expected) { event('native.refused', {name, reason:'instruction fingerprint mismatch'}); return; }
  }
  for (const [name, off] of nativeTargets) {
    const location = nativeLocation(m, off);
    try {
      listeners.push(Interceptor.attach(m.base.add(off), {
        onEnter() { event('native.enter', {name, ...location}); },
        onLeave(result) { event('native.leave', {name, ...location,
          result: name === 'JNI_OnLoad' ? result.toString() : null}); }
      }));
      event('native.hooked', {name, ...location});
    } catch(e) { event('native.hook_error', {name, error:String(e), ...location}); }
  }
}});

const dexReferences = {"RootCheck.<init>":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x24d42c","instructions_offset":"0x24d43c","source_line":null}],"RootCheck.checkRootMethod1":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24cf8c","instructions_offset":"0x24cf9c","source_line":14}],"RootCheck.checkRootMethod2":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d050","instructions_offset":"0x24d060","source_line":51}],"RootCheck.checkRootMethod3":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d140","instructions_offset":"0x24d150","source_line":85}],"RootCheck.executeCommand":[{"origin":"payload","descriptor":"(Ljava/lang/String;)Ljava/lang/String;","code_item_offset":"0x24d334","instructions_offset":"0x24d344","source_line":101}],"RootCheck.hasDebuggingTools":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d1a0","instructions_offset":"0x24d1b0","source_line":28}],"RootCheck.isDeviceRooted":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d200","instructions_offset":"0x24d210","source_line":10}],"RootCheck.isMagiskPresent":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d264","instructions_offset":"0x24d274","source_line":24}],"RootCheck.isRootedBySuCommand":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d2e8","instructions_offset":"0x24d2f8","source_line":38}],"UsbScreenUtil.<init>":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x24d890","instructions_offset":"0x24d8a0","source_line":null}],"UsbScreenUtil.getScreenLock":[{"origin":"payload","descriptor":"(Landroid/content/Context;)Ljava/lang/String;","code_item_offset":"0x24d444","instructions_offset":"0x24d454","source_line":16}],"UsbScreenUtil.getUsbState":[{"origin":"payload","descriptor":"(Landroid/content/Context;)Ljava/lang/String;","code_item_offset":"0x24d4bc","instructions_offset":"0x24d4cc","source_line":54}],"VpsCheck.<init>":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x24dc78","instructions_offset":"0x24dc88","source_line":null}],"VpsCheck.checkCpuInfo":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d8a8","instructions_offset":"0x24d8b8","source_line":37}],"VpsCheck.checkFileSystem":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d950","instructions_offset":"0x24d960","source_line":58}],"VpsCheck.checkSystemProperties":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24d9bc","instructions_offset":"0x24d9cc","source_line":33}],"VpsCheck.checkVirtualizationFeatures":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24da44","instructions_offset":"0x24da54","source_line":14}],"VpsCheck.containsVirtualizationKeywords":[{"origin":"payload","descriptor":"(Ljava/io/File;)Z","code_item_offset":"0x24daf4","instructions_offset":"0x24db04","source_line":69}],"VpsCheck.isRootedByBuildTags":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24dbf0","instructions_offset":"0x24dc00","source_line":28}],"VpsCheck.isRunningOnVps":[{"origin":"payload","descriptor":"()Z","code_item_offset":"0x24dc20","instructions_offset":"0x24dc30","source_line":10}],"BriActivity.<clinit>":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x248018","instructions_offset":"0x248028","source_line":null},{"origin":"outer","descriptor":"()V","code_item_offset":"0x163888","instructions_offset":"0x163898","source_line":null}],"BriActivity.<init>":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x2480a8","instructions_offset":"0x2480b8","source_line":null},{"origin":"outer","descriptor":"()V","code_item_offset":"0x1638d8","instructions_offset":"0x1638e8","source_line":null}],"BriActivity.access$000":[{"origin":"payload","descriptor":"(Lcom/crimavon/barrage/BriActivity;)Z","code_item_offset":"0x2471f0","instructions_offset":"0x247200","source_line":null}],"BriActivity.access$002":[{"origin":"payload","descriptor":"(Lcom/crimavon/barrage/BriActivity; Z)Z","code_item_offset":"0x247208","instructions_offset":"0x247218","source_line":null}],"BriActivity.access$100":[{"origin":"payload","descriptor":"()Ljava/lang/String;","code_item_offset":"0x247638","instructions_offset":"0x247648","source_line":null}],"BriActivity.access$200":[{"origin":"payload","descriptor":"(Lcom/crimavon/barrage/BriActivity;)V","code_item_offset":"0x248114","instructions_offset":"0x248124","source_line":null}],"BriActivity.access$300":[{"origin":"payload","descriptor":"(Lcom/crimavon/barrage/BriActivity;)V","code_item_offset":"0x24812c","instructions_offset":"0x24813c","source_line":null}],"BriActivity.access$400":[{"origin":"payload","descriptor":"(Lcom/crimavon/barrage/BriActivity; I)V","code_item_offset":"0x248144","instructions_offset":"0x248154","source_line":null}],"BriActivity.access$500":[{"origin":"payload","descriptor":"(Lcom/crimavon/barrage/BriActivity;)Landroid/os/Handler;","code_item_offset":"0x2471d8","instructions_offset":"0x2471e8","source_line":null}],"BriActivity.access$600":[{"origin":"payload","descriptor":"(Lcom/crimavon/barrage/BriActivity;)V","code_item_offset":"0x24815c","instructions_offset":"0x24816c","source_line":null}],"BriActivity.access$800":[{"origin":"payload","descriptor":"(Lcom/crimavon/barrage/BriActivity; Ljava/lang/String; Ljava/lang/String;)V","code_item_offset":"0x248174","instructions_offset":"0x248184","source_line":null}],"BriActivity.buildHttp3Payload":[{"origin":"payload","descriptor":"()Ljava/lang/String;","code_item_offset":"0x247650","instructions_offset":"0x247660","source_line":363}],"BriActivity.cancelInstallReferrerTimeout":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x24818c","instructions_offset":"0x24819c","source_line":286}],"BriActivity.checkInstallRefAndGo":[{"origin":"payload","descriptor":"(Ljava/lang/String;)V","code_item_offset":"0x2481bc","instructions_offset":"0x2481cc","source_line":342}],"BriActivity.closeInstallReferrerClient":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x24825c","instructions_offset":"0x24826c","source_line":294}],"BriActivity.closeQuietly":[{"origin":"payload","descriptor":"(Ljava/io/Closeable;)V","code_item_offset":"0x24829c","instructions_offset":"0x2482ac","source_line":641}],"BriActivity.decodeStoredValue":[{"origin":"payload","descriptor":"(Ljava/lang/String; I)Ljava/lang/String;","code_item_offset":"0x2479d4","instructions_offset":"0x2479e4","source_line":562}],"BriActivity.getHttpProxyInfo":[{"origin":"payload","descriptor":"()Ljava/lang/String;","code_item_offset":"0x247aa8","instructions_offset":"0x247ab8","source_line":461}],"BriActivity.getInstallSource":[{"origin":"payload","descriptor":"()Ljava/lang/String;","code_item_offset":"0x247b6c","instructions_offset":"0x247b7c","source_line":510}],"BriActivity.getMcc":[{"origin":"payload","descriptor":"()Ljava/lang/String;","code_item_offset":"0x247c2c","instructions_offset":"0x247c3c","source_line":407}],"BriActivity.getScreenOffTimeoutSeconds":[{"origin":"payload","descriptor":"()J","code_item_offset":"0x247f54","instructions_offset":"0x247f64","source_line":430}],"BriActivity.getStoredV3Value":[{"origin":"payload","descriptor":"(Ljava/lang/String;)Ljava/lang/String;","code_item_offset":"0x247cc0","instructions_offset":"0x247cd0","source_line":582}],"BriActivity.getSystemProperty":[{"origin":"payload","descriptor":"(Ljava/lang/String;)Ljava/lang/String;","code_item_offset":"0x247ce4","instructions_offset":"0x247cf4","source_line":540}],"BriActivity.getVersionCode":[{"origin":"payload","descriptor":"()J","code_item_offset":"0x247fa0","instructions_offset":"0x247fb0","source_line":450}],"BriActivity.getVersionName":[{"origin":"payload","descriptor":"()Ljava/lang/String;","code_item_offset":"0x247d64","instructions_offset":"0x247d74","source_line":442}],"BriActivity.getVpnInfo":[{"origin":"payload","descriptor":"()Ljava/lang/String;","code_item_offset":"0x247dac","instructions_offset":"0x247dbc","source_line":481}],"BriActivity.gotoA":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x248450","instructions_offset":"0x248460","source_line":188},{"origin":"payload","descriptor":"(Ljava/lang/String;)V","code_item_offset":"0x24846c","instructions_offset":"0x24847c","source_line":188}],"BriActivity.gotoAorB":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x24852c","instructions_offset":"0x24853c","source_line":91}],"BriActivity.handleInstallReferrerSetupFinished":[{"origin":"payload","descriptor":"(I)V","code_item_offset":"0x248664","instructions_offset":"0x248674","source_line":257}],"BriActivity.isReferrerBlank":[{"origin":"payload","descriptor":"(Ljava/lang/String;)Z","code_item_offset":"0x247220","instructions_offset":"0x247230","source_line":332}],"BriActivity.markInstallReferrerHandled":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x2486e8","instructions_offset":"0x2486f8","source_line":280}],"BriActivity.postPlainText":[{"origin":"payload","descriptor":"(Ljava/lang/String; Ljava/lang/String;)V","code_item_offset":"0x248770","instructions_offset":"0x248780","source_line":587}],"BriActivity.readAll":[{"origin":"payload","descriptor":"(Ljava/io/InputStream;)Ljava/lang/String;","code_item_offset":"0x247ebc","instructions_offset":"0x247ecc","source_line":625}],"BriActivity.runEnvChecksThenEnter":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x2488c8","instructions_offset":"0x2488d8","source_line":121}],"BriActivity.safeField":[{"origin":"payload","descriptor":"(Ljava/lang/String;)Ljava/lang/String;","code_item_offset":"0x247f18","instructions_offset":"0x247f28","source_line":551}],"BriActivity.sendReport":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x248bf0","instructions_offset":"0x248c00","source_line":305}],"BriActivity.skipChannelThenEnvChecks":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x248d14","instructions_offset":"0x248d24","source_line":337}],"BriActivity.enterB":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x2482d0","instructions_offset":"0x2482e0","source_line":170}],"BriActivity.getInstallReferrer":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x248388","instructions_offset":"0x248398","source_line":205}],"BriActivity.onCreate":[{"origin":"payload","descriptor":"(Landroid/os/Bundle;)V","code_item_offset":"0x24870c","instructions_offset":"0x24871c","source_line":77},{"origin":"outer","descriptor":"(Landroid/os/Bundle;)V","code_item_offset":"0x163900","instructions_offset":"0x163910","source_line":87}],"BriActivity.onDestroy":[{"origin":"payload","descriptor":"()V","code_item_offset":"0x248740","instructions_offset":"0x248750","source_line":84}],"BriActivity.parseInstallJS":[{"origin":"payload","descriptor":"(Ljava/lang/String; Ljava/lang/String;)Z","code_item_offset":"0x247254","instructions_offset":"0x247264","source_line":747}],"BriActivity.a":[{"origin":"outer","descriptor":"(I)Landroid/widget/LinearLayout;","code_item_offset":"0x1636b8","instructions_offset":"0x1636c8","source_line":23}],"BriActivity.b":[{"origin":"outer","descriptor":"(Ljava/lang/String; I F Ljava/lang/Integer;)Landroid/widget/TextView;","code_item_offset":"0x163810","instructions_offset":"0x163820","source_line":32}],"BriActivity.c":[{"origin":"outer","descriptor":"()Landroid/widget/LinearLayout$LayoutParams;","code_item_offset":"0x1637d0","instructions_offset":"0x1637e0","source_line":43}],"BriActivity.d":[{"origin":"outer","descriptor":"(Ljava/lang/String; Ljava/lang/String;)Landroid/widget/LinearLayout;","code_item_offset":"0x1636e8","instructions_offset":"0x1636f8","source_line":47}],"BriActivity.e":[{"origin":"outer","descriptor":"(I)I","code_item_offset":"0x163854","instructions_offset":"0x163864","source_line":64}],"BriActivity.f":[{"origin":"outer","descriptor":"(I)Landroid/graphics/drawable/GradientDrawable;","code_item_offset":"0x163630","instructions_offset":"0x163640","source_line":68}],"BriActivity.g":[{"origin":"outer","descriptor":"(F I)Landroid/view/View;","code_item_offset":"0x163688","instructions_offset":"0x163698","source_line":76}],"BriActivity.h":[{"origin":"outer","descriptor":"()Landroid/widget/LinearLayout$LayoutParams;","code_item_offset":"0x1637f0","instructions_offset":"0x163800","source_line":82}],"MainActivity.<clinit>":[{"origin":"outer","descriptor":"()V","code_item_offset":"0x163b68","instructions_offset":"0x163b78","source_line":null}],"MainActivity.<init>":[{"origin":"outer","descriptor":"()V","code_item_offset":"0x163b7c","instructions_offset":"0x163b8c","source_line":null}],"MainActivity.a":[{"origin":"outer","descriptor":"(Lcom/crimavon/barrage/MainActivity;)V","code_item_offset":"0x163b94","instructions_offset":"0x163ba4","source_line":null}],"MainActivity.b":[{"origin":"outer","descriptor":"()Landroid/webkit/WebView;","code_item_offset":"0x163ac0","instructions_offset":"0x163ad0","source_line":49}],"MainActivity.c":[{"origin":"outer","descriptor":"()V","code_item_offset":"0x163bac","instructions_offset":"0x163bbc","source_line":76}],"MainActivity.d":[{"origin":"outer","descriptor":"()V","code_item_offset":"0x163c90","instructions_offset":"0x163ca0","source_line":80}],"MainActivity.e":[{"origin":"outer","descriptor":"()V","code_item_offset":"0x163cc8","instructions_offset":"0x163cd8","source_line":85}],"MainActivity.initEnv":[{"origin":"outer","descriptor":"()V","code_item_offset":null,"instructions_offset":null,"source_line":93}],"MainActivity.onCreate":[{"origin":"outer","descriptor":"(Landroid/os/Bundle;)V","code_item_offset":"0x163bd0","instructions_offset":"0x163be0","source_line":96}],"MainActivity.onDestroy":[{"origin":"outer","descriptor":"()V","code_item_offset":"0x163c14","instructions_offset":"0x163c24","source_line":107}],"MainActivity.onPause":[{"origin":"outer","descriptor":"()V","code_item_offset":"0x163c40","instructions_offset":"0x163c50","source_line":117}],"MainActivity.onResume":[{"origin":"outer","descriptor":"()V","code_item_offset":"0x163c68","instructions_offset":"0x163c78","source_line":126}]};
const prefix = 'com.crimavon.barrage.';
const targets = {
  MainActivity: ['initEnv'],
  BriActivity: ['gotoAorB','runEnvChecksThenEnter','gotoA','enterB','getInstallReferrer',
    'checkInstallRefAndGo','parseInstallJS','getHttpProxyInfo','getVpnInfo','getInstallSource',
    'getSystemProperty','getMcc','getScreenOffTimeoutSeconds'],
  RootCheck: ['isDeviceRooted','checkRootMethod1','checkRootMethod2','checkRootMethod3',
    'isMagiskPresent','hasDebuggingTools','isRootedBySuCommand'],
  VpsCheck: ['isRunningOnVps','checkVirtualizationFeatures','isRootedByBuildTags',
    'checkSystemProperties','checkCpuInfo','checkFileSystem','containsVirtualizationKeywords'],
  UsbScreenUtil: ['getScreenLock','getUsbState']
};
function wanted(name) { return name.startsWith(prefix) && targets[name.slice(prefix.length)] !== undefined; }
// Actual environment checks are Java in the recovered DEX, not functions in libdou.so.
// Detailed code_item offsets and source lines are in signal-map.json next to this script.
function installClass(classObject) {
  const name = String(classObject.getName());
  if (!wanted(name)) return;
  const loader = classObject.getClassLoader();
  const id = loader === null ? 'boot' : String(Java.use('java.lang.System').identityHashCode(loader));
  const key = name + '@' + id;
  if (javaSeen.has(key)) return;
  javaSeen.add(key);
  const factory = loader === null ? Java.classFactory : Java.ClassFactory.get(loader);
  const cls = factory.use(name), shortName = name.slice(prefix.length);
  for (const method of targets[shortName]) {
    if (!cls[method]) { event('java.method_absent', {class:name, method, loader:id}); continue; }
    for (const overload of cls[method].overloads) {
      const signature = '(' + overload.argumentTypes.map(t => t.className).join(',') + ')';
      const reference = {class:name, method, signature, loader:id, ghidra_va:null,
        dex_candidates:dexReferences[shortName + '.' + method] || [], reference:'signal-map.json', source: 'com/crimavon/barrage/' + shortName + '.java'};
      overload.implementation = function(...args) {
        // Log only string/primitive args; Context/File objects are identified by their Java type.
        const values = args.map((arg,i) => {
          const type = overload.argumentTypes[i].className;
          return type === 'java.lang.String' || !type.includes('.') ? safeString(arg) : '<' + type + '>';
        });
        event('java.enter', {...reference, args:values});
        try {
          const result = overload.call(this, ...args);
          event('java.leave', {...reference, result: overload.returnType.className === 'void' ? null : safeString(result)});
          return result;
        } catch(e) { event('java.throw', {...reference, error:safeString(e)}); throw e; }
      };
      event('java.hooked', reference);
    }
  }
}
function startJava() {
  if (typeof Java === 'undefined' || !Java.available) {
    event('java.unavailable', {hint:'Use the Frida CLI Java bridge; native hooks remain active'}); return;
  }
  Java.perform(() => {
    const Class = Java.use('java.lang.Class');
    // Hook only naturally loaded classes, using their actual defining loader.
    const Loader = Java.use('java.lang.ClassLoader');
    for (const overload of Loader.loadClass.overloads) {
      overload.implementation = function(...args) {
        const result = overload.call(this, ...args);
        if (wanted(String(args[0]))) {
          try { installClass(result); } catch(e) { event('java.hook_error', {error:String(e)}); }
        }
        return result;
      };
    }
    Java.enumerateLoadedClasses({onMatch(name, handle) {
      if (!wanted(name)) return;
      try { installClass(Java.cast(handle, Class)); } catch(e) { event('java.hook_error', {class:name,error:String(e)}); }
    }, onComplete() { event('java.ready', {note:'Absent payload classes are not force-loaded; no events does not prove absence of checks.'}); }});
  });
}
setImmediate(startJava);
setInterval(() => event('summary', {counts:{...counts}}), 30000);
