// Reuse a JNI GDT, type JNI entry points and follow evidence-backed indirect calls.
// Standalone: paste this entire file into Ghidra's editor as ResolveJNI.java.
// GUI: reuse an open jni_all archive, or select a GDT in the file dialog.
// Arguments: [auto|/path/to/jni_all.gdt] [/path/to/report.json]
// @category APKDefense
// @menupath Tools.APK Defense.Resolve JNI

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import com.google.gson.GsonBuilder;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class ResolveJNI extends GhidraScript {
    private static final int PASSES = 10, DEPTH = 48, MAX_METHODS = 4096;
    private DataTypeManager dtm;
    private DataType env, vm;
    private Structure nativeTable, invokeTable, methodType;
    private final Map<String, Map<String, Object>> findings = new LinkedHashMap<>();
    private final Set<String> changes = new LinkedHashSet<>();
    private final Map<Address, DataTypeComponent> wrappers = new HashMap<>();
    private final Set<String> registrations = new HashSet<>();
    private final Map<String, Object> report = new LinkedHashMap<>();
    private boolean changed;
    private int pointerSize;
    private String archiveDescription;

    @Override public void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("Open a native program first");
        dtm = currentProgram.getDataTypeManager();
        pointerSize = currentProgram.getDefaultPointerSize();
        if (pointerSize != 4 && pointerSize != 8) throw new IllegalArgumentException("Only 32/64-bit targets supported");
        String[] args = getScriptArgs();
        loadTypes(args.length > 0 ? args[0] : "auto");
        seedEntries();
        int passes = 0;
        boolean converged = false;
        for (; passes < PASSES && !monitor.isCancelled(); passes++) {
            changed = false;
            findings.clear();
            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) throw new IOException(decompiler.getLastMessage());
                for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                    monitor.checkCancelled();
                    if (f.isExternal() || f.isThunk()) continue;
                    DecompileResults r = decompiler.decompileFunction(f, 30, monitor);
                    if (!r.decompileCompleted() || r.getHighFunction() == null) {
                        finding(f, f.getEntryPoint(), "decompile_failed", r.getErrorMessage());
                        continue;
                    }
                    try { inspect(f, r.getHighFunction(), decompiler); }
                    catch (ghidra.util.exception.CancelledException e) { throw e; }
                    catch (Exception e) { finding(f, f.getEntryPoint(), "analysis_error", e.toString()); }
                }
            } finally { decompiler.dispose(); }
            println("JNI pass " + (passes + 1) + ": " + changes.size() + " cumulative changes");
            if (!changed) { converged = true; passes++; break; }
        }
        report.put("schema", 1);
        report.put("program", currentProgram.getName());
        report.put("language", currentProgram.getLanguageID().toString());
        report.put("pointer_size", pointerSize);
        report.put("archive", archiveDescription);
        report.put("jni_slots", nativeTable.getNumComponents());
        report.put("passes", passes);
        report.put("converged", converged);
        report.put("changes", changes);
        report.put("findings", findings.values());
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(report);
        if (args.length > 1) Files.writeString(Paths.get(args[1]), json + "\n");
        else {
            // A program option keeps the last report available without a mandatory file dialog.
            currentProgram.getOptions("APK Defense JNI").setString("Last report", json);
        }
        println("JNI analysis: " + changes.size() + " changes, " + findings.size() + " findings; converged=" + converged);
        for (Map<String,Object> item : findings.values()) println(item.toString());
    }

    private void loadTypes(String selection) throws Exception {
        DataTypeManager source = null;
        FileDataTypeManager owned = null;
        DataTypeManagerService service = state.getTool() == null ? null :
            state.getTool().getService(DataTypeManagerService.class);
        if (selection.equals("auto")) {
            if (service != null) for (DataTypeManager m : service.getDataTypeManagers()) {
                if (m != dtm && m.getName().equals("jni_all")) { source = m; break; }
            }
        }
        if (source == null) {
            if (selection.equals("auto")) {
                if (isRunningHeadless()) throw new IOException(
                    "Pass the JNI archive as a script argument: -postScript ResolveJNI.java /path/jni_all.gdt [report.json]");
                selection = askFile("Select JNI type archive", "Use archive").getCanonicalPath();
            }
            if (service != null) {
                // Ghidra owns the archive and keeps it open for subsequent runs.
                source = service.openArchive(new File(selection), false).getDataTypeManager();
            } else {
                owned = FileDataTypeManager.openFileArchive(new File(selection), false);
                source = owned;
            }
        }
        archiveDescription = source.getName() + " (" + (owned == null ? "open Ghidra archive" : selection) + ")";
        StandAloneDataTypeManager normalized = new StandAloneDataTypeManager("JNI normalized", dtm.getDataOrganization());
        int tx = normalized.startTransaction("Normalize JNI scalar widths");
        try {
            for (String name : List.of("JNIEnv", "JavaVM", "JNINativeInterface_", "JNIInvokeInterface_", "JNINativeMethod")) {
                List<DataType> matches = new ArrayList<>(); source.findDataTypes(name, matches);
                if (matches.size() != 1) throw new IOException("Expected one " + name + " in archive");
                normalized.resolve(matches.get(0), DataTypeConflictHandler.DEFAULT_HANDLER);
            }
            Map<String,DataType> scalars = new LinkedHashMap<>();
            scalars.put("jboolean", ByteDataType.dataType); scalars.put("jbyte", SignedByteDataType.dataType);
            scalars.put("jchar", WordDataType.dataType); scalars.put("jshort", SignedWordDataType.dataType);
            scalars.put("jint", SignedDWordDataType.dataType); scalars.put("jsize", SignedDWordDataType.dataType);
            scalars.put("jlong", SignedQWordDataType.dataType); scalars.put("jfloat", FloatDataType.dataType);
            scalars.put("jdouble", DoubleDataType.dataType);
            for (Map.Entry<String,DataType> entry : scalars.entrySet()) {
                List<DataType> matches = new ArrayList<>(); normalized.findDataTypes(entry.getKey(),matches);
                if (matches.size() != 1) throw new IOException("Missing/ambiguous JNI scalar " + entry.getKey());
                DataType old = matches.get(0);
                normalized.replaceDataType(old, new TypedefDataType(old.getCategoryPath(), old.getName(), entry.getValue(), normalized), true);
            }
            // Keep corrected types separate from an archive already imported by an
            // analyst. Detach archive identities as well as paths so Ghidra cannot
            // silently reuse an older, ABI-incompatible jint definition.
            List<DataType> detached = new ArrayList<>(); normalized.getAllDataTypes(detached);
            for (DataType type : detached) if (!(type instanceof BuiltInDataType)) normalized.disassociate(type);
            Category root = normalized.getRootCategory();
            Category[] originalCategories = root.getCategories();
            DataType[] originalRootTypes = root.getDataTypes();
            Category isolated = normalized.createCategory(new CategoryPath("/APKDefenseJNI"));
            for (Category category : originalCategories) isolated.moveCategory(category, monitor);
            for (DataType type : originalRootTypes) {
                if (type instanceof TypeDef || type instanceof Composite || type instanceof FunctionDefinition)
                    isolated.moveDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER);
            }
            source = normalized;
            env = new PointerDataType(importType(source, "JNIEnv"), dtm);
            vm = new PointerDataType(importType(source, "JavaVM"), dtm);
            nativeTable = (Structure) base(importType(source, "JNINativeInterface_"));
            invokeTable = (Structure) base(importType(source, "JNIInvokeInterface_"));
            methodType = (Structure) base(importType(source, "JNINativeMethod"));
            // Derive every offset from the imported, target-sized structure, never 32-bit constants.
            validateTable(nativeTable, "RegisterNatives", 215);
            validateTable(invokeTable, "GetEnv", 6);
            if (methodType.getLength() != 3 * pointerSize) throw new IOException("Invalid JNINativeMethod layout");
            for (int i = 0; i < 3; i++) if (methodType.getComponent(i).getOffset() != i * pointerSize)
                throw new IOException("Invalid JNINativeMethod field layout");
            Map<String,Integer> widths = new LinkedHashMap<>();
            for (String name : scalars.keySet()) {
                int width = named(name).getLength();
                if (width != scalars.get(name).getLength()) throw new IOException("JNI scalar width mismatch: " + name);
                widths.put(name,width);
            }
            report.put("jni_scalar_widths", widths);
        } finally {
            normalized.endTransaction(tx, true); normalized.close();
            if (owned != null) owned.close();
        }
    }
    private DataType importType(DataTypeManager source, String name) throws Exception {
        List<DataType> matches = new ArrayList<>();
        source.findDataTypes(name, matches);
        if (matches.size() != 1) throw new IOException("Expected one " + name + " in archive, got " + matches.size());
        return dtm.resolve(matches.get(0), DataTypeConflictHandler.DEFAULT_HANDLER);
    }
    private void validateTable(Structure table, String anchor, int index) throws Exception {
        for (DataTypeComponent c : table.getComponents()) {
            if (c.getOffset() != c.getOrdinal() * pointerSize || c.getLength() != pointerSize)
                throw new IOException("Archive has incompatible pointer layout: " + table.getPathName());
        }
        if (table.getNumComponents() <= index || !anchor.equals(table.getComponent(index).getFieldName()))
            throw new IOException("Archive missing standard JNI anchor " + anchor);
    }
    private DataType base(DataType d) { while (d instanceof TypeDef) d = ((TypeDef)d).getBaseDataType(); return d; }
    private DataType named(String name) {
        DataType d = dtm.getDataType(nativeTable.getCategoryPath(), name);
        if (d == null) throw new IllegalArgumentException("JNI type missing: " + name);
        return d;
    }
    private boolean editable(Function f) { return f.getSignatureSource() != SourceType.USER_DEFINED && !f.hasCustomVariableStorage(); }
    private void note(String message) { if (changes.add(message)) changed = true; }
    private void seedEntries() throws Exception {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String n = f.getName();
            if (!editable(f)) continue;
            if (n.equals("JNI_OnLoad") || n.equals("JNI_OnUnload")) {
                List<Variable> params = List.of(new ParameterImpl("vm", vm, currentProgram),
                    new ParameterImpl("reserved", new PointerDataType(VoidDataType.dataType, dtm), currentProgram));
                setSignature(f, params, n.equals("JNI_OnLoad") ? named("jint") : VoidDataType.dataType, "JNI lifecycle");
            } else if (n.startsWith("Java_")) {
                // Export names do not encode return types or whether the method is static.
                setParameter(f, 0, env, "env");
                setParameter(f, 1, named("jobject"), "receiver");
            }
        }
    }
    private void setSignature(Function f, List<? extends Variable> params, DataType ret, String reason) throws Exception {
        if (!editable(f)) return;
        boolean same = f.getParameterCount() == params.size() && f.getReturnType().isEquivalent(ret);
        if (same) for (int i=0;i<params.size();i++) same &= f.getParameter(i).getDataType().isEquivalent(params.get(i).getDataType());
        if (same) return;
        f.updateFunction(null, new ReturnParameterImpl(ret, currentProgram), params,
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.ANALYSIS);
        note(f.getEntryPoint() + ": " + reason);
    }
    private void setParameter(Function f, int index, DataType type, String name) throws Exception {
        if (!editable(f) || index > 32 || f.isExternal()) return;
        List<Variable> params = new ArrayList<>(Arrays.asList(f.getParameters()));
        while (params.size() <= index) params.add(new ParameterImpl(null, Undefined.getUndefinedDataType(pointerSize), currentProgram));
        if (params.get(index).getDataType().isEquivalent(type)) return;
        // A concrete conflicting type is an explicit stopping point, not permission to guess.
        if (base(params.get(index).getDataType()) instanceof Structure || handleKind(params.get(index).getDataType()) != null) return;
        params.set(index, new ParameterImpl(params.get(index).getName(), type, currentProgram));
        String convention = null;
        if (f.getAutoParameterCount() != 0) {
            // Android C++ JNI wrappers use the platform ABI. Make `this` explicit once;
            // passing an auto-parameter back to dynamic storage would duplicate it.
            convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
            List<Variable> explicit = new ArrayList<>();
            for (Variable p : params) explicit.add(new ParameterImpl(p.getName(), p.getDataType(), currentProgram));
            params = explicit;
        }
        f.updateFunction(convention, null, params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.ANALYSIS);
        note(f.getEntryPoint() + ": parameter " + index + " -> " + type.getDisplayName());
    }
    private Map<String,Object> finding(Function f, Address at, String status, String detail) {
        Map<String,Object> item = new LinkedHashMap<>();
        item.put("function", f.getName()); item.put("address", at.toString());
        item.put("status", status); item.put("detail", detail);
        findings.put(at + ":" + status, item);
        return item;
    }
    private void annotate(Address a, String text) {
        String previous = getPlateComment(a), line = "[APK Defense JNI] " + text;
        if (previous == null || !previous.contains(line)) setPlateComment(a, previous == null ? line : previous + "\n" + line);
    }

    // A small, architecture-neutral symbolic evaluator over Ghidra SSA p-code.
    // Unknown operations and disagreeing phi nodes fail closed. No INDIRECT-through-write shortcut.
    private static class Value {
        final String kind; final long offset;
        Value(String k, long o) { kind=k; offset=o; }
        boolean same(Value b) { return b != null && kind.equals(b.kind) && offset == b.offset; }
    }
    private String handleKind(DataType d) {
        if (d == null) return null;
        if (d.isEquivalent(env)) return "env";
        if (d.isEquivalent(vm)) return "vm";
        return null;
    }
    private Value eval(Varnode n, int depth) {
        if (n == null || depth > DEPTH) return null;
        if (n.isConstant()) return new Value("const", n.getOffset());
        String kind = n.getHigh() == null ? null : handleKind(n.getHigh().getDataType());
        if (kind != null) return new Value(kind, 0);
        PcodeOp op = n.getDef();
        // Ghidra can attach call-clobber INDIRECT/self-COPY nodes even to ARM
        // literal pools. Read-only loaded bytes remain usable; writable memory does not.
        if (n.isAddress() && (op == null || op.getOpcode() == PcodeOp.INDIRECT ||
                (op.getOpcode() == PcodeOp.COPY && op.getInput(0).getAddress().equals(n.getAddress())))) {
            Value immutable = readConstant(n.getAddress(), n.getSize());
            if (immutable != null) return immutable;
        }
        if (op == null) return null;
        Value a = op.getNumInputs()>0 ? eval(op.getInput(0),depth+1) : null;
        switch (op.getOpcode()) {
            case PcodeOp.COPY: case PcodeOp.CAST: return a;
            case PcodeOp.MULTIEQUAL:
                if (a == null) return null;
                for (int i=1;i<op.getNumInputs();i++) if (!a.same(eval(op.getInput(i),depth+1))) return null;
                return a;
            case PcodeOp.INT_ADD: case PcodeOp.PTRSUB: case PcodeOp.PTRADD: {
                Value b = eval(op.getInput(1),depth+1);
                if (a == null || b == null || !b.kind.equals("const")) return null;
                long delta = b.offset;
                if (op.getOpcode() == PcodeOp.PTRADD) {
                    Value c = eval(op.getInput(2),depth+1);
                    if (c == null || !c.kind.equals("const")) return null;
                    delta *= c.offset;
                }
                if (a.kind.equals("const") || a.kind.endsWith("_table")) {
                    long result = a.offset + delta;
                    if (a.kind.equals("const") && n.getSize() < 8) result &= (1L << (8*n.getSize()))-1;
                    return new Value(a.kind,result);
                }
                return delta == 0 ? a : null;
            }
            case PcodeOp.LOAD: {
                Value ptr = eval(op.getInput(1),depth+1);
                if (ptr == null) return null;
                if (ptr.kind.equals("env") || ptr.kind.equals("vm")) return new Value(ptr.kind+"_table",0);
                if (ptr.kind.endsWith("_table")) return new Value(ptr.kind.replace("_table","_call"),ptr.offset);
                if (ptr.kind.equals("const")) return readConstant(toAddr(ptr.offset), n.getSize());
                return null;
            }
            default: return null;
        }
    }
    private Value readConstant(Address a, int size) {
        try {
            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            if (b == null || b.isWrite() || !b.isInitialized() || size > 8 || size < 1 || !b.contains(a.add(size-1))) return null;
            byte[] bytes = new byte[size]; currentProgram.getMemory().getBytes(a,bytes);
            long value=0;
            for(int i=0;i<size;i++) value |= (bytes[i]&255L) << (8*(currentProgram.getLanguage().isBigEndian()?size-1-i:i));
            return new Value("const",value);
        } catch (Exception e) { return null; }
    }
    private Long constant(Varnode n) { Value v=eval(n,0); return v!=null && v.kind.equals("const") ? v.offset : null; }
    private DataTypeComponent slot(Value value) {
        if (value == null || !(value.kind.equals("env_call") || value.kind.equals("vm_call")) || value.offset < 0 || value.offset > Integer.MAX_VALUE) return null;
        Structure table = value.kind.equals("env_call") ? nativeTable : invokeTable;
        DataTypeComponent c = table.getComponentAt((int)value.offset);
        return c != null && c.getOffset() == value.offset && base(c.getDataType()) instanceof Pointer &&
            base(((Pointer)base(c.getDataType())).getDataType()) instanceof FunctionDefinition ? c : null;
    }
    private void inspect(Function f, HighFunction hf, DecompInterface decompiler) throws Exception {
        Set<Address> switches = new HashSet<>();
        for (JumpTable jt : hf.getJumpTables()) {
            switches.add(jt.getSwitchAddress());
            Map<String,Object> item=finding(f,jt.getSwitchAddress(),"jump_table", "Targets recovered by Ghidra's decompiler");
            List<String> targets=new ArrayList<>(); for(Address a:jt.getCases()) targets.add(a.toString());
            item.put("targets",targets);
        }
        Iterator<PcodeOpAST> ops=hf.getPcodeOps();
        while(ops.hasNext()) {
            PcodeOpAST op=ops.next(); Address at=op.getSeqnum().getTarget();
            if(op.getOpcode()==PcodeOp.BRANCHIND && !switches.contains(at)) finding(f,at,"unresolved_branch","Computed branch without recovered jump table");
            if(op.getOpcode()==PcodeOp.CALL) {
                Function target=getFunctionAt(op.getInput(0).getAddress());
                if (target != null && target.isThunk()) target = target.getThunkedFunction(true);
                if (target != null && wrappers.containsKey(target.getEntryPoint())) {
                    processJNI(f, hf, op, wrappers.get(target.getEntryPoint()), "verified wrapper " + target.getName());
                }
                if (target != null && !target.isExternal() && editable(target) &&
                    target.getSignatureSource() == SourceType.DEFAULT && target.getParameterCount() == 0 &&
                    op.getNumInputs() == 1 && Arrays.stream(f.getParameters()).anyMatch(p -> handleKind(p.getDataType()) != null)) {
                    DecompileResults callee = decompiler.decompileFunction(target, 30, monitor);
                    if (callee.decompileCompleted() && callee.getHighFunction().getLocalSymbolMap().getNumParams() > 0) {
                        HighFunctionDBUtil.commitParamsToDatabase(callee.getHighFunction(), true,
                            HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS);
                        note(target.getEntryPoint() + ": materialized Ghidra-inferred helper parameters");
                    }
                }
                if(target != null) for(int i=1;i<op.getNumInputs();i++) {
                    Value v=eval(op.getInput(i),0);
                    if(v!=null && (v.kind.equals("env") || v.kind.equals("vm")))
                        setParameter(target,i-1,v.kind.equals("env")?env:vm,"jni_"+(i-1));
                }
            }
            if(op.getOpcode()!=PcodeOp.CALLIND) continue;
            Value v=eval(op.getInput(0),0); DataTypeComponent c=slot(v);
            if(c==null) {
                Long address=constant(op.getInput(0)); Function target=address==null?null:getFunctionAt(codeAddress(address));
                if(target!=null) {
                    finding(f,at,"constant_indirect_call",target.getName()+" @ "+target.getEntryPoint());
                    annotate(at,"indirect target " + target.getName());
                } else finding(f,at,"unresolved_call","No proven JNI table origin or constant function target");
                continue;
            }
            processJNI(f, hf, op, c, "JNI table load");
            FunctionDefinition signature = (FunctionDefinition)base(((Pointer)base(c.getDataType())).getDataType());
            boolean forwards = op.getNumInputs()-1 == signature.getArguments().length;
            for (int i=1; forwards && i<op.getNumInputs(); i++) forwards = parameterSlot(op.getInput(i),0) == i-1;
            if (forwards && !wrappers.containsKey(f.getEntryPoint())) {
                wrappers.put(f.getEntryPoint(), c);
                note(f.getEntryPoint()+": verified forwarding wrapper " + c.getFieldName());
            }
        }
    }
    private int parameterSlot(Varnode n, int depth) {
        if (depth > DEPTH) return -1;
        if (n.getHigh() instanceof HighParam) return ((HighParam)n.getHigh()).getSlot();
        PcodeOp op=n.getDef();
        if (op!=null && (op.getOpcode()==PcodeOp.COPY || op.getOpcode()==PcodeOp.CAST || op.getOpcode()==PcodeOp.INT_ZEXT || op.getOpcode()==PcodeOp.INT_SEXT)) return parameterSlot(op.getInput(0),depth+1);
        if (op!=null && op.getOpcode()==PcodeOp.SUBPIECE && op.getInput(1).isConstant() && op.getInput(1).getOffset()==0) return parameterSlot(op.getInput(0),depth+1);
        return -1;
    }
    private void processJNI(Function f, HighFunction hf, PcodeOp op, DataTypeComponent c, String evidence) throws Exception {
        Address at=op.getSeqnum().getTarget(); String name=c.getFieldName();
        Map<String,Object> item=finding(f,at,"jni_call",name);
        item.put("evidence",evidence);
        item.put("table",c.getParent().isEquivalent(nativeTable)?"JNIEnv":"JavaVM"); item.put("slot",c.getOffset()/pointerSize);
        annotate(at,name+" ("+item.get("table")+" slot "+item.get("slot")+")");
        if(name.equals("GetEnv") && op.getNumInputs()>=4) {
            Long version=constant(op.getInput(3));
            if(version!=null && Set.of(0x10001L,0x10002L,0x10004L,0x10006L,0x10008L).contains(version))
                typeGetEnvLocal(hf,op.getInput(2));
        }
        if(name.equals("RegisterNatives")) {
            if(op.getNumInputs()<5) { item.put("registration","unresolved argument count"); return; }
            Long table=constant(op.getInput(3)), count=constant(op.getInput(4));
            if(table==null || count==null || count<1 || count>MAX_METHODS) { item.put("registration","unresolved table/count (runtime or stack construction)"); return; }
            recoverMethods(f,at,toAddr(table),count.intValue(),item);
        }
    }
    private void typeGetEnvLocal(HighFunction hf, Varnode pointer) throws Exception {
        PcodeOp def=pointer.getDef();
        while(def!=null && (def.getOpcode()==PcodeOp.CAST || def.getOpcode()==PcodeOp.COPY)) { pointer=def.getInput(0); def=pointer.getDef(); }
        Address address=HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram.getAddressFactory(),def);
        if(address==null || !address.isStackAddress()) return;
        HighSymbol symbol=hf.getLocalSymbolMap().findLocal(address,null);
        if(symbol==null || symbol.getDataType().isEquivalent(env)) return;
        Variable existing=HighFunctionDBUtil.getFunctionVariable(symbol);
        if(existing!=null && existing.getSource()==SourceType.USER_DEFINED) return;
        HighFunctionDBUtil.updateDBVariable(symbol,null,env,SourceType.ANALYSIS);
        note(hf.getFunction().getEntryPoint()+": GetEnv local "+address+" -> JNIEnv *");
    }
    private Address codeAddress(long raw) {
        if(currentProgram.getLanguage().getProcessor().toString().equals("ARM")) raw &= ~1L;
        return toAddr(raw);
    }
    private long readPointer(Address address) throws Exception {
        return pointerSize==8 ? currentProgram.getMemory().getLong(address) : Integer.toUnsignedLong(currentProgram.getMemory().getInt(address));
    }
    private String readString(long pointer) throws Exception {
        Address a=toAddr(pointer); StringBuilder s=new StringBuilder();
        for(int i=0;i<2048;i++) {
            int c=currentProgram.getMemory().getByte(a.add(i))&255;
            if(c==0) return s.toString();
            if(c<32 || c>126) throw new IOException("Non-ASCII/encoded registration string");
            s.append((char)c);
        }
        throw new IOException("Registration string too long");
    }
    private void recoverMethods(Function caller, Address at, Address table, int count, Map<String,Object> item) throws Exception {
        List<Map<String,Object>> methods=new ArrayList<>();
        List<Function> funcs=new ArrayList<>(); List<List<DataType>> signatures=new ArrayList<>(); List<String> names=new ArrayList<>();
        try {
            MemoryBlock block=currentProgram.getMemory().getBlock(table);
            if(block==null || block.isWrite() || !block.contains(table.add((long)count*3*pointerSize-1))) throw new IOException("Table is writable, unmapped or crosses a block");
            for(int i=0;i<count;i++) {
                Address row=table.add((long)i*3*pointerSize);
                String name=readString(readPointer(row));
                String descriptor=readString(readPointer(row.add(pointerSize)));
                if(!name.matches("[A-Za-z_$][A-Za-z0-9_$]*")) throw new IOException("Unsupported method name");
                Address entry=codeAddress(readPointer(row.add(2L*pointerSize)));
                Function f=getFunctionAt(entry);
                if(f==null || f.isExternal() || currentProgram.getMemory().getBlock(entry)==null || !currentProgram.getMemory().getBlock(entry).isExecute()) throw new IOException("Target is not an analyzed executable function");
                List<DataType> types=parseDescriptor(descriptor);
                funcs.add(f); signatures.add(types); names.add(name);
                Map<String,Object> method=new LinkedHashMap<>(); method.put("name",name); method.put("descriptor",descriptor); method.put("target",entry.toString()); methods.add(method);
            }
        } catch(Exception e) { item.put("registration","needs_review: "+e.getMessage()); return; }
        for(int i=0;i<count;i++) {
            Function f=funcs.get(i); List<DataType> types=signatures.get(i);
            List<Variable> params=new ArrayList<>(); params.add(new ParameterImpl("env",env,currentProgram)); params.add(new ParameterImpl("receiver",named("jobject"),currentProgram));
            for(int j=0;j<types.size()-1;j++) params.add(new ParameterImpl("arg"+j,types.get(j),currentProgram));
            setSignature(f,params,types.get(types.size()-1),"RegisterNatives "+names.get(i));
            annotate(f.getEntryPoint(),"Registered method "+names.get(i)+" "+methods.get(i).get("descriptor")+"; static/instance requires Java metadata");
        }
        String key=table+":"+count;
        if(registrations.add(key)) {
            ArrayDataType array=new ArrayDataType(methodType,count,methodType.getLength(),dtm);
            // Preserve existing listing definitions; never clear code or analyst-created data.
            Data existing=getDataAt(table);
            if(existing==null || existing.getDataType() instanceof Undefined) {
                try { createData(table,array); note(table+": JNINativeMethod["+count+"]"); }
                catch(Exception e) { item.put("table_annotation", "Existing listing preserved: "+e.getMessage()); }
            }
        }
        item.put("registration","resolved_static_table"); item.put("methods",methods);
    }
    private List<DataType> parseDescriptor(String s) throws Exception {
        if(!s.startsWith("(")) throw new IOException("Invalid descriptor");
        int[] pos={1}; List<DataType> types=new ArrayList<>();
        while(pos[0]<s.length() && s.charAt(pos[0])!=')') types.add(descriptorType(s,pos,false));
        if(pos[0]>=s.length() || s.charAt(pos[0]++)!=')') throw new IOException("Invalid descriptor");
        types.add(descriptorType(s,pos,true));
        if(pos[0]!=s.length()) throw new IOException("Trailing descriptor bytes");
        return types;
    }
    private DataType descriptorType(String s,int[] p,boolean allowVoid) throws Exception {
        if(p[0]>=s.length()) throw new IOException("Truncated descriptor");
        char c=s.charAt(p[0]++);
        switch(c) {
            case 'V': if(allowVoid) return VoidDataType.dataType; break;
            case 'Z': return named("jboolean"); case 'B': return named("jbyte"); case 'C': return named("jchar");
            case 'S': return named("jshort"); case 'I': return named("jint"); case 'J': return named("jlong");
            case 'F': return named("jfloat"); case 'D': return named("jdouble");
            case 'L': {
                int end=s.indexOf(';',p[0]); if(end<=p[0]) break;
                String cls=s.substring(p[0],end); if(!cls.matches("[A-Za-z0-9_$/]+")) break; p[0]=end+1;
                return named(cls.equals("java/lang/String")?"jstring":cls.equals("java/lang/Class")?"jclass":"jobject");
            }
            case '[': descriptorType(s,p,false); return named("jarray");
        }
        throw new IOException("Unsupported descriptor");
    }
}
