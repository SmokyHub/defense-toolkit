"""Bounded isolated AArch64 string-helper emulation, without Android or host calls."""
import struct
import time

from family4_native import Unsupported


class Decoder:
    MAX_STEPS = 100000
    MAX_SECONDS = 1.0
    MAX_TOTAL_SECONDS = 15.0
    MAX_CALLS = 512
    BASE = 0x700000000000
    SIZE = 0x10000

    def __init__(self, img, entry, imported):
        try:
            import unicorn as u
            from unicorn import arm64_const as r
        except ImportError as error:
            raise Unsupported('isolated decoder requires unicorn; install requirements.txt') from error
        self.u, self.r, self.img, self.entry, self.imported = u, r, img, entry, imported
        self.calls = 0; self.total_time = 0; self.cache = {}
        defined = {}
        for sec in img.elf.iter_sections():
            if sec['sh_type'] in ('SHT_DYNSYM','SHT_SYMTAB'):
                for symbol in sec.iter_symbols():
                    if (symbol['st_shndx']!='SHN_UNDEF' and symbol['st_info']['type']=='STT_FUNC'
                            and symbol['st_value'] in img.byaddr):
                        defined.setdefault(symbol.name,set()).add(symbol['st_value'])
        self.local_targets = {address:next(iter(defined[name])) for address,name in imported.items()
                              if len(defined.get(name,()))==1}
        self._check_direct_helpers()
        try:
            self.machine = u.Uc(u.UC_ARCH_ARM64, u.UC_MODE_ARM)
            pages = set()
            for s in img.loads:
                start, end = s['p_vaddr'], s['p_vaddr'] + s['p_filesz']
                if end > self.BASE or end-start > 32*1024*1024:
                    raise Unsupported('isolated decoder ELF mapping bounds')
                pages.update(range(start & ~4095, (end+4095)&~4095, 4096))
            if len(pages) > 8192:
                raise Unsupported('isolated decoder mapped-byte budget')
            for address in sorted(pages):self.machine.mem_map(address,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
            for s in img.loads:
                self.machine.mem_write(s['p_vaddr'],img.read(s['p_vaddr'],s['p_filesz']))
            for address, value in img.reloc.items():
                self.machine.mem_write(address,struct.pack('<Q',value))
            self.stack, self.heap, self.result, self.tls, self.stop = [self.BASE+i*self.SIZE for i in range(5)]
            for address in (self.stack,self.heap,self.result,self.tls):
                self.machine.mem_map(address,self.SIZE,u.UC_PROT_READ|u.UC_PROT_WRITE)
            self.machine.mem_map(self.stop,4096,u.UC_PROT_READ|u.UC_PROT_EXEC)
            self.machine.hook_add(u.UC_HOOK_CODE,self._code)
            self.machine.hook_add(u.UC_HOOK_MEM_READ,self._read)
            self.machine.hook_add(u.UC_HOOK_MEM_WRITE,self._write)
            self.initial = self.machine.context_save()
        except u.UcError as error:
            raise Unsupported("isolated decoder mapping failure: "+str(error)) from error

    def _check_direct_helpers(self):
        from family4_indexed import body
        pending=[self.entry];seen=set();count=0
        while pending:
            start=pending.pop()
            if start in seen:continue
            seen.add(start)
            if len(seen)>32:raise Unsupported('decoder helper-count budget')
            code=body(self.img,start,self.imported);count+=len(code)
            if count>16384:raise Unsupported('decoder helper-code budget')
            for ins in code:
                if ins.mnemonic=='ret' and ins.op_str not in ('','x30'):
                    raise Unsupported('nonstandard decoder helper return')
                if ins.mnemonic=='bl':
                    target=ins.operands[0].imm
                    if target in self.local_targets:pending.append(self.local_targets[target])
                    elif target not in self.imported:pending.append(target)
                    elif self.imported[target] not in ('malloc','calloc','__stack_chk_fail'):
                        raise Unsupported('unmodeled decoder dependency: '+self.imported[target])

    def _fail(self, reason):
        self.error = reason
        self.machine.emu_stop()

    def _read(self, uc, access, address, size, value, user):
        if address < self.BASE:
            try:self.img.read(address,size)
            except Unsupported:
                self._fail('decoder reads outside file-backed input');return
            self.reads.update(range(address,address+size))
            if len(self.reads)>65536:self._fail('decoder source-read budget')

    def _write(self, uc, access, address, size, value, user):
        if not any(base<=address and address+size<=base+self.SIZE for base in (self.stack,self.heap,self.result)):
            self._fail('decoder writes outside isolated scratch memory')

    def _code(self, uc, address, size, user):
        r=self.r
        if address==self.stop:
            self.returned=True;uc.emu_stop();return
        self.steps+=1
        if self.steps>self.MAX_STEPS or (self.steps%128==0 and time.monotonic()-self.started>self.MAX_SECONDS):
            self._fail('isolated decoder instruction/time budget');return
        imported=self.imported.get(address)
        if imported:
            if address in self.local_targets:
                uc.reg_write(r.UC_ARM64_REG_PC,self.local_targets[address]);return
            a,b=uc.reg_read(r.UC_ARM64_REG_X0),uc.reg_read(r.UC_ARM64_REG_X1)
            if imported not in ('calloc','malloc'):
                self._fail('unmodeled decoder import: '+imported);return
            size=a*b if imported=='calloc' else a
            if not 1<=size<=16385 or self.allocated+size>self.SIZE:
                self._fail('isolated decoder allocation budget');return
            ptr=self.heap+self.allocated;self.allocated=(self.allocated+size+15)&~15
            # calloc is zeroed. malloc stays poisoned until initialized by guest code.
            uc.mem_write(ptr,(b'\0' if imported=='calloc' else b'\xa5')*size)
            self.allocations[ptr]=size;uc.reg_write(r.UC_ARM64_REG_X0,ptr)
            uc.reg_write(r.UC_ARM64_REG_PC,uc.reg_read(r.UC_ARM64_REG_LR));return
        ins=self.img.byaddr.get(address)
        if ins is None or ins.mnemonic in ('svc','hvc','smc','brk','hlt','msr','sys','sysl'):
            self._fail('unmodeled decoder instruction or system operation');return
        if bytes(uc.mem_read(address,4)) != bytes(ins.bytes):
            self._fail('decoder instruction differs from inspected input');return
        if ins.mnemonic in ('paciasp','autiasp','pacibsp','autibsp','bti'):
            uc.reg_write(r.UC_ARM64_REG_PC,address+4)
        elif ins.mnemonic=='mrs' and not ins.op_str.endswith('tpidr_el0'):
            self._fail('unmodeled decoder system register')

    def decode(self, identifier):
        if identifier in self.cache:return self.cache[identifier]
        if self.calls>=self.MAX_CALLS or self.total_time>=self.MAX_TOTAL_SECONDS:
            raise Unsupported('isolated decoder aggregate budget')
        self.calls+=1
        first=self._decode_once(identifier,False)
        second=self._decode_once(identifier,True)
        if (first is None)!=(second is None) or (first and first['text']!=second['text']):
            raise Unsupported('decoder depends on unmodeled register/stack inputs')
        if first:
            first['input_model']='ID in w0 and result pointer in x8; two scratch-state probes agree, not a proof of input independence.'
        self.cache[identifier]=first
        return first

    def _decode_once(self, identifier, poison):
        self.steps=0;self.error=None;self.returned=False;self.reads=set()
        self.allocated=0;self.allocations={};uc=self.machine;r=self.r
        uc.context_restore(self.initial)
        for base in (self.stack,self.heap,self.result,self.tls):uc.mem_write(base,b'\0'*self.SIZE)
        if poison:
            uc.mem_write(self.stack,b'\xa5'*self.SIZE)
            for index in range(30):
                if index not in (0,8):uc.reg_write(getattr(r,'UC_ARM64_REG_X'+str(index)),0x5a5a5a5a5a5a5a5a)
        uc.reg_write(r.UC_ARM64_REG_SP,self.stack+self.SIZE-16)
        uc.reg_write(r.UC_ARM64_REG_X0,identifier&0xffffffff)
        uc.reg_write(r.UC_ARM64_REG_X8,self.result)
        uc.reg_write(r.UC_ARM64_REG_LR,self.stop)
        uc.reg_write(r.UC_ARM64_REG_TPIDR_EL0,self.tls)
        self.started=time.monotonic()
        try:uc.emu_start(self.entry,self.stop+4,timeout=int(self.MAX_SECONDS*1000000),count=self.MAX_STEPS+2)
        except self.u.UcError as error:self.error='isolated decoder memory/CPU fault: '+str(error)
        finally:self.total_time+=time.monotonic()-self.started
        if self.error or not self.returned:
            raise Unsupported(self.error or 'isolated decoder did not return within bounds')
        ptr,size=struct.unpack('<QQ',uc.mem_read(self.result,16))
        if not ptr and not size:
            return None
        if not 1<=size<=16385 or self.allocations.get(ptr)!=size:
            raise Unsupported('decoder output does not match a bounded allocation')
        raw=bytes(uc.mem_read(ptr,size))
        if not raw.endswith(b'\0') or b'\0' in raw[:-1]:
            raise Unsupported('decoder output is not one terminated string')
        try:text=raw[:-1].decode('utf-8')
        except UnicodeError as error:raise Unsupported('decoder output is not UTF-8') from error
        if not text or any(ord(c)<32 or ord(c)==127 for c in text):
            raise Unsupported('decoder output is not printable text')
        ranges=[]
        for address in sorted(self.reads):
            if ranges and ranges[-1][0]+ranges[-1][1]==address:ranges[-1][1]+=1
            else:ranges.append([address,1])
        result={'text':text,'length':len(raw)-1,'decoder_va':hex(self.entry),'string_id':identifier,
                'recovery':'bounded_isolated_decoder','instructions':self.steps,
                'input_read_ranges':[{'va':hex(a),'size':n,'file_offset':hex(next(
                    s['p_offset']+a-s['p_vaddr'] for s in self.img.loads if s['p_vaddr']<=a<s['p_vaddr']+s['p_filesz']))}
                    for a,n in ranges],
                'provenance_note':'Input bytes read by this isolated call include metadata and ciphertext; ranges are not bytewise plaintext origins.',
                'decode_calls':[]}
        return result
