"""Bounded, pure AArch64 integer-helper interpreter for finite selector domains.

No native execution, imports, syscalls, Android state or host callbacks. Unknown
caller values remain symbolic: they cannot choose a branch/address or become an
accepted output. Only read-only file-backed ELF data and private scratch exist.
"""
import re
from dataclasses import dataclass

from capstone.arm64_const import (ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM,
    ARM64_SFT_LSL, ARM64_SFT_LSR, ARM64_SFT_ASR, ARM64_SFT_ROR,
    ARM64_EXT_UXTB, ARM64_EXT_UXTH, ARM64_EXT_UXTW, ARM64_EXT_UXTX,
    ARM64_EXT_SXTB, ARM64_EXT_SXTH, ARM64_EXT_SXTW, ARM64_EXT_SXTX)
from family4_native import Unsupported

UNKNOWN = ('unknown',)


@dataclass(frozen=True)
class Address:
    region: str
    offset: int


@dataclass(frozen=True)
class SignedReturn:
    target: Address
    stack: Address
    key: str


class ScalarMachine:
    STACK = 0x700000000000
    OUTPUT = STACK + 0x10000
    STOP = STACK + 0x20000
    MAX_STEPS = 8192
    MAX_TOTAL_STEPS = 200000
    MAX_CALLS = 64

    def __init__(self, image, entry, imported):
        self.image, self.entry, self.imported = image, entry, imported
        self.total_steps = 0
        self.calls = []

    @staticmethod
    def known(value):
        if not isinstance(value, int):
            raise Unsupported('scalar helper depends on unknown caller/scratch state')
        return value

    @staticmethod
    def register(name):
        bits=32 if name.startswith('w') else 64
        name = {'fp':'x29', 'lr':'x30', 'wsp':'sp'}.get(name, name)
        if name not in ('sp','xzr','wzr') and not re.fullmatch(r'[xw](?:[0-9]|[12][0-9]|30)',name):
            raise Unsupported('unmodeled scalar register: '+name)
        return ('zr' if name in ('xzr','wzr') else name.replace('w','x',1),
                bits)

    def get(self, name):
        reg,bits = self.register(name)
        value = 0 if reg == 'zr' else self.regs[reg]
        return value & ((1<<bits)-1) if isinstance(value,int) else value if bits==64 else UNKNOWN

    def put(self, name, value):
        reg,bits = self.register(name)
        if reg != 'zr':
            self.regs[reg] = value & ((1<<bits)-1) if isinstance(value,int) else value if bits==64 else UNKNOWN

    @staticmethod
    def signed(value, bits):
        value &= (1<<bits)-1
        return value-(1<<bits) if value>>(bits-1) else value

    def shifted(self, value, op, bits):
        if not isinstance(value,int):return value if not op.ext and not op.shift.type else UNKNOWN
        extensions = {ARM64_EXT_UXTB:(8,False), ARM64_EXT_UXTH:(16,False),
            ARM64_EXT_UXTW:(32,False), ARM64_EXT_UXTX:(64,False),
            ARM64_EXT_SXTB:(8,True), ARM64_EXT_SXTH:(16,True),
            ARM64_EXT_SXTW:(32,True), ARM64_EXT_SXTX:(64,True)}
        if op.ext:
            if op.ext not in extensions:raise Unsupported('unmodeled scalar extension')
            width,sign = extensions[op.ext]
            value = self.signed(value,width) if sign else value & ((1<<width)-1)
        mask = (1<<bits)-1
        value &= mask
        amount = op.shift.value
        if not op.shift.type:return value
        if not 0<=amount<bits:raise Unsupported('unmodeled scalar immediate shift')
        if op.shift.type==ARM64_SFT_LSL:return (value<<amount)&mask
        if op.shift.type==ARM64_SFT_LSR:return value>>amount
        if op.shift.type==ARM64_SFT_ASR:return self.signed(value,bits)>>amount & mask
        if op.shift.type==ARM64_SFT_ROR:return (value>>amount | value<<(bits-amount))&mask
        raise Unsupported('unmodeled scalar shift')

    def operand(self, ins, op, bits):
        if op.type==ARM64_OP_REG:value=self.get(ins.reg_name(op.reg))
        elif op.type==ARM64_OP_IMM:value=op.imm
        else:raise Unsupported('unmodeled scalar operand')
        return self.shifted(value,op,bits)

    def compare(self, a, b, bits, add=False):
        if not isinstance(a,int) or not isinstance(b,int):
            self.flags=None;return
        mask=(1<<bits)-1;a&=mask;b&=mask
        result=(a+b if add else a-b)&mask
        overflow=((~(a^b) if add else a^b)&(a^result))>>(bits-1)&1
        self.flags=(bool(result>>(bits-1)),result==0,a+b>mask if add else a>=b,bool(overflow))

    def condition(self, cc):
        # Capstone ARM64_CC_EQ..NV: AL and NV are unconditional for A64.
        if cc in (15,16):return True
        if self.flags is None:raise Unsupported('scalar helper branches on unknown flags')
        n,z,c,v=self.flags
        conditions={1:z,2:not z,3:c,4:not c,5:n,6:not n,7:v,8:not v,
                    9:c and not z,10:not c or z,11:n==v,12:n!=v,13:not z and n==v,14:z or n!=v}
        if cc not in conditions:raise Unsupported('unmodeled scalar condition')
        return conditions[cc]

    def memory(self, address, width, value=None, *, write=False):
        if not isinstance(address,Address) or address.region not in ('image','stack','output'):
            raise Unsupported('scalar helper uses an unproven memory address')
        region=address.region
        if region!='image' and not 0<=address.offset<=({'stack':4096,'output':8}[region]-width):
            raise Unsupported('scalar scratch address escapes its region')
        address=address.offset+{'image':0,'stack':self.STACK,'output':self.OUTPUT}[region]
        scratch=(self.STACK<=address and address+width<=self.STACK+4096
                 or self.OUTPUT<=address and address+width<=self.OUTPUT+8)
        if region!='image' and not scratch:raise Unsupported('scalar scratch address escapes its region')
        if region=='image' and scratch:raise Unsupported('scalar image address aliases scratch')
        if not scratch:
            if write:raise Unsupported('scalar helper writes outside private scratch')
            if not any(not s['p_flags']&2 and s['p_vaddr']<=address
                       and address+width<=s['p_vaddr']+s['p_filesz'] for s in self.image.loads):
                raise Unsupported('scalar helper reads mutable or non-file-backed memory')
            if any(address<va+8 and va<address+width for va in self.image.reloc):
                raise Unsupported('scalar helper reads relocated data')
            self.reads.update(range(address,address+width))
            if len(self.reads)>65536:raise Unsupported('scalar helper read budget exceeded')
            return int.from_bytes(self.image.read(address,width),'little')
        if write:
            for k in range(width):
                self.scratch[address+k]=(value>>(8*k))&255 if isinstance(value,int) else (value,k,width)
            return
        values=[self.scratch.get(address+k) for k in range(width)]
        if all(isinstance(x,int) for x in values):return int.from_bytes(bytes(values),'little')
        # Preserve an untouched symbolic saved register through a full-width spill.
        first=values[0]
        if isinstance(first,tuple) and first[1:]==(0,width):
            if values==[(first[0],k,width) for k in range(width)]:return first[0]
        return UNKNOWN

    def load_store(self, ins):
        ops=ins.operands;m=ins.mnemonic
        index=next((k for k,o in enumerate(ops) if o.type==ARM64_OP_MEM),None)
        if index not in (1,2):raise Unsupported('unmodeled scalar memory operands')
        mem=ops[index];base=ins.reg_name(mem.mem.base)
        registers=[self.register(ins.reg_name(o.reg))[0] for o in ops[:index]]
        if ((ins.writeback and self.register(base)[0] in registers)
                or m=='ldp' and registers[0]==registers[1]):
            raise Unsupported('unpredictable scalar memory register overlap')
        origin=self.get(base)
        if not isinstance(origin,Address):raise Unsupported('scalar memory base lacks pointer provenance')
        offset=origin.offset+mem.mem.disp
        if mem.mem.index:
            index_value=self.shifted(self.get(ins.reg_name(mem.mem.index)),mem,64)
            offset+=self.signed(self.known(index_value),64)
        address=Address(origin.region,offset)
        width=1 if m in ('ldrb','strb') else 2 if m in ('ldrh','strh') else self.register(ins.reg_name(ops[0].reg))[1]//8
        if index==2 and m not in ('ldp','stp'):raise Unsupported('unmodeled scalar paired access')
        for k in range(index):
            if ops[k].type!=ARM64_OP_REG:raise Unsupported('unmodeled scalar load/store register')
            name=ins.reg_name(ops[k].reg)
            at=Address(address.region,address.offset+k*width)
            if m.startswith('ld'):self.put(name,self.memory(at,width))
            else:self.memory(at,width,self.get(name),write=True)
        if ins.writeback:
            if ins.post_index:
                if ops[-1].type!=ARM64_OP_IMM:raise Unsupported('unmodeled scalar post-index')
                self.put(base,Address(origin.region,origin.offset+ops[-1].imm))
            else:self.put(base,address)

    def run(self, identifier, *, output=False):
        if len(self.calls)>=self.MAX_CALLS:raise Unsupported('scalar helper call budget exceeded')
        self.regs={f'x{k}':('caller',k) for k in range(31)}
        self.regs.update(x0=identifier,sp=Address('stack',4080),x30=Address('return',0))
        if output:self.regs['x1']=Address('output',0)
        preserved={r:self.regs[r] for r in ['sp',*[f'x{k}' for k in range(18,30)]]}
        self.scratch={};self.reads=set();self.flags=None;pc=self.entry
        for steps in range(1,self.MAX_STEPS+1):
            self.total_steps+=1
            if self.total_steps>self.MAX_TOTAL_STEPS:raise Unsupported('scalar helper aggregate instruction budget')
            if pc==self.STOP:
                if any(self.regs[r]!=value for r,value in preserved.items()):
                    raise Unsupported('scalar helper violates preserved-register/stack ABI')
                returned=self.known(self.get('x0'))
                if output and returned!=1:raise Unsupported('scalar selector rejected an in-domain input')
                result=self.known(self.memory(Address('output',0),8)) if output else returned
                ranges=[]
                for address in sorted(self.reads):
                    offset=next(s['p_offset']+address-s['p_vaddr'] for s in self.image.loads
                                if s['p_vaddr']<=address<s['p_vaddr']+s['p_filesz'])
                    if (ranges and ranges[-1]['va']+ranges[-1]['size']==address
                            and ranges[-1]['file_offset']+ranges[-1]['size']==offset):ranges[-1]['size']+=1
                    else:ranges.append({'va':address,'file_offset':offset,'size':1})
                ranges=[dict(row,va=hex(row['va']),file_offset=hex(row['file_offset'])) for row in ranges]
                self.calls.append({'input':identifier,'output':result,'instructions':steps-1,'read_ranges':ranges})
                return result
            if pc in self.imported:raise Unsupported('scalar helper import is not allowed')
            ins=self.image.byaddr.get(pc)
            if ins is None:raise Unsupported('scalar helper reaches undecoded code')
            if not any(s['p_flags']&1 and not s['p_flags']&2 and s['p_vaddr']<=pc
                       and pc+4<=s['p_vaddr']+s['p_filesz'] for s in self.image.loads):
                raise Unsupported('scalar helper code is not immutable executable input')
            m=ins.mnemonic;ops=ins.operands;pc+=4
            if m in ('nop','bti'):continue
            if m in ('paciasp','autiasp','pacibsp','autibsp'):
                link=self.get('x30');stack=self.get('sp');key='b' if m.endswith('bsp') else 'a'
                if m.startswith('pac'):
                    if not isinstance(link,Address) or link.region!='return' or not isinstance(stack,Address):
                        raise Unsupported('unmodeled scalar pointer-authentication source')
                    self.put('x30',SignedReturn(link,stack,key))
                else:
                    if not isinstance(link,SignedReturn) or link.stack!=stack or link.key!=key:
                        raise Unsupported('scalar pointer-authentication state mismatch')
                    self.put('x30',link.target)
                continue
            if m=='ret':
                if ins.op_str not in ('','x30'):raise Unsupported('unmodeled scalar return')
                target=self.get('x30')
                if target==Address('return',0):pc=self.STOP
                elif isinstance(target,Address) and target.region=='return':pc=target.offset
                else:raise Unsupported('scalar return address lacks call provenance')
                continue
            if m in ('b','bl') or m.startswith('b.'):
                if len(ops)!=1 or ops[0].type!=ARM64_OP_IMM:raise Unsupported('unmodeled scalar branch')
                if m=='bl':self.put('x30',Address('return',pc))
                if m in ('b','bl') or self.condition(ins.cc):pc=ops[0].imm
                continue
            if m in ('cbz','cbnz','tbz','tbnz'):
                value=self.known(self.operand(ins,ops[0],64))
                test=value==0 if m.startswith('cb') else not value&(1<<ops[1].imm)
                if test==(m in ('cbz','tbz')):pc=ops[-1].imm
                continue
            if m in ('ldr','ldur','ldrb','ldrh','ldp','str','stur','strb','strh','stp'):
                self.load_store(ins);continue
            if not ops or ops[0].type!=ARM64_OP_REG:raise Unsupported('unmodeled scalar instruction: '+m)
            dest=ins.reg_name(ops[0].reg);bits=self.register(dest)[1];mask=(1<<bits)-1
            values=[self.operand(ins,o,bits) for o in ops[1:]]
            if m in ('adr','adrp'):result=Address('image',values[0])
            elif m=='mov':result=values[0]
            elif m=='movk':
                old=self.get(dest);shift=ops[1].shift.value
                result=(old&~(0xffff<<shift))|values[0] if isinstance(old,int) else UNKNOWN
            elif m in ('cmp','cmn','ccmp','ccmn'):
                if m in ('ccmp','ccmn') and not self.condition(ins.cc):
                    flags=ops[2].imm;self.flags=tuple(bool(flags&(1<<k)) for k in (3,2,1,0))
                else:self.compare(self.get(dest),values[0],bits,m in ('cmn','ccmn'))
                continue
            elif m in ('csel','csinc','csinv','csneg'):
                take=self.condition(ins.cc);result=values[0] if take else values[1]
                if not take and isinstance(result,int):
                    result={'csel':result,'csinc':result+1,'csinv':~result,'csneg':-result}[m]
            elif m in ('cset','csetm'):result=(1 if m=='cset' else mask) if self.condition(ins.cc) else 0
            elif m in ('add','adds','sub','subs','and','ands','orr','eor','bic','mul','madd','msub','umaddl','umulh','udiv','lsl','lsr','asr','ror','neg','mvn'):
                result=UNKNOWN
                if m in ('add','sub') and isinstance(values[0],Address) and isinstance(values[1],int):
                    delta=self.signed(values[1],bits)
                    result=Address(values[0].region,values[0].offset+(delta if m=='add' else -delta))
                elif m=='add' and isinstance(values[0],int) and isinstance(values[1],Address):
                    result=Address(values[1].region,values[1].offset+self.signed(values[0],bits))
                elif m=='sub' and all(isinstance(v,Address) for v in values) and values[0].region==values[1].region:
                    result=values[0].offset-values[1].offset
                elif m in ('madd','umaddl') and all(isinstance(v,int) for v in values[:2]) and isinstance(values[2],Address):
                    result=Address(values[2].region,values[2].offset+values[0]*values[1])
                if all(isinstance(v,int) for v in values):
                    a=values[0];b=values[1] if len(values)>1 else 0
                    shift=b%bits
                    if m in ('add','adds'):result=a+b
                    elif m in ('sub','subs'):result=a-b
                    elif m in ('and','ands'):result=a&b
                    elif m=='orr':result=a|b
                    elif m=='eor':result=a^b
                    elif m=='bic':result=a&~b
                    elif m=='mul':result=a*b
                    elif m in ('madd','umaddl'):result=a*b+values[2]
                    elif m=='msub':result=values[2]-a*b
                    elif m=='umulh':result=(a*b)>>64
                    elif m=='udiv':result=a//b if b else 0
                    elif m=='lsl':result=a<<shift
                    elif m=='lsr':result=a>>shift
                    elif m=='asr':result=self.signed(a,bits)>>shift
                    elif m=='ror':result=a>>shift|a<<(bits-shift)
                    elif m=='neg':result=-a
                    elif m=='mvn':result=~a
                if m in ('adds','subs'):self.compare(values[0],values[1],bits,m=='adds')
                elif m=='ands':self.flags=None if not isinstance(result,int) else (bool(result>>(bits-1)),result==0,False,False)
            else:raise Unsupported('unmodeled scalar instruction: '+m)
            self.put(dest,result)
        raise Unsupported('scalar helper instruction budget exceeded')


def recover_selectors(image, bound, imported):
    """Exhaust the caller-verified domains; no extrapolation to untested IDs."""
    domains={'selector_value':list(range(16)), 'role_mapper':[1,*range(3,16)], 'role_order':list(range(14))}
    values={};evidence={}
    for name,domain in domains.items():
        machine=ScalarMachine(image,bound[name],imported)
        values[name]=[machine.run(k,output=name=='selector_value') for k in domain]
        evidence[name]={'helper_va':hex(bound[name]),'calls':machine.calls}
    keys=values['selector_value']
    if len(set(keys[1:]))!=15 or not all(0<=k<10**12 for k in keys):
        raise Unsupported('invalid finite-domain numeric selectors')
    if sorted(values['role_mapper'])!=list(range(14)) or sorted(values['role_order'])!=domains['role_mapper']:
        raise Unsupported('finite-domain role mappings are not permutations')
    return keys,evidence
