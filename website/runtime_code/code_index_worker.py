"""Isolated Androguard reference index and bounded constant evaluation; no target code execution."""
import base64
import json
import re
import sys
from collections import defaultdict

UNKNOWN=object()

def argument_evidence(value):
    if isinstance(value,str):return {'text':value[:4096],'truncated':len(value)>4096}
    if isinstance(value,list) and len(value)<=4096 and all(type(v) is int and -128<=v<=255 for v in value):
        raw=bytes(v&255 for v in value)
        return {'hex':raw.hex(),'base64':base64.b64encode(raw).decode(),'length':len(raw)}
    return {'status':'unresolved'}

def identity(owner,name,desc):return owner+'->'+name+desc.replace(' ','')
def java_name(owner):return (owner[1:-1] if owner.startswith('L') and owner.endswith(';') else owner).replace('/','.')
def category(target):
    if '->loadUrl(' in target or '->loadData' in target:return 'webview_navigation'
    if '->setWebViewClient(' in target or 'WebViewClient;' in target:return 'webview_client'
    if 'customtabs/' in target or '->launchUrl(' in target:return 'custom_tab'
    if target.startswith(('Ljava/net/','Ljavax/net/','Lokhttp','Lorg/apache/http/')):return 'network_boundary'
    if target.startswith(('Lorg/json/','Lcom/google/gson/','Lcom/fasterxml/jackson/','Lcom/squareup/moshi/','Lkotlinx/serialization/')):return 'parser_boundary'
    if target.startswith(('Ljava/lang/reflect/','Ljava/lang/Class;->forName','Ljava/lang/Class;->get')):return 'reflection'
    if target.startswith('Ljavax/crypto/'):return 'crypto_boundary'
    return 'app_reference'

class Unsupported(ValueError):pass

class Index:
    def __init__(self,data):
        from loguru import logger
        logger.disable('androguard')
        from androguard.core.dex import DEX
        dex=DEX(data)
        self.methods={};self.classes=[];self.sites=[];self.edges=[];self.seen=set();self.steps=0;self.notes=set();self.fields={}
        self.max_steps=300000
        for cls in dex.get_classes():
            self.classes.append({'class':java_name(cls.get_name()),'descriptor':cls.get_name(),'superclass':cls.get_superclassname(),
                'interfaces':cls.get_interfaces(),'basis':'static_class_declaration','executed':'not_established'})
            for field in cls.get_fields():
                init=field.get_init_value()
                if init:
                    value=init.get_value()
                    if isinstance(value,(str,int)):
                        field_id=field.get_class_name()+'->'+field.get_name()+' '+field.get_descriptor()
                        self.fields[field_id]=value
                        if isinstance(value,str):self.site(field_id,0,'field_literal',value=value,basis='static_encoded_field_value')
        count=0
        for method in dex.get_encoded_methods():
            code=method.get_code()
            if not code:continue
            key=identity(method.get_class_name(),method.get_name(),method.get_descriptor())
            instructions={}
            for pc,ins in method.get_instructions_idx():
                count+=1
                if count>2000000:raise Unsupported('Instruction index budget exceeded')
                name=ins.get_name();ops=ins.get_operands(pc)
                extra=ins.get_data() if name=='fill-array-data-payload' else None
                width=getattr(ins,'element_width',None)
                instructions[pc]=(name,ops,ins.get_length(),extra,width)
                if name.startswith('invoke'):
                    target=str(ops[-1][-1]).replace(' ','')
                    self.edges.append({'from':key,'to':target,'offset':pc,'basis':'static_invoke_reference','dispatch':name,'category':category(target)})
                    if category(target)!='app_reference':self.site(key,pc,category(target),target=target)
                    if 'stringfog' in target.casefold():
                        self.site(key,pc,'stringfog_candidate',target=target,basis='named_StringFog_reference',
                                  limitations=['Name-based candidate; obfuscated names and unmodeled decoders may remain unresolved'])
                if name.startswith('const-string'):self.site(key,pc,'string_literal',value=str(ops[-1][-1]))
                if name=='new-instance':self.site(key,pc,'instantiation',target=str(ops[-1][-1]))
                if name.startswith(('iget','sget','iput','sput')):
                    field=str(ops[-1][-1]);basis='static_field_read' if 'get' in name else 'static_field_write'
                    self.edges.append({'from':key,'to':field,'offset':pc,'basis':basis,'category':'field_reference'})
            xor=any(n.startswith('xor-') for n,_,_,_,_ in instructions.values())
            self.methods[key]={'registers':code.get_registers_size(),'incoming':code.get_ins_size(),'static':bool(method.get_access_flags()&8),'code':instructions,'xor':xor}
            if xor:self.site(key,0,'xor_candidate',basis='heuristic_xor_instruction',reason='XOR alone does not establish string decoding or encryption')
        if len(self.edges)>200000:raise Unsupported('Reference count budget exceeded')
        # Evaluate each method independently with unknown arguments. Only deterministic,
        # modeled prefixes/paths produce values; unknown branches stop interpretation.
        for key,method in self.methods.items():
            if self.steps>=self.max_steps:self.notes.add('constant_evaluation_step_limit');break
            try:self.evaluate(key,[],(),emit=True)
            except (Unsupported,ValueError,IndexError,KeyError,TypeError,OverflowError,UnicodeError,ZeroDivisionError):pass
        self.method_count=len(self.methods)
        hierarchy={c['descriptor']:c.get('superclass') for c in self.classes}
        for cls in self.classes:
            parent=cls.get('superclass');visited=set()
            while parent and parent not in visited and len(visited)<16:
                visited.add(parent)
                if parent in ('Landroid/webkit/WebViewClient;','Landroid/webkit/WebChromeClient;','Landroid/webkit/WebView;'):
                    cls['webview_base']=parent;break
                parent=hierarchy.get(parent)

    def site(self,method,offset,kind,**values):
        if len(self.sites)>=30000:self.notes.add('site_limit');return
        record={'method':method,'class':java_name(method.split('->')[0]),'offset':offset,'kind':kind,
                'basis':'static_reference','executed':'not_established',**values}
        if isinstance(record.get('value'),str) and len(record['value'])>4096:
            record['value']=record['value'][:4096];record['truncated']=True
        key=json.dumps(record,sort_keys=True)
        if key not in self.seen:self.sites.append(record);self.seen.add(key)

    def evaluate(self,key,args,stack,emit=False):
        if key not in self.methods or key in stack or len(stack)>=6:raise Unsupported('Unknown or recursive helper')
        method=self.methods[key];regs={};pending=UNKNOWN;code=method['code'];pc=0;local_steps=0;tainted=method['xor']
        for i,value in enumerate(args):regs[method['registers']-method['incoming']+i]=value
        while pc in code:
            self.steps+=1;local_steps+=1
            if self.steps>self.max_steps or local_steps>20000:raise Unsupported('Evaluation step limit')
            name,ops,length,extra,width=code[pc];rr=[int(x[1]) for x in ops if int(x[0])==0]
            vv=[regs.get(r,UNKNOWN) for r in rr];lit=[x[1] for x in ops if int(x[0])==1];next_pc=pc+length
            if name.startswith('move-result'):regs[rr[0]]=pending
            elif name.startswith('move') and len(rr)>=2:regs[rr[0]]=vv[1]
            elif name.startswith('const-string'):regs[rr[0]]=str(ops[-1][-1])
            elif name=='const-class':regs[rr[0]]=('class',str(ops[-1][-1]))
            elif name.startswith('const'):regs[rr[0]]=lit[0]
            elif name=='new-instance':regs[rr[0]]={'type':str(ops[-1][-1])}
            elif name=='new-array':
                if type(vv[1]) is not int or not 0<=vv[1]<=4096:raise Unsupported('Array size')
                regs[rr[0]]=[0]*vv[1]
            elif name.startswith('filled-new-array'):pending=list(vv)
            elif name=='fill-array-data':
                payload=code[pc+int(ops[-1][1])*2];data,w=payload[3],payload[4]
                if not isinstance(vv[0],list) or w not in (1,2,4) or len(vv[0])*w>len(data):raise Unsupported('Array payload')
                vv[0][:]=[int.from_bytes(data[i*w:(i+1)*w],'little',signed=w!=2) for i in range(len(vv[0]))]
            elif name=='array-length':
                if not isinstance(vv[1],list):raise Unsupported('Unknown array')
                regs[rr[0]]=len(vv[1])
            elif name.startswith('aget'):
                if not isinstance(vv[1],list) or type(vv[2]) is not int or not 0<=vv[2]<len(vv[1]):raise Unsupported('Array read')
                regs[rr[0]]=vv[1][vv[2]]
            elif name.startswith('aput'):
                if not isinstance(vv[1],list) or type(vv[2]) is not int or not 0<=vv[2]<len(vv[1]):raise Unsupported('Array write')
                vv[1][vv[2]]=vv[0]
            elif name.startswith(('xor-int','add-int','sub-int','rem-int','and-int','or-int','mul-int')):
                a,b=(vv[0],vv[1]) if '/2addr' in name else (vv[1],lit[0] if lit else vv[2])
                if type(a) is not int or type(b) is not int:raise Unsupported('Unknown arithmetic')
                op=name.split('-')[0];v={'xor':lambda:a^b,'add':lambda:a+b,'sub':lambda:a-b,'rem':lambda:a-int(a/b)*b,'and':lambda:a&b,'or':lambda:a|b,'mul':lambda:a*b}[op]()
                regs[rr[0]]=(v+2**31)%2**32-2**31
            elif name in ('int-to-byte','int-to-char','int-to-short'):
                if type(vv[1]) is not int:raise Unsupported('Unknown conversion')
                bits=8 if name=='int-to-byte' else 16;v=vv[1]&((1<<bits)-1)
                regs[rr[0]]=v if name=='int-to-char' or v<1<<(bits-1) else v-(1<<bits)
            elif name.startswith('goto'):next_pc=pc+int(ops[-1][1])*2
            elif name.startswith('if-'):
                a=vv[0];b=vv[1] if len(vv)>1 else 0
                if type(a) is not int or type(b) is not int:raise Unsupported('Unknown branch; no guessed merge')
                condition={'eq':a==b,'ne':a!=b,'lt':a<b,'le':a<=b,'gt':a>b,'ge':a>=b}[name.split('-')[1].rstrip('z')]
                if condition:next_pc=pc+int(ops[-1][1])*2
            elif name.startswith('sget'):
                field=str(ops[-1][-1]);regs[rr[0]]=self.fields.get(field,UNKNOWN)
                if 'Ljava/nio/charset/StandardCharsets;->UTF_8' in field:regs[rr[0]]='UTF-8'
            elif name.startswith('invoke'):
                target=str(ops[-1][-1]).replace(' ','')
                original_args=[argument_evidence(v) for v in vv]
                pending,used_xor=self.call(target,vv,stack+(key,),key,pc,emit)
                tainted|=used_xor
                value=pending.get('value') if isinstance(pending,dict) else pending
                if emit and isinstance(value,str) and (used_xor or re.search(r'https?://',value)):
                    self.site(key,pc,'decoded_string' if used_xor else 'computed_string',value=value,decoder=target,
                              decoder_arguments=original_args,
                              string_obfuscation={'classification':'stringfog_candidate' if used_xor and 'stringfog' in target.casefold() else 'xor_decoder' if used_xor else 'computed_value',
                                'input':original_args[0] if original_args else {'status':'unresolved'},
                                'key_candidate':original_args[1] if len(original_args)>1 else {'status':'unresolved'},
                                'key_role':'Second argument retained; key semantics require decoder inspection'},
                              basis='bounded_constant_evaluation',limitations=['Modeled bytecode path; execution not established'])
            elif name.startswith('return'):
                value=vv[0] if vv else None
                if isinstance(value,dict) and 'value' in value:value=value['value']
                return value,tainted
            elif name in ('nop','check-cast'):pass
            else:raise Unsupported('Unmodeled instruction '+name)
            pc=next_pc
        raise Unsupported('No modeled return')

    def call(self,target,args,stack,owner,pc,emit):
        if target.startswith('Ljava/lang/String;-><init>'):
            value=args[1] if len(args)>1 else UNKNOWN
            if isinstance(value,list):
                if any(type(v) is not int for v in value):raise Unsupported('Unknown string bytes')
                if target.startswith('Ljava/lang/String;-><init>([C'):value=''.join(chr(v&65535) for v in value)
                elif len(args)>2 and args[2] not in ('UTF-8','UTF8'):raise Unsupported('Unmodeled charset/string constructor')
                else:value=bytes(v&255 for v in value).decode('utf-8')
            if isinstance(args[0],dict) and isinstance(value,str):args[0]['value']=value
            return UNKNOWN,False
        if target.startswith('Ljava/lang/String;->getBytes(') and isinstance(args[0],str):
            if len(args)>1 and args[1] not in ('UTF-8','UTF8'):raise Unsupported('Unmodeled charset')
            value=args[0].encode('utf-8')
            if len(value)>4096:raise Unsupported('String byte limit')
            return list(value),False
        if target.startswith('Ljava/lang/String;->length(') and isinstance(args[0],str):return len(args[0].encode('utf-16-le','surrogatepass'))//2,False
        if target.startswith('Ljava/lang/String;->charAt(') and isinstance(args[0],str) and type(args[1]) is int:
            value=args[0].encode('utf-16-le','surrogatepass');index=args[1]*2
            if not 0<=index<len(value):raise Unsupported('String index')
            return int.from_bytes(value[index:index+2],'little'),False
        if target.startswith('Landroid/util/Base64;->decode(') and isinstance(args[0],str) and len(args[0])<=8192:
            return list(base64.b64decode(args[0],validate=True)),False
        if target.startswith('Ljava/lang/Class;->forName(') and isinstance(args[0],str):return ('class','L'+args[0].replace('.','/')+';'),False
        if target.startswith(('Ljava/lang/Class;->getMethod(','Ljava/lang/Class;->getDeclaredMethod(')):
            if isinstance(args[0],tuple) and args[0][0]=='class' and isinstance(args[1],str):
                params=args[2] if len(args)>2 else []
                desc='('+''.join(t[1] for t in params)+')' if isinstance(params,list) and all(isinstance(t,tuple) and t[0]=='class' for t in params) else '(?)'
                return ('method',args[0][1],args[1],desc),False
        if target.startswith(('Ljava/lang/Class;->getConstructor(','Ljava/lang/Class;->getDeclaredConstructor(')) and isinstance(args[0],tuple):return ('constructor',args[0][1]),False
        if target.startswith('Ljava/lang/reflect/Method;->invoke(') and isinstance(args[0],tuple) and args[0][0]=='method':
            resolved=args[0][1]+'->'+args[0][2]+args[0][3]+'?'
            if emit:
                self.site(owner,pc,'reflective_call',target=resolved,basis='statically_resolved_reflection',category=category(resolved),return_type='unresolved',target_existence='not_verified')
                self.edges.append({'from':owner,'to':resolved,'offset':pc,'basis':'statically_resolved_reflection','category':category(resolved)})
            return UNKNOWN,False
        if target.startswith(('Ljava/lang/reflect/Constructor;->newInstance(','Ljava/lang/Class;->newInstance(')) and isinstance(args[0],tuple):
            resolved=args[0][1]
            if emit:
                self.site(owner,pc,'reflective_instantiation',target=resolved,basis='statically_resolved_reflection')
                self.edges.append({'from':owner,'to':resolved+'-><init>(?)?','offset':pc,'basis':'statically_resolved_reflection','category':'instantiation'})
            return {'type':resolved},False
        if target in self.methods:
            # Resolve only the exact bytecode reference; virtual/interface dispatch is
            # intentionally not guessed from method-name similarity.
            copied=[]
            import copy
            copied=copy.deepcopy(args)
            try:
                result=self.evaluate(target,copied,stack)
                for original,updated in zip(args,copied):
                    if isinstance(original,list):original[:]=updated
                    elif isinstance(original,dict):original.clear();original.update(updated)
                return result
            except (Unsupported,ValueError,IndexError,KeyError,TypeError,OverflowError,UnicodeError,ZeroDivisionError):pass
        # Unknown calls may mutate their arguments. Do not subsequently decode from
        # stale modeled bytes or claim a string produced after an unmodeled mutation.
        for value in args:
            if isinstance(value,list):value[:]=[UNKNOWN]*len(value)
            elif isinstance(value,dict):value.pop('value',None)
        return UNKNOWN,False

    def result(self):
        return {'format':'code-references/v1','validity':'indexed','classes':self.classes,'sites':self.sites,'edges':self.edges,
            'defined_methods':sorted(self.methods),
            'method_count':self.method_count,'evaluation_steps':self.steps,'diagnostics':sorted(self.notes),
            'limitations':['Static references are potential paths, not observed execution or proven data flow',
             'Constant evaluation stops on unknown branches and unmodeled instructions; no universal StringFog/reflective resolution',
             'No native/Dart/JavaScript bodies; method dispatch and cross-DEX helper evaluation may remain unresolved']}

def worker_limits():
    """Keep CPU/output limits on both hosts; Darwin has no reliable RLIMIT_AS cap."""
    import resource
    limitations=[]
    if sys.platform == 'darwin':
        limitations.append('macOS worker has no hard address-space limit; input, evaluation, CPU, output and host timeout limits still apply')
    else:
        resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(45,45))
    resource.setrlimit(resource.RLIMIT_FSIZE,(32*1024**2,32*1024**2))
    return limitations


if __name__=='__main__':
    try:
        limitations=worker_limits()
        from pathlib import Path
        with Path(sys.argv[1]).open('rb') as source:
            data=source.read(64*1024**2+1)
        if len(data)>64*1024**2:raise Unsupported('DEX byte limit')
        result=Index(data).result()
        result['limitations'].extend(limitations)
        print(json.dumps(result,ensure_ascii=True))
    except Exception as error:
        print(json.dumps({'format':'code-references/v1','validity':'failed','diagnostic':str(error)}));sys.exit(1)
