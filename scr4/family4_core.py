"""Compositional contract recovery, independent of the app-wide compiler graph."""
from bisect import bisect_right
import json
from pathlib import Path
import struct

from family4_native import (Unsupported, ARM64_OP_MEM, _local_argument,
                            _formatted_numeric_selectors)
from family4_indexed import verify_graph, finish_contract
from family4_decoder import Decoder


def analyze_core(img):
    # A candidate must expose the JNI direct-buffer operation used by this core.
    candidates=set()
    for ins in img.ins:
        if (ins.mnemonic=='ldr' and len(ins.operands)==2 and ins.operands[1].type==ARM64_OP_MEM
                and ins.operands[1].mem.disp==0x730):
            at=bisect_right(img.starts,ins.address)-1
            if at>=0:candidates.add(img.starts[at])
    if not candidates:return None
    if len(candidates)>16:
        return {'family':'family4','status':'needs_review','contracts':[],'strings':[],
                'diagnostics':['core candidate budget exceeded']}
    model=json.loads(Path(__file__).with_name('family4_core_models.json').read_text())
    results=[];failures=[]
    for start in sorted(candidates):
        try:bound,codes,refs,constants,imported=verify_graph(img,start,model,core=True)
        except (Unsupported,KeyError,IndexError):continue
        try:
            table=refs[('selectors',model['selector_table_instruction'])]
            outer=struct.unpack('<Q',img.read(table,8))[0]
            # The same checked decimal formatter must feed JNI NewStringUTF.
            triggers=[x for x in _formatted_numeric_selectors(img) if x['value']==str(outer)]
            if not triggers:raise Unsupported('core outer selector lacks a verified JNI trigger')
            decoder=Decoder(img,bound['decoder'],imported)
            rows={};required={}
            for name,spec in model['functions'].items():
                for k,binding in spec.get('string_calls',{}).items():
                    call=codes[name][int(k)];identifier=constants[(name,binding['argument_instruction'])]
                    row=decoder.decode(identifier)
                    if row is None or binding['kind']!='literal' or row['text']!=binding['text']:
                        raise Unsupported('core JNI string argument does not match its use')
                    required[call.address]=identifier
                    rows[identifier]=row
            # Recover actual constant-ID calls elsewhere, without matching their callers' bodies.
            # Their instruction flow is not assumed to execute during normal app startup.
            calls={}
            for k,ins in enumerate(img.ins):
                if ins.mnemonic=='bl' and ins.operands[0].imm==bound['decoder']:
                    identifier=_local_argument(img.ins,k,'x0')
                    if identifier is not None and 0<=identifier<=0xffffffff:
                        calls.setdefault(identifier,[]).append(ins.address)
            if len(calls)>Decoder.MAX_CALLS:raise Unsupported('decoder call-ID budget exceeded')
            for identifier,addresses in calls.items():
                row=decoder.decode(identifier)
                if row is None:raise Unsupported('decoder rejected a referenced constant ID')
                rows[identifier]=row
                row['decode_calls']=[{'call_va':hex(a),'string_id':identifier} for a in addresses]
            if not all(identifier in calls and va in calls[identifier] for va,identifier in required.items()):
                raise Unsupported('inconsistent core decoder call provenance')
            result=finish_contract(img,model,bound,codes,refs,constants,list(rows.values()),
                                   {'kind':'isolated'},outer_evidence=triggers)
            result.update(variant='compositional_native_core',
                evidence_level='verified_native_contract_and_isolated_decoder_calls',
                decoder_transform={'mode':'bounded_isolated_native_instructions'},
                endpoint_evidence='Decoded constant-ID call; surrounding network path is not verified.',
                recovery_scope='Constant-ID decoder calls; unreferenced strings and dynamically computed IDs may be absent.',
                limitations=['Conditional contract at the verified native loader. Surrounding startup, network and registration logic is not matched.',
                             'Isolated decoder execution is not evidence that the app invoked the loader or executed the DEX.',
                             'Changed parser/loader control flow, unsupported decoder dependencies or ambiguous contracts still require review.'])
            result['analysis_stages']=[{'stage':'verified_contract_helpers','status':'observed','candidate_count':len(bound)-1},
                                      {'stage':'isolated_decoder_calls','status':'observed','candidate_count':decoder.calls},
                                      {'stage':'outer_trigger','status':'observed','candidate_count':len(triggers)}]
            results.append(result)
        except (Unsupported,ValueError,struct.error) as error:failures.append(str(error))
    if len(results)==1:return results[0]
    if results or failures:
        return {'family':'family4','variant':'compositional_native_core','status':'needs_review',
                'contracts':[],'strings':[],'diagnostics':['ambiguous core contracts'] if results else failures,
                'runtime_execution_observed':False}
    return None
