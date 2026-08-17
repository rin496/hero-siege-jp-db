#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Hero Siege Permanent Master Extractor
=====================================

常設Master版。以後は基本的にこの1本を使います。
"""
from pathlib import Path
import argparse,csv,hashlib,json,math,shutil,struct,time,zipfile
from collections import Counter,defaultdict
MASTER_VERSION="permanent-master-v6-github"
FUNC_BEGIN=0x05856C00;FUNC_END=0x0588E599;DEFINE_INIT=0x04FF54F0
PREP=0x0C54E830;TARGET=0x0C579810;ITEM_HELPER=0x058A48A0;VALUE_HELPER=0x56710;CLEANUP=0x56560;FIELD_CONSUMER_HELPER=0x0C566890;FIELD_CONSUMER_INNER=0x0C534390
PRIMARY_SEGMENTS=list(range(2,71,2));KNOWN_SEGMENTS={8:"Godfather",20:"Thor",40:"Genji"}
KNOWN_EXPECTED={"Godfather":{"target_subsequence":[13315,1424,11],"identity_candidate":1855},"Thor":{"target_subsequence":[8860,1424,83],"identity_candidate":16155},"Genji":{"target_subsequence":[8866,1424,78],"identity_candidate":29455}}
DEFAULT_RULES={"version":2,"identity_fields":["0x100","0x1D0"],"fingerprint":{"use_target_head":False,"target_head_length":4,"numeric_local_fields":["0x1D0"]},"auto_tune":{"enabled":True,"max_fields":4,"min_coverage":10,"prefer_full_coverage":True}}
REG=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"]
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def s32(b,o):return struct.unpack_from('<i',b,o)[0]
def desktop():
    for p in (Path.home()/"Desktop",Path.home()/"OneDrive"/"Desktop"):
        if p.exists():return p
    return Path.cwd()
def sha256(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1<<20),b''):h.update(c)
    return h.hexdigest()
def finite_double(q):
    try:
        x=struct.unpack('<d',struct.pack('<Q',q))[0]
        if not math.isfinite(x) or abs(x)>1e12:return None
        return int(round(x)) if abs(x-round(x))<1e-10 else x
    except:return None
def uniq_order(seq):
    out=[]
    for x in seq:
        if x not in out:out.append(x)
    return out
def contains_subsequence(seq,sub):
    j=0
    for x in seq:
        if j<len(sub) and x==sub[j]:j+=1
    return j==len(sub)
def deep_copy_jsonable(obj):return json.loads(json.dumps(obj))
def load_json(path,default):
    if not path.exists():return deep_copy_jsonable(default)
    try:return json.loads(path.read_text(encoding='utf-8'))
    except:return deep_copy_jsonable(default)
def save_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')
def append_jsonl(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a',encoding='utf-8') as f:f.write(json.dumps(obj,ensure_ascii=False)+'\n')
def migrate_rules_to_v2(rules):
    old=deep_copy_jsonable(rules);changed=False
    if int(rules.get('version',1))<2:rules['version']=2;changed=True
    ids=list(rules.get('identity_fields',[]))
    for d in ('0x100','0x1D0'):
        if d not in ids:ids.append(d);changed=True
    rules['identity_fields']=ids;fp=rules.setdefault('fingerprint',{})
    if fp.get('use_target_head',True) is not False:fp['use_target_head']=False;changed=True
    if fp.get('numeric_local_fields')!=['0x1D0']:fp['numeric_local_fields']=['0x1D0'];changed=True
    fp.setdefault('target_head_length',4)
    return rules,{'changed':changed,'old_rules':old,'new_rules':deep_copy_jsonable(rules),'reason':'promote_rbp_0x1D0_to_canonical_fingerprint' if changed else 'already_v2'}
class PE:
    def __init__(self,path):
        self.path=path;self.data=path.read_bytes();self.sections=[];self._parse()
    def _parse(self):
        d=self.data;pe=u32(d,0x3C);coff=pe+4;nsec=u16(d,coff+2);optsz=u16(d,coff+16);opt=coff+20;self.image_base=u64(d,opt+24);sec=opt+optsz
        for i in range(nsec):
            o=sec+i*40;self.sections.append({'name':d[o:o+8].split(b'\0',1)[0].decode('ascii','ignore'),'virtual_size':u32(d,o+8),'rva':u32(d,o+12),'raw_size':u32(d,o+16),'raw_ptr':u32(d,o+20),'executable':bool(u32(d,o+36)&0x20000000)})
    def rva_to_off(self,rva):
        for s in self.sections:
            span=max(s['virtual_size'],s['raw_size'])
            if s['rva']<=rva<s['rva']+span:
                delta=rva-s['rva']
                if delta<s['raw_size']:return s['raw_ptr']+delta
        return None
    def get(self,begin,end):
        off=self.rva_to_off(begin)
        if off is None:return b''
        return self.data[off:off+(end-begin)]
    def section_by_name(self,name):
        for s in self.sections:
            if s['name']==name:return s
        return None
    def pdata_function_containing(self,rva):
        s=self.section_by_name('.pdata')
        if not s:return None
        off=s['raw_ptr'];count=s['raw_size']//12;d=self.data
        for i in range(count):
            o=off+i*12
            if o+12>len(d):break
            beg=u32(d,o);end=u32(d,o+4);uw=u32(d,o+8)
            if beg<=rva<end:return {'begin':beg,'end':end,'size':end-beg,'unwind_rva':uw,'pdata_index':i}
        return None
def choose_exe(root):
    for p in (root/'Hero_Siege.exe',root/'bin'/'Hero_Siege.exe',root/'Hero Siege.exe',root/'bin'/'Hero Siege.exe'):
        if p.exists():return p
    xs=list(root.rglob('Hero_Siege.exe'))
    if not xs:raise SystemExit('Hero_Siege.exe not found')
    return xs[0]
def build_direct_calls(pe,begin,end):
    b=pe.get(begin,end);calls=[];by_target=defaultdict(list);i=0
    while i+5<=len(b):
        if b[i]==0xE8:
            rva=begin+i;dst=(rva+5+s32(b,i+1))&0xffffffff;rec={'rva':rva,'target':dst};calls.append(rec);by_target[dst].append(rva);i+=5
        else:i+=1
    return calls,by_target
def build_prep_segments(calls):
    preps=[c['rva'] for c in calls if c['target']==PREP];segments=[]
    for i,begin in enumerate(preps):
        end=preps[i+1] if i+1<len(preps) else FUNC_END;segments.append({'segment_index':i,'begin':begin,'end':end,'size':end-begin})
    return preps,segments
def scan_block(pe,begin,end):
    b=pe.get(begin,end);events=[];imm_by_reg={};i=0
    while i<len(b):
        rva=begin+i
        if i+5<=len(b) and b[i]==0xE8:
            events.append({'rva':rva,'kind':'CALL','target':(rva+5+s32(b,i+1))&0xffffffff});i+=5;continue
        if i+10<=len(b) and b[i]==0x48 and 0xB8<=b[i+1]<=0xBF:
            reg=REG[b[i+1]-0xB8];q=u64(b,i+2);rec={'rva':rva,'kind':'REG_IMM64','reg':reg,'qword':q,'double':finite_double(q)};events.append(rec);imm_by_reg[reg]=rec;i+=10;continue
        if i+7<=len(b) and b[i]==0x48 and b[i+1] in (0x89,0x8B,0x8D):
            m=b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7
            if mod==2 and rm==5:
                reg=REG[rr];disp=s32(b,i+3)
                if b[i+1]==0x89:
                    rec={'rva':rva,'kind':'STORE_REG64_RBP','disp':disp,'reg':reg};prod=imm_by_reg.get(reg)
                    if prod and 0<=rva-prod['rva']<=0x60:rec['source_rva']=prod['rva'];rec['qword']=prod['qword'];rec['double']=prod['double']
                    events.append(rec)
                elif b[i+1]==0x8B:events.append({'rva':rva,'kind':'LOAD_REG64_RBP','disp':disp,'reg':reg})
                else:events.append({'rva':rva,'kind':'LEA_REG64_RBP','disp':disp,'reg':reg})
                i+=7;continue
        if i+10<=len(b) and b[i:i+2]==b'\xC7\x85':events.append({'rva':rva,'kind':'STORE_IMM32_RBP','disp':s32(b,i+2),'value':u32(b,i+6)});i+=10;continue
        i+=1
    return events
def nearest_local_double(events,call_rva,disp,lookback=0x140):
    c=[e for e in events if e['kind']=='STORE_REG64_RBP' and e.get('disp')==disp and e.get('double') is not None and e['rva']<call_rva and call_rva-e['rva']<=lookback]
    return c[-1] if c else None
def nearby_calls(events,rva,before_n=3,after_n=5,distance=0x120):
    before=[e for e in events if e['kind']=='CALL' and e['rva']<rva and rva-e['rva']<=distance];after=[e for e in events if e['kind']=='CALL' and e['rva']>rva and e['rva']-rva<=distance]
    return {'before':before[-before_n:],'after':after[:after_n]}
def structural_target_head(payloads,n):return [x for x in payloads if x is not None][:n]
def extract_primary_blocks(pe,preps,rules):
    rows=[];target_head_len=int(rules['fingerprint'].get('target_head_length',4))
    for ordinal,segidx in enumerate(PRIMARY_SEGMENTS):
        if segidx>=len(preps):continue
        begin=preps[segidx];end=preps[segidx+2] if segidx+2<len(preps) else FUNC_END;events=scan_block(pe,begin,end);block_calls=[e for e in events if e['kind']=='CALL'];target_calls=[e for e in block_calls if e['target']==TARGET];numeric_stores=[e for e in events if e['kind']=='STORE_REG64_RBP' and e.get('double') is not None]
        target_payloads=[]
        for c in target_calls:
            q=nearest_local_double(events,c['rva'],0x1D0);target_payloads.append({'call_rva':c['rva'],'payload':q['double'] if q else None,'store_rva':q['rva'] if q else None})
        payload_values=[x['payload'] for x in target_payloads];local_values=defaultdict(list);local_events=defaultdict(list)
        for e in numeric_stores:local_values[e['disp']].append(e['double']);local_events[e['disp']].append(e)
        row={'candidate_ordinal':ordinal,'segment_index':segidx,'known_name':KNOWN_SEGMENTS.get(segidx),'begin':begin,'end':end,'size':end-begin,'call_count':len(block_calls),'target_count':len(target_calls),'item_helper_count':sum(1 for e in block_calls if e['target']==ITEM_HELPER),'value_helper_count':sum(1 for e in block_calls if e['target']==VALUE_HELPER),'cleanup_count':sum(1 for e in block_calls if e['target']==CLEANUP),'target_payload_values':payload_values,'structural_target_head':structural_target_head(payload_values,target_head_len),'numeric_store_count':len(numeric_stores),'unique_numeric_values':uniq_order([e['double'] for e in numeric_stores]),'local_numeric_values':{f'0x{d:X}':uniq_order(vals) for d,vals in sorted(local_values.items())},'local_numeric_events':{f'0x{d:X}':evs for d,evs in sorted(local_events.items())}}
        lifecycle={}
        for disp_hex in rules.get('identity_fields',[]):
            disp=int(disp_hex,16);evs=[e for e in events if e.get('disp')==disp and e['kind'] in ('STORE_REG64_RBP','LOAD_REG64_RBP','LEA_REG64_RBP','STORE_IMM32_RBP')];lifecycle[disp_hex]=[{'event':e,'nearby_calls':nearby_calls(events,e['rva'])} for e in evs]
        row['identity_lifecycle']=lifecycle;rows.append(row)
    return rows
def trace_call_args_raw(pe,begin,call_rva,window=0xA0):
    a=max(begin,call_rva-window);b=pe.get(a,call_rva);events=[];i=0;base_regs=['RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI'];ext_regs=['R8','R9','R10','R11','R12','R13','R14','R15']
    while i<len(b):
        r=a+i
        if i+10<=len(b) and b[i] in (0x48,0x49) and 0xB8<=b[i+1]<=0xBF:
            idx=b[i+1]-0xB8;reg=(ext_regs if (b[i]&1) else base_regs)[idx];q=u64(b,i+2);events.append({'rva':r,'kind':'IMM','dst':reg,'qword':q,'double':finite_double(q)});i+=10;continue
        if i+3<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x89,0x8B,0x8D):
            rex=b[i];op=b[i+1];m=b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7;reg=(ext_regs if (rex&4) else base_regs)[rr];rmreg=(ext_regs if (rex&1) else base_regs)[rm]
            if mod==3 and op in (0x89,0x8B):dst,source=(rmreg,reg) if op==0x89 else (reg,rmreg);events.append({'rva':r,'kind':'MOV_REG','dst':dst,'src':source});i+=3;continue
            if mod==2 and rm==5 and i+7<=len(b):
                disp=s32(b,i+3);events.append({'rva':r,'kind':'LOAD_RBP' if op==0x8B else 'LEA_RBP','dst':reg,'disp':disp});i+=7;continue
        i+=1
    return {reg:([e for e in events if e.get('dst')==reg][-1] if [e for e in events if e.get('dst')==reg] else None) for reg in ('RCX','RDX','R8','R9')}
def analyze_named_helper(pe,rows,target=FIELD_CONSUMER_HELPER):
    out=[];arg_shape_freq=Counter()
    for r in rows:
        ev=scan_block(pe,r['begin'],r['end']);calls=[e for e in ev if e['kind']=='CALL' and e['target']==target];entries=[]
        for c in calls:
            args=trace_call_args_raw(pe,r['begin'],c['rva']);shape=tuple(None if args[k] is None else (args[k].get('kind'),args[k].get('disp'),args[k].get('src'),args[k].get('double')) for k in ('RCX','RDX','R8','R9'));arg_shape_freq[repr(shape)]+=1;entries.append({'call_rva':c['rva'],'call_rva_hex':f"0x{c['rva']:X}",'args':args,'near_0x100':r.get('local_numeric_values',{}).get('0x100',[]),'canonical_0x1D0':r.get('local_numeric_values',{}).get('0x1D0',[])})
        out.append({'candidate_ordinal':r['candidate_ordinal'],'segment_index':r['segment_index'],'known_name':r['known_name'],'calls':entries})
    return {'target':target,'target_hex':f'0x{target:X}','total_calls':sum(len(x['calls']) for x in out),'arg_shape_frequency':[{'shape':k,'count':v} for k,v in arg_shape_freq.most_common()],'per_block':out}
def analyze_field_consumers(rows,fields=('0x100','0x1D0')):
    out={}
    for field in fields:
        ek=Counter();fa=Counter();aseq=Counter();pb=[]
        for r in rows:
            life=r.get('identity_lifecycle',{}).get(field,[]);ents=[]
            for item in life:
                ev=item.get('event',{});ek[ev.get('kind','?')]+=1;after=item.get('nearby_calls',{}).get('after',[]);seq=tuple(c.get('target') for c in after[:4]);
                if seq:fa[seq[0]]+=1;aseq[seq]+=1
                ents.append({'event':ev,'first_after_target':seq[0] if seq else None,'after_targets':list(seq)})
            pb.append({'candidate_ordinal':r['candidate_ordinal'],'segment_index':r['segment_index'],'known_name':r['known_name'],'field_values':r.get('local_numeric_values',{}).get(field,[]),'events':ents})
        out[field]={'event_kind_counts':dict(ek),'first_after_target_frequency':[{'target':t,'target_hex':f'0x{t:X}','count':c} for t,c in fa.most_common()],'after_sequence_frequency':[{'targets':list(seq),'targets_hex':[f'0x{x:X}' for x in seq],'count':c} for seq,c in aseq.most_common()],'per_block':pb}
    return out
def analyze_helper_body(pe,helper_rva=FIELD_CONSUMER_HELPER):
    bounds=pe.pdata_function_containing(helper_rva)
    if not bounds:return {'helper_rva':helper_rva,'helper_hex':f'0x{helper_rva:X}','bounds_found':False}
    a,z=bounds['begin'],bounds['end'];b=pe.get(a,z);calls=[];freq=Counter();rip=[];i=0
    while i<len(b):
        r=a+i
        if i+5<=len(b) and b[i]==0xE8:
            t=(r+5+s32(b,i+1))&0xffffffff;calls.append({'rva':r,'rva_hex':f'0x{r:X}','target':t,'target_hex':f'0x{t:X}'});freq[t]+=1;i+=5;continue
        if i+7<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x8B,0x8D):
            m=b[i+2]
            if (m&0xC7)==0x05:
                t=(r+7+s32(b,i+3))&0xffffffff;rip.append({'rva':r,'kind':'RIP_LEA' if b[i+1]==0x8D else 'RIP_LOAD','target':t,'target_hex':f'0x{t:X}'});i+=7;continue
        i+=1
    return {'helper_rva':helper_rva,'helper_hex':f'0x{helper_rva:X}','bounds_found':True,'function':{**bounds,'begin_hex':f'0x{a:X}','end_hex':f'0x{z:X}'},'direct_calls':calls,'direct_call_frequency':[{'target':t,'target_hex':f'0x{t:X}','count':c} for t,c in freq.most_common()],'rip_refs':rip,'raw_prefix':b[:256].hex(' '),'raw_suffix':b[-256:].hex(' ') if len(b)>256 else b.hex(' ')}
def analyze_switch_dispatcher(pe,helper_rva=FIELD_CONSUMER_HELPER):
    bounds=pe.pdata_function_containing(helper_rva)
    if not bounds:return {'found':False,'reason':'no_pdata_bounds'}
    a,z=bounds['begin'],bounds['end'];b=pe.get(a,z);result={'found':True,'function':{**bounds,'begin_hex':f'0x{a:X}','end_hex':f'0x{z:X}'}};table=None
    for i in range(len(b)-7):
        if b[i:i+3]==b'\x48\x8D\x15':
            insn=a+i;base=(insn+7+s32(b,i+3))&0xffffffff;table={'lea_rva':insn,'lea_rva_hex':f'0x{insn:X}','table_rva':base,'table_rva_hex':f'0x{base:X}'};break
    result['jump_table']=table;cases=[]
    if table:
        toff=pe.rva_to_off(table['table_rva'])
        if toff is not None:
            for idx in range(16):
                rel=s32(pe.data,toff+idx*4);dst=(table['table_rva']+rel)&0xffffffff;cases.append({'index':idx,'entry_rel32':rel,'target':dst,'target_hex':f'0x{dst:X}'})
    result['cases']=cases;result['case_target_frequency']=[{'target':t,'target_hex':f'0x{t:X}','count':c} for t,c in Counter(x['target'] for x in cases).most_common()];stubs=[]
    for target in sorted(set(x['target'] for x in cases)):
        off=pe.rva_to_off(target)
        if off is None:continue
        raw=pe.data[off:off+64];direct=[];tails=[]
        for j in range(min(len(raw)-5,64)):
            r=target+j
            if raw[j]==0xE8:
                t=(r+5+s32(raw,j+1))&0xffffffff;direct.append({'rva':r,'rva_hex':f'0x{r:X}','target':t,'target_hex':f'0x{t:X}'})
            if raw[j]==0xE9:
                t=(r+5+s32(raw,j+1))&0xffffffff;tails.append({'rva':r,'rva_hex':f'0x{r:X}','target':t,'target_hex':f'0x{t:X}'})
        stubs.append({'target':target,'target_hex':f'0x{target:X}','raw64':raw.hex(' '),'direct_calls':direct,'tail_jumps':tails})
    result['case_stubs']=stubs;return result
def analyze_function_deep(pe,rva):
    bounds=pe.pdata_function_containing(rva)
    if not bounds:return {'rva':rva,'rva_hex':f'0x{rva:X}','bounds_found':False}
    a,z=bounds['begin'],bounds['end'];b=pe.get(a,z);calls=[];tails=[];rip=[];i=0
    while i<len(b):
        cur=a+i
        if i+5<=len(b) and b[i]==0xE8:
            t=(cur+5+s32(b,i+1))&0xffffffff;calls.append({'rva':cur,'rva_hex':f'0x{cur:X}','target':t,'target_hex':f'0x{t:X}'});i+=5;continue
        if i+5<=len(b) and b[i]==0xE9:
            t=(cur+5+s32(b,i+1))&0xffffffff;tails.append({'rva':cur,'rva_hex':f'0x{cur:X}','target':t,'target_hex':f'0x{t:X}'});i+=5;continue
        if i+7<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x8B,0x8D):
            m=b[i+2]
            if (m&0xC7)==0x05:
                t=(cur+7+s32(b,i+3))&0xffffffff;rip.append({'rva':cur,'rva_hex':f'0x{cur:X}','kind':'LEA' if b[i+1]==0x8D else 'LOAD','target':t,'target_hex':f'0x{t:X}'});i+=7;continue
        i+=1
    return {'rva':rva,'rva_hex':f'0x{rva:X}','bounds_found':True,'function':{**bounds,'begin_hex':f'0x{a:X}','end_hex':f'0x{z:X}'},'direct_calls':calls,'direct_call_frequency':[{'target':t,'target_hex':f'0x{t:X}','count':c} for t,c in Counter(x['target'] for x in calls).most_common()],'tail_jumps':tails,'tail_jump_frequency':[{'target':t,'target_hex':f'0x{t:X}','count':c} for t,c in Counter(x['target'] for x in tails).most_common()],'rip_refs':rip,'raw_prefix':b[:512].hex(' '),'raw_suffix':b[-512:].hex(' ') if len(b)>512 else b.hex(' ')}
def survey_local_discriminators(rows):
    mp=defaultdict(dict)
    for r in rows:
        for d,vals in r['local_numeric_values'].items():mp[d][r['candidate_ordinal']]=tuple(vals)
    result=[]
    for d,bm in mp.items():
        groups=defaultdict(list)
        for o,sig in bm.items():groups[sig].append(o)
        collisions=[{'values':list(sig),'ordinals':ords} for sig,ords in groups.items() if len(ords)>1];result.append({'disp':d,'coverage':len(bm),'distinct_signatures':len(groups),'collision_group_count':len(collisions),'collisions':collisions,'block_values':{str(k):list(v) for k,v in sorted(bm.items())}})
    return sorted(result,key=lambda x:(-x['coverage'],-x['distinct_signatures'],x['collision_group_count'],int(x['disp'],16)))
def make_fingerprint(row,rules):
    fp=[]
    if rules['fingerprint'].get('use_target_head',True):fp+=['TARGET_HEAD']+row['structural_target_head']
    for d in rules['fingerprint'].get('numeric_local_fields',[]):fp+=[f'RBP:{d}']+row['local_numeric_values'].get(d,[])
    return fp
def apply_fingerprints(rows,rules):
    groups=defaultdict(list)
    for r in rows:r['fingerprint']=make_fingerprint(r,rules);groups[tuple(r['fingerprint'])].append(r['candidate_ordinal'])
    return [{'fingerprint':list(k),'ordinals':ords} for k,ords in groups.items() if len(ords)>1]
def score_rules(rows,rules):
    c=apply_fingerprints(rows,rules);cb=sum(len(x['ordinals']) for x in c);return {'collision_group_count':len(c),'collided_block_count':cb,'unique_block_count':len(rows)-cb,'collisions':c}
def auto_tune_rules(rows,rules,survey):
    cfg=rules.get('auto_tune',{})
    if not cfg.get('enabled',True):return rules,{'changed':False,'reason':'auto_tune_disabled'}
    before_rules=deep_copy_jsonable(rules);before=score_rules(rows,before_rules)
    if before['collision_group_count']==0:return rules,{'changed':False,'reason':'already_collision_free','before':before,'after':before}
    chosen=list(rules['fingerprint'].get('numeric_local_fields',[]));max_fields=int(cfg.get('max_fields',4));min_cov=int(cfg.get('min_coverage',10));best_rules=deep_copy_jsonable(rules);best_score=before
    for cand in [x for x in survey if x['coverage']>=min_cov and x['disp'] not in chosen]:
        if len(chosen)>=max_fields:break
        trial=deep_copy_jsonable(best_rules);trial['fingerprint']['numeric_local_fields']=chosen+[cand['disp']];ts=score_rules(rows,trial);better=ts['collision_group_count']<best_score['collision_group_count'] or (ts['collision_group_count']==best_score['collision_group_count'] and ts['collided_block_count']<best_score['collided_block_count'])
        if better:chosen.append(cand['disp']);best_rules=trial;best_score=ts
        if best_score['collision_group_count']==0:break
    changed=best_rules['fingerprint'].get('numeric_local_fields',[])!=before_rules['fingerprint'].get('numeric_local_fields',[]);return best_rules,{'changed':changed,'reason':'improved' if changed else 'no_better_field_found','before':before,'after':best_score,'selected_fields':best_rules['fingerprint'].get('numeric_local_fields',[])}
def validate_known(rows):
    out=[]
    for r in rows:
        name=r.get('known_name')
        if not name:continue
        exp=KNOWN_EXPECTED[name];payloads=[x for x in r['target_payload_values'] if x is not None];ids=r['local_numeric_values'].get('0x100',[]);po=contains_subsequence(payloads,exp['target_subsequence']);io=exp['identity_candidate'] in ids;out.append({'name':name,'candidate_ordinal':r['candidate_ordinal'],'segment_index':r['segment_index'],'payloads':payloads,'expected_subsequence':exp['target_subsequence'],'payload_ok':po,'identity_values_0x100':ids,'expected_identity_candidate':exp['identity_candidate'],'identity_ok':io,'overall_ok':po and io})
    return out
def load_cache(path):return load_json(path,{'version':1,'exe_sha256':None,'calls':None,'preps':None,'segments':None})
def save_cache(path,h,calls,preps,segments):save_json(path,{'version':1,'exe_sha256':h,'calls':calls,'preps':preps,'segments':segments})
def write_csv(path,rows):
    fields=['candidate_ordinal','segment_index','known_name','begin_hex','end_hex','structural_target_head','fingerprint','local_0x100','local_0x1D0','target_payload_values']
    with path.open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in rows:w.writerow({'candidate_ordinal':r['candidate_ordinal'],'segment_index':r['segment_index'],'known_name':r['known_name'] or '','begin_hex':f"0x{r['begin']:X}",'end_hex':f"0x{r['end']:X}",'structural_target_head':json.dumps(r['structural_target_head'],ensure_ascii=False),'fingerprint':json.dumps(r['fingerprint'],ensure_ascii=False),'local_0x100':json.dumps(r['local_numeric_values'].get('0x100',[]),ensure_ascii=False),'local_0x1D0':json.dumps(r['local_numeric_values'].get('0x1D0',[]),ensure_ascii=False),'target_payload_values':json.dumps(r['target_payload_values'],ensure_ascii=False)})
def zip_dir(src,zip_path):
    if zip_path.exists():zip_path.unlink()
    with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED) as z:
        for p in src.rglob('*'):
            if p.is_file():z.write(p,p.relative_to(src))
def main():
    t0=time.time();ap=argparse.ArgumentParser();ap.add_argument('hero_siege_dir');args=ap.parse_args();root=Path(args.hero_siege_dir).resolve();exe=choose_exe(root);desk=desktop();out=desk/'hero_siege_master';zip_path=desk/'hero_siege_master.zip';state=desk/'hero_siege_master_state';rules_path=state/'rules.json';cache_path=state/'cache.json';history_path=state/'rules_history.jsonl';state.mkdir(parents=True,exist_ok=True)
    if out.exists():shutil.rmtree(out)
    out.mkdir(parents=True);rules=load_json(rules_path,DEFAULT_RULES);rules,migration_info=migrate_rules_to_v2(rules)
    if migration_info['changed']:save_json(rules_path,rules);append_jsonl(history_path,{'timestamp':time.strftime('%Y-%m-%d %H:%M:%S'),'event':'rules_migration','master_version':MASTER_VERSION,'migration':migration_info})
    exe_hash=sha256(exe);cache=load_cache(cache_path);pe=PE(exe);cache_hit=cache.get('exe_sha256')==exe_hash and cache.get('calls') and cache.get('preps') and cache.get('segments')
    if cache_hit:
        calls=cache['calls'];preps=cache['preps'];segments=cache['segments'];calls_by_target=defaultdict(list)
        for c in calls:calls_by_target[int(c['target'])].append(int(c['rva']))
    else:
        calls,calls_by_target=build_direct_calls(pe,FUNC_BEGIN,FUNC_END);preps,segments=build_prep_segments(calls);save_cache(cache_path,exe_hash,calls,preps,segments)
    rows=extract_primary_blocks(pe,preps,rules);survey=survey_local_discriminators(rows);consumer_analysis=analyze_field_consumers(rows);named_helper_analysis=analyze_named_helper(pe,rows);helper_body_analysis=analyze_helper_body(pe);switch_dispatch_analysis=analyze_switch_dispatcher(pe);inner_helper_analysis=analyze_function_deep(pe,FIELD_CONSUMER_INNER);tuned_rules,tune_info=auto_tune_rules(rows,rules,survey)
    if tune_info.get('changed'):
        old=deep_copy_jsonable(rules);rules=tuned_rules;save_json(rules_path,rules);append_jsonl(history_path,{'timestamp':time.strftime('%Y-%m-%d %H:%M:%S'),'exe_sha256':exe_hash,'old_rules':old,'new_rules':rules,'tune_info':tune_info})
    else:rules=tuned_rules;save_json(rules_path,rules) if not rules_path.exists() else None
    final_collisions=apply_fingerprints(rows,rules);validation=validate_known(rows);helper_counts={'all_direct_calls':len(calls),'prep_calls':len(calls_by_target.get(PREP,[])),'target_calls':len(calls_by_target.get(TARGET,[])),'item_helper_calls':len(calls_by_target.get(ITEM_HELPER,[])),'value_helper_calls':len(calls_by_target.get(VALUE_HELPER,[])),'cleanup_calls':len(calls_by_target.get(CLEANUP,[]))};id_groups=defaultdict(list);missing_100=[]
    for r in rows:
        vals=r['local_numeric_values'].get('0x100',[])
        if not vals:missing_100.append(r['candidate_ordinal'])
        for v in set(vals):id_groups[v].append(r['candidate_ordinal'])
    duplicate_100=[{'value':v,'ordinals':ords} for v,ords in id_groups.items() if len(ords)>1];canonical_records=[];canonical_groups=defaultdict(list)
    for r in rows:
        seq=r['local_numeric_values'].get('0x1D0',[]);canonical_groups[tuple(seq)].append(r['candidate_ordinal']);canonical_records.append({'candidate_ordinal':r['candidate_ordinal'],'segment_index':r['segment_index'],'known_name':r['known_name'],'rbp_0x1D0_sequence':seq,'family_candidate':seq[0] if len(seq)>0 else None,'middle_candidate':seq[1] if len(seq)>1 else None,'third_candidate':seq[2] if len(seq)>2 else None,'aux_identity_0x100':r['local_numeric_values'].get('0x100',[]),'begin':r['begin'],'end':r['end']})
    canonical_collisions=[{'sequence':list(seq),'ordinals':ords} for seq,ords in canonical_groups.items() if len(ords)>1];elapsed=time.time()-t0
    summary={'master_version':MASTER_VERSION,'elapsed_seconds':elapsed,'exe':str(exe),'exe_sha256':exe_hash,'cache_hit':bool(cache_hit),'helper_counts':helper_counts,'prep_segment_count':len(segments),'primary_candidate_count':len(rows),'rules':rules,'rules_migration':migration_info,'auto_tune':tune_info,'known_validation':validation,'canonical_rbp_0x1D0':{'coverage':sum(1 for r in rows if r['local_numeric_values'].get('0x1D0')),'distinct_signatures':len(canonical_groups),'collision_count':len(canonical_collisions),'collisions':canonical_collisions},'identity_0x100':{'missing_ordinals':missing_100,'duplicate_groups':duplicate_100},'fingerprint_collision_count':len(final_collisions),'fingerprint_collisions':final_collisions,'best_local_discriminator_candidates':survey[:30],'named_helper_analysis_summary':{'target_hex':named_helper_analysis['target_hex'],'total_calls':named_helper_analysis['total_calls'],'arg_shape_frequency':named_helper_analysis['arg_shape_frequency'][:20]},'consumer_helper_body_summary':{'bounds_found':helper_body_analysis.get('bounds_found'),'function':helper_body_analysis.get('function'),'direct_call_frequency':helper_body_analysis.get('direct_call_frequency',[])[:30],'rip_ref_count':len(helper_body_analysis.get('rip_refs',[]))},'switch_dispatch_summary':{'jump_table':switch_dispatch_analysis.get('jump_table'),'case_target_frequency':switch_dispatch_analysis.get('case_target_frequency',[])},'inner_helper_summary':{'rva_hex':inner_helper_analysis.get('rva_hex'),'function':inner_helper_analysis.get('function'),'direct_call_frequency':inner_helper_analysis.get('direct_call_frequency',[])[:30],'tail_jump_frequency':inner_helper_analysis.get('tail_jump_frequency',[])[:30],'rip_ref_count':len(inner_helper_analysis.get('rip_refs',[]))}}
    save_json(out/'master_summary.json',summary);save_json(out/'primary_blocks.json',rows);save_json(out/'known_validation.json',validation);save_json(out/'local_discriminator_survey.json',survey);save_json(out/'fingerprint_collisions.json',final_collisions);save_json(out/'active_rules.json',rules);save_json(out/'auto_tune_result.json',tune_info);save_json(out/'canonical_records.json',canonical_records);save_json(out/'canonical_record_collisions.json',canonical_collisions);save_json(out/'field_consumer_analysis.json',consumer_analysis);save_json(out/'consumer_helper_0xC566890.json',named_helper_analysis);save_json(out/'consumer_helper_0xC566890_body.json',helper_body_analysis);save_json(out/'consumer_helper_0xC566890_switch.json',switch_dispatch_analysis);save_json(out/'consumer_inner_0xC534390.json',inner_helper_analysis);write_csv(out/'primary_blocks.csv',rows)
    diag=[f'Hero Siege Master {MASTER_VERSION}',f'Runtime: {elapsed:.2f} sec',f'Cache hit: {bool(cache_hit)}',f'Primary blocks: {len(rows)}',f'Canonical 0x1D0: {len(canonical_groups)} distinct / {len(canonical_collisions)} collisions',f"0xC566890 function: {helper_body_analysis.get('function')}",f"0xC566890 direct calls: {helper_body_analysis.get('direct_call_frequency',[])}",f"switch table: {switch_dispatch_analysis.get('jump_table')}",f"switch cases: {switch_dispatch_analysis.get('case_target_frequency',[])}",f"0xC534390 function: {inner_helper_analysis.get('function')}",f"0xC534390 calls: {inner_helper_analysis.get('direct_call_frequency',[])[:20]}",f"0xC534390 tails: {inner_helper_analysis.get('tail_jump_frequency',[])[:20]}",'Validation:']+[f"  {v['name']}: {'OK' if v['overall_ok'] else 'CHECK'}" for v in validation]
    (out/'diagnostics.txt').write_text('\n'.join(diag),encoding='utf-8');zip_dir(out,zip_path);print('\n'.join(diag));print('ZIP:',zip_path)
if __name__=='__main__':main()
