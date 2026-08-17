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
MASTER_VERSION="permanent-master-v4-github"
FUNC_BEGIN=0x05856C00;FUNC_END=0x0588E599;DEFINE_INIT=0x04FF54F0
PREP=0x0C54E830;TARGET=0x0C579810;ITEM_HELPER=0x058A48A0;VALUE_HELPER=0x56710;CLEANUP=0x56560;FIELD_CONSUMER_HELPER=0x0C566890
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
def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
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
    if not sub:return True
    j=0
    for x in seq:
        if x==sub[j]:
            j+=1
            if j==len(sub):return True
    return False
def load_json(path,default):
    if not path.exists():return json.loads(json.dumps(default))
    try:return json.loads(path.read_text(encoding='utf-8'))
    except:return json.loads(json.dumps(default))
def save_json(path,obj):path.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')
class PE:
    def __init__(self,path):
        self.path=path;self.data=path.read_bytes();self.sections=[];d=self.data;pe=u32(d,0x3C);coff=pe+4;n=u16(d,coff+2);osz=u16(d,coff+16);sec=coff+20+osz
        for i in range(n):
            o=sec+i*40;self.sections.append((u32(d,o+12),u32(d,o+8),u32(d,o+16),u32(d,o+20)))
    def off(self,r):
        for va,vs,rs,rp in self.sections:
            if va<=r<va+max(vs,rs) and r-va<rs:return rp+r-va
    def get(self,a,b):
        o=self.off(a);return b'' if o is None else self.data[o:o+b-a]
def choose_exe(root):
    for p in (root/'Hero_Siege.exe',root/'bin'/'Hero_Siege.exe'):
        if p.exists():return p
    xs=list(root.rglob('Hero_Siege.exe'))
    if not xs:raise SystemExit('Hero_Siege.exe not found')
    return xs[0]
def build_direct_calls(pe,begin,end):
    b=pe.get(begin,end);calls=[];by=defaultdict(list);i=0
    while i+5<=len(b):
        if b[i]==0xE8:
            r=begin+i;t=(r+5+s32(b,i+1))&0xffffffff;calls.append({'rva':r,'target':t});by[t].append(r);i+=5
        else:i+=1
    return calls,by
def scan_block(pe,begin,end):
    b=pe.get(begin,end);events=[];imm={};i=0
    while i<len(b):
        r=begin+i
        if i+5<=len(b) and b[i]==0xE8:events.append({'rva':r,'kind':'CALL','target':(r+5+s32(b,i+1))&0xffffffff});i+=5;continue
        if i+10<=len(b) and b[i]==0x48 and 0xB8<=b[i+1]<=0xBF:
            reg=REG[b[i+1]-0xB8];q=u64(b,i+2);e={'rva':r,'kind':'IMM','reg':reg,'double':finite_double(q),'qword':q};events.append(e);imm[reg]=e;i+=10;continue
        if i+7<=len(b) and b[i]==0x48 and b[i+1] in (0x89,0x8B,0x8D):
            m=b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7
            if mod==2 and rm==5:
                reg=REG[rr];disp=s32(b,i+3)
                if b[i+1]==0x89:
                    e={'rva':r,'kind':'STORE','disp':disp,'reg':reg};p=imm.get(reg)
                    if p and 0<=r-p['rva']<=0x60:e['double']=p['double'];e['qword']=p['qword']
                    events.append(e)
                elif b[i+1]==0x8B:events.append({'rva':r,'kind':'LOAD','disp':disp,'reg':reg})
                else:events.append({'rva':r,'kind':'LEA','disp':disp,'reg':reg})
                i+=7;continue
        i+=1
    return events
def near(events,call,disp):
    x=[e for e in events if e['kind']=='STORE' and e.get('disp')==disp and e.get('double') is not None and e['rva']<call and call-e['rva']<=0x140]
    return x[-1]['double'] if x else None
def extract(pe,preps):
    rows=[]
    for n,si in enumerate(PRIMARY_SEGMENTS):
        a=preps[si];z=preps[si+2] if si+2<len(preps) else FUNC_END;ev=scan_block(pe,a,z);cs=[e for e in ev if e['kind']=='CALL'];tc=[e for e in cs if e['target']==TARGET];nums=[e for e in ev if e['kind']=='STORE' and e.get('double') is not None];loc=defaultdict(list)
        for e in nums:loc[f"0x{e['disp']:X}"].append(e['double'])
        loc={k:uniq_order(v) for k,v in loc.items()};pay=[near(ev,c['rva'],0x1D0) for c in tc]
        life={}
        for field in ('0x100','0x1D0'):
            d=int(field,16);arr=[]
            for e in ev:
                if e.get('disp')==d and e['kind'] in ('STORE','LOAD','LEA'):
                    after=[c for c in cs if c['rva']>e['rva'] and c['rva']-e['rva']<=0x120][:4];arr.append({'kind':e['kind'],'event_rva':e['rva'],'value':e.get('double'),'after_targets':[c['target'] for c in after],'after_targets_hex':[f"0x{c['target']:X}" for c in after]})
            life[field]=arr
        rows.append({'candidate_ordinal':n,'segment_index':si,'known_name':KNOWN_SEGMENTS.get(si),'begin':a,'end':z,'target_payload_values':pay,'local_numeric_values':loc,'canonical_0x1D0':loc.get('0x1D0',[]),'aux_0x100':loc.get('0x100',[]),'identity_lifecycle':life,'calls':len(cs),'target_calls':len(tc),'item_helper_calls':sum(c['target']==ITEM_HELPER for c in cs),'value_helper_calls':sum(c['target']==VALUE_HELPER for c in cs),'cleanup_calls':sum(c['target']==CLEANUP for c in cs)})
    return rows
def trace_call_args_raw(pe,begin,call_rva,window=0xA0):
    a=max(begin,call_rva-window);b=pe.get(a,call_rva);events=[];i=0;base=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"];ext=["R8","R9","R10","R11","R12","R13","R14","R15"]
    while i<len(b):
        r=a+i
        if i+10<=len(b) and b[i] in (0x48,0x49) and 0xB8<=b[i+1]<=0xBF:
            idx=b[i+1]-0xB8;reg=(ext if b[i]&1 else base)[idx];q=u64(b,i+2);events.append({'rva':r,'kind':'IMM','dst':reg,'double':finite_double(q),'qword':q});i+=10;continue
        if i+3<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x89,0x8B,0x8D):
            rex=b[i];op=b[i+1];m=b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7;reg=(ext if rex&4 else base)[rr];rmreg=(ext if rex&1 else base)[rm]
            if mod==3 and op in (0x89,0x8B):
                dst,source=(rmreg,reg) if op==0x89 else (reg,rmreg);events.append({'rva':r,'kind':'MOV_REG','dst':dst,'src':source});i+=3;continue
            if mod==2 and rm==5 and i+7<=len(b):
                disp=s32(b,i+3)
                if op==0x8B:events.append({'rva':r,'kind':'LOAD_RBP','dst':reg,'disp':disp})
                elif op==0x8D:events.append({'rva':r,'kind':'LEA_RBP','dst':reg,'disp':disp})
                i+=7;continue
        i+=1
    out={}
    for reg in ('RCX','RDX','R8','R9'):
        c=[e for e in events if e.get('dst')==reg];out[reg]=c[-1] if c else None
    return out
def analyze_named_helper(pe,rows,target=FIELD_CONSUMER_HELPER):
    per=[];freq=Counter()
    for r in rows:
        ev=scan_block(pe,r['begin'],r['end']);calls=[e for e in ev if e['kind']=='CALL' and e['target']==target];entries=[]
        for c in calls:
            args=trace_call_args_raw(pe,r['begin'],c['rva']);shape=repr(tuple(None if args[k] is None else (args[k].get('kind'),args[k].get('disp'),args[k].get('src'),args[k].get('double')) for k in ('RCX','RDX','R8','R9')));freq[shape]+=1;entries.append({'call_rva':c['rva'],'call_rva_hex':f"0x{c['rva']:X}",'args':args,'near_0x100':r['aux_0x100'],'canonical_0x1D0':r['canonical_0x1D0']})
        per.append({'candidate_ordinal':r['candidate_ordinal'],'segment_index':r['segment_index'],'known_name':r['known_name'],'calls':entries})
    return {'target':target,'target_hex':f"0x{target:X}",'total_calls':sum(len(x['calls']) for x in per),'arg_shape_frequency':[{'shape':k,'count':v} for k,v in freq.most_common()],'per_block':per}
def field_consumer(rows):
    out={}
    for field in ('0x100','0x1D0'):
        kinds=Counter();first=Counter();seqs=Counter();per=[]
        for r in rows:
            es=r['identity_lifecycle'][field]
            for e in es:
                kinds[e['kind']]+=1;seq=tuple(e['after_targets'])
                if seq:first[seq[0]]+=1;seqs[seq]+=1
            per.append({'candidate_ordinal':r['candidate_ordinal'],'known_name':r['known_name'],'values':r['local_numeric_values'].get(field,[]),'events':es})
        out[field]={'event_kind_counts':dict(kinds),'first_after_target_frequency':[{'target':t,'target_hex':f"0x{t:X}",'count':c} for t,c in first.most_common()],'after_sequence_frequency':[{'targets':list(s),'targets_hex':[f"0x{x:X}" for x in s],'count':c} for s,c in seqs.most_common()],'per_block':per}
    return out
def local_survey(rows):
    mp=defaultdict(dict)
    for r in rows:
        for d,v in r['local_numeric_values'].items():mp[d][r['candidate_ordinal']]=tuple(v)
    out=[]
    for d,bm in mp.items():
        g=defaultdict(list)
        for o,v in bm.items():g[v].append(o)
        out.append({'disp':d,'coverage':len(bm),'distinct':len(g),'collisions':[{'values':list(v),'ordinals':o} for v,o in g.items() if len(o)>1]})
    return sorted(out,key=lambda x:(-x['coverage'],-x['distinct'],len(x['collisions'])))
def main():
    ap=argparse.ArgumentParser();ap.add_argument('hero_siege_dir');a=ap.parse_args();root=Path(a.hero_siege_dir).resolve();exe=choose_exe(root);desk=desktop();out=desk/'hero_siege_master';state=desk/'hero_siege_master_state';state.mkdir(exist_ok=True)
    if out.exists():shutil.rmtree(out)
    out.mkdir();zpath=desk/'hero_siege_master.zip';h=sha256(exe);cachep=state/'cache.json';cache={}
    if cachep.exists():
        try:cache=json.loads(cachep.read_text(encoding='utf-8'))
        except:pass
    pe=PE(exe);hit=cache.get('exe_sha256')==h and cache.get('calls') and cache.get('preps')
    if hit:
        cs=cache['calls'];preps=cache['preps'];by=defaultdict(list)
        for c in cs:by[c['target']].append(c['rva'])
    else:
        cs,by=build_direct_calls(pe,FUNC_BEGIN,FUNC_END);preps=[c['rva'] for c in cs if c['target']==PREP];cachep.write_text(json.dumps({'exe_sha256':h,'calls':cs,'preps':preps}),encoding='utf-8')
    rows=extract(pe,preps);groups=defaultdict(list)
    for r in rows:groups[tuple(r['canonical_0x1D0'])].append(r['candidate_ordinal'])
    col=[{'sequence':list(k),'ordinals':v} for k,v in groups.items() if len(v)>1];val=[]
    for r in rows:
        if r['known_name']:
            sub,idv=KNOWN_EXPECTED[r['known_name']]['target_subsequence'],KNOWN_EXPECTED[r['known_name']]['identity_candidate'];p=[x for x in r['target_payload_values'] if x is not None];val.append({'name':r['known_name'],'payload_ok':contains_subsequence(p,sub),'identity_ok':idv in r['aux_0x100'],'overall_ok':contains_subsequence(p,sub) and idv in r['aux_0x100']})
    consumers=field_consumer(rows);named=analyze_named_helper(pe,rows);survey=local_survey(rows);summary={'version':MASTER_VERSION,'exe':str(exe),'exe_sha256':h,'cache_hit':bool(hit),'helper_counts':{'all_direct_calls':len(cs),'prep_calls':len(by.get(PREP,[])),'target_calls':len(by.get(TARGET,[])),'item_helper_calls':len(by.get(ITEM_HELPER,[]))},'primary_candidate_count':len(rows),'canonical_0x1D0':{'coverage':sum(bool(r['canonical_0x1D0']) for r in rows),'distinct':len(groups),'collision_count':len(col),'collisions':col},'known_validation':val,'best_local_discriminators':survey[:30],'field_consumer_summary':{k:{'event_kind_counts':v['event_kind_counts'],'first_after_target_frequency':v['first_after_target_frequency'][:20],'after_sequence_frequency':v['after_sequence_frequency'][:20]} for k,v in consumers.items()},'named_helper_analysis_summary':{'target_hex':named['target_hex'],'total_calls':named['total_calls'],'arg_shape_frequency':named['arg_shape_frequency'][:20]}}
    save_json(out/'master_summary.json',summary);save_json(out/'canonical_records.json',rows);save_json(out/'field_consumer_analysis.json',consumers);save_json(out/'consumer_helper_0xC566890.json',named);save_json(out/'local_discriminator_survey.json',survey);save_json(out/'canonical_record_collisions.json',col)
    with (out/'primary_blocks.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f);w.writerow(['ordinal','segment','known','0x1D0','0x100','TARGET'])
        for r in rows:w.writerow([r['candidate_ordinal'],r['segment_index'],r['known_name'] or '',json.dumps(r['canonical_0x1D0']),json.dumps(r['aux_0x100']),json.dumps(r['target_payload_values'])])
    diag=[f'Hero Siege Master {MASTER_VERSION}',f'Cache hit: {bool(hit)}',f'Primary blocks: {len(rows)}',f'Canonical 0x1D0: {len(groups)} distinct / {len(col)} collisions',f'0xC566890 calls: {named["total_calls"]}','Validation:']+[f"  {v['name']}: {'OK' if v['overall_ok'] else 'CHECK'}" for v in val];(out/'diagnostics.txt').write_text('\n'.join(diag),encoding='utf-8')
    if zpath.exists():zpath.unlink()
    with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED) as z:
        for p in out.rglob('*'):
            if p.is_file():z.write(p,p.relative_to(out))
    print('\n'.join(diag));print('ZIP:',zpath)
if __name__=='__main__':main()
