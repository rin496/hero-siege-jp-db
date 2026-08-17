#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hero Siege permanent master scanner.

Run directly or via tools/run_master.bat.
Game files are read-only. Output is written to Desktop/hero_siege_master and
Desktop/hero_siege_master.zip. Persistent state is kept in
Desktop/hero_siege_master_state.
"""
from pathlib import Path
from collections import defaultdict
import argparse,csv,hashlib,json,math,shutil,struct,time,zipfile

VERSION="permanent-master-v2-github"
FUNC_BEGIN=0x05856C00; FUNC_END=0x0588E599
PREP=0x0C54E830; TARGET=0x0C579810; ITEM_HELPER=0x058A48A0
VALUE_HELPER=0x56710; CLEANUP=0x56560
PRIMARY=list(range(2,71,2))
KNOWN={8:"Godfather",20:"Thor",40:"Genji"}
EXPECT={"Godfather":([13315,1424,11],1855),"Thor":([8860,1424,83],16155),"Genji":([8866,1424,78],29455)}
REG=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"]

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]
def s32(b,o): return struct.unpack_from('<i',b,o)[0]
def desktop():
    for p in (Path.home()/"Desktop",Path.home()/"OneDrive"/"Desktop"):
        if p.exists(): return p
    return Path.cwd()
def sha256(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1<<20),b''): h.update(c)
    return h.hexdigest()
def fd(q):
    try:
        x=struct.unpack('<d',struct.pack('<Q',q))[0]
        if not math.isfinite(x) or abs(x)>1e12:return None
        return int(round(x)) if abs(x-round(x))<1e-10 else x
    except:return None
def uniq(xs):
    out=[]
    for x in xs:
        if x not in out: out.append(x)
    return out
def subseq(seq,sub):
    j=0
    for x in seq:
        if j<len(sub) and x==sub[j]: j+=1
    return j==len(sub)

def choose(root):
    for p in (root/'Hero_Siege.exe',root/'bin'/'Hero_Siege.exe'):
        if p.exists(): return p
    xs=list(root.rglob('Hero_Siege.exe'))
    if not xs: raise SystemExit('Hero_Siege.exe not found')
    return xs[0]

class PE:
    def __init__(self,p):
        self.p=p; self.d=p.read_bytes(); self.s=[]
        pe=u32(self.d,0x3c); coff=pe+4; n=u16(self.d,coff+2); osz=u16(self.d,coff+16); sec=coff+20+osz
        for i in range(n):
            o=sec+i*40; self.s.append((u32(self.d,o+12),u32(self.d,o+8),u32(self.d,o+16),u32(self.d,o+20)))
    def off(self,r):
        for va,vs,rs,rp in self.s:
            if va<=r<va+max(vs,rs) and r-va<rs:return rp+r-va
    def get(self,a,b):
        o=self.off(a); return b'' if o is None else self.d[o:o+b-a]

def calls(pe):
    b=pe.get(FUNC_BEGIN,FUNC_END); out=[]; by=defaultdict(list); i=0
    while i+5<=len(b):
        if b[i]==0xE8:
            r=FUNC_BEGIN+i; t=(r+5+s32(b,i+1))&0xffffffff; out.append({'rva':r,'target':t}); by[t].append(r); i+=5
        else:i+=1
    return out,by

def scan(pe,a,z):
    b=pe.get(a,z); ev=[]; imm={}; i=0
    while i<len(b):
        r=a+i
        if i+5<=len(b) and b[i]==0xE8:
            ev.append({'rva':r,'kind':'CALL','target':(r+5+s32(b,i+1))&0xffffffff}); i+=5; continue
        if i+10<=len(b) and b[i]==0x48 and 0xB8<=b[i+1]<=0xBF:
            reg=REG[b[i+1]-0xB8]; q=u64(b,i+2); e={'rva':r,'kind':'IMM','reg':reg,'qword':q,'double':fd(q)}; ev.append(e); imm[reg]=e; i+=10; continue
        if i+7<=len(b) and b[i]==0x48 and b[i+1] in (0x89,0x8B,0x8D):
            m=b[i+2]; mod=(m>>6)&3; rr=(m>>3)&7; rm=m&7
            if mod==2 and rm==5:
                reg=REG[rr]; disp=s32(b,i+3)
                if b[i+1]==0x89:
                    e={'rva':r,'kind':'STORE','disp':disp,'reg':reg}; p=imm.get(reg)
                    if p and 0<=r-p['rva']<=0x60:e['double']=p['double'];e['qword']=p['qword']
                    ev.append(e)
                elif b[i+1]==0x8B: ev.append({'rva':r,'kind':'LOAD','disp':disp,'reg':reg})
                else: ev.append({'rva':r,'kind':'LEA','disp':disp,'reg':reg})
                i+=7; continue
        i+=1
    return ev

def near(events,call,disp):
    x=[e for e in events if e['kind']=='STORE' and e.get('disp')==disp and e.get('double') is not None and e['rva']<call and call-e['rva']<=0x140]
    return x[-1]['double'] if x else None

def extract(pe,preps):
    rows=[]
    for n,si in enumerate(PRIMARY):
        a=preps[si]; z=preps[si+2] if si+2<len(preps) else FUNC_END; ev=scan(pe,a,z)
        cs=[e for e in ev if e['kind']=='CALL']; tc=[e for e in cs if e['target']==TARGET]
        nums=[e for e in ev if e['kind']=='STORE' and e.get('double') is not None]
        loc=defaultdict(list)
        for e in nums: loc[f"0x{e['disp']:X}"].append(e['double'])
        loc={k:uniq(v) for k,v in loc.items()}
        pay=[near(ev,c['rva'],0x1D0) for c in tc]
        seq=loc.get('0x1D0',[])
        rows.append({'candidate_ordinal':n,'segment_index':si,'known_name':KNOWN.get(si),'begin':a,'end':z,'target_payload_values':pay,'local_numeric_values':loc,'canonical_0x1D0':seq,'aux_0x100':loc.get('0x100',[]),'calls':len(cs),'target_calls':len(tc),'item_helper_calls':sum(c['target']==ITEM_HELPER for c in cs),'value_helper_calls':sum(c['target']==VALUE_HELPER for c in cs),'cleanup_calls':sum(c['target']==CLEANUP for c in cs)})
    return rows

def local_survey(rows):
    mp=defaultdict(dict)
    for r in rows:
        for d,v in r['local_numeric_values'].items(): mp[d][r['candidate_ordinal']]=tuple(v)
    out=[]
    for d,bm in mp.items():
        g=defaultdict(list)
        for o,v in bm.items():g[v].append(o)
        out.append({'disp':d,'coverage':len(bm),'distinct':len(g),'collisions':[{'values':list(v),'ordinals':o} for v,o in g.items() if len(o)>1]})
    return sorted(out,key=lambda x:(-x['coverage'],-x['distinct'],len(x['collisions'])))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('hero_siege_dir');a=ap.parse_args();root=Path(a.hero_siege_dir).resolve();exe=choose(root);desk=desktop();out=desk/'hero_siege_master';state=desk/'hero_siege_master_state';state.mkdir(exist_ok=True)
    if out.exists():shutil.rmtree(out)
    out.mkdir(); zpath=desk/'hero_siege_master.zip'; h=sha256(exe); cachep=state/'cache.json'; cache={}
    if cachep.exists():
        try:cache=json.loads(cachep.read_text(encoding='utf-8'))
        except:pass
    pe=PE(exe); hit=cache.get('exe_sha256')==h and cache.get('calls') and cache.get('preps')
    if hit:
        cs=cache['calls']; preps=cache['preps']; by=defaultdict(list)
        for c in cs:by[c['target']].append(c['rva'])
    else:
        cs,by=calls(pe); preps=[c['rva'] for c in cs if c['target']==PREP]; cachep.write_text(json.dumps({'exe_sha256':h,'calls':cs,'preps':preps}),encoding='utf-8')
    rows=extract(pe,preps); groups=defaultdict(list)
    for r in rows:groups[tuple(r['canonical_0x1D0'])].append(r['candidate_ordinal'])
    col=[{'sequence':list(k),'ordinals':v} for k,v in groups.items() if len(v)>1]
    val=[]
    for r in rows:
        if r['known_name']:
            sub,idv=EXPECT[r['known_name']]; p=[x for x in r['target_payload_values'] if x is not None]; ids=r['aux_0x100'];val.append({'name':r['known_name'],'payload_ok':subseq(p,sub),'identity_ok':idv in ids,'overall_ok':subseq(p,sub) and idv in ids})
    survey=local_survey(rows)
    summary={'version':VERSION,'exe':str(exe),'exe_sha256':h,'cache_hit':bool(hit),'helper_counts':{'all_direct_calls':len(cs),'prep_calls':len(by.get(PREP,[])),'target_calls':len(by.get(TARGET,[])),'item_helper_calls':len(by.get(ITEM_HELPER,[]))},'primary_candidate_count':len(rows),'canonical_0x1D0':{'coverage':sum(bool(r['canonical_0x1D0']) for r in rows),'distinct':len(groups),'collision_count':len(col),'collisions':col},'known_validation':val,'best_local_discriminators':survey[:30]}
    (out/'master_summary.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf-8');(out/'canonical_records.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False),encoding='utf-8');(out/'local_discriminator_survey.json').write_text(json.dumps(survey,indent=2,ensure_ascii=False),encoding='utf-8');(out/'canonical_record_collisions.json').write_text(json.dumps(col,indent=2,ensure_ascii=False),encoding='utf-8')
    with (out/'primary_blocks.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f);w.writerow(['ordinal','segment','known','0x1D0','0x100','TARGET'])
        for r in rows:w.writerow([r['candidate_ordinal'],r['segment_index'],r['known_name'] or '',json.dumps(r['canonical_0x1D0']),json.dumps(r['aux_0x100']),json.dumps(r['target_payload_values'])])
    diag=[f'Hero Siege Master {VERSION}',f'Cache hit: {bool(hit)}',f'Primary blocks: {len(rows)}',f'Canonical 0x1D0: {len(groups)} distinct / {len(col)} collisions','Validation:']+[f"  {v['name']}: {'OK' if v['overall_ok'] else 'CHECK'}" for v in val]
    (out/'diagnostics.txt').write_text('\n'.join(diag),encoding='utf-8')
    if zpath.exists():zpath.unlink()
    with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED) as z:
        for p in out.rglob('*'):
            if p.is_file():z.write(p,p.relative_to(out))
    print('\n'.join(diag));print('ZIP:',zpath)
if __name__=='__main__':main()
