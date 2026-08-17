#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
from collections import defaultdict,Counter
import argparse,csv,hashlib,json,math,shutil,struct,zipfile
VERSION='permanent-master-v5-github'
FB=0x05856C00;FE=0x0588E599;PREP=0x0C54E830;TARGET=0x0C579810;ITEM=0x058A48A0;VALUE=0x56710;CLEAN=0x56560;HELPER=0x0C566890
PRIMARY=list(range(2,71,2));KNOWN={8:'Godfather',20:'Thor',40:'Genji'};EXPECT={'Godfather':([13315,1424,11],1855),'Thor':([8860,1424,83],16155),'Genji':([8866,1424,78],29455)}
REG=['RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI'];XREG=['R8','R9','R10','R11','R12','R13','R14','R15']
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def s32(b,o):return struct.unpack_from('<i',b,o)[0]
def desk():
 for p in (Path.home()/'Desktop',Path.home()/'OneDrive'/'Desktop'):
  if p.exists():return p
 return Path.cwd()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()
def fd(q):
 try:
  x=struct.unpack('<d',struct.pack('<Q',q))[0]
  if not math.isfinite(x) or abs(x)>1e12:return None
  return int(round(x)) if abs(x-round(x))<1e-10 else x
 except:return None
def uniq(xs):
 o=[]
 for x in xs:
  if x not in o:o.append(x)
 return o
def subseq(seq,sub):
 j=0
 for x in seq:
  if j<len(sub) and x==sub[j]:j+=1
 return j==len(sub)
def choose(root):
 for p in (root/'Hero_Siege.exe',root/'bin'/'Hero_Siege.exe'):
  if p.exists():return p
 x=list(root.rglob('Hero_Siege.exe'))
 if not x:raise SystemExit('Hero_Siege.exe not found')
 return x[0]
class PE:
 def __init__(self,p):
  self.p=p;self.d=p.read_bytes();self.s=[];pe=u32(self.d,0x3c);co=pe+4;n=u16(self.d,co+2);osz=u16(self.d,co+16);sec=co+20+osz
  for i in range(n):
   o=sec+i*40;self.s.append({'name':self.d[o:o+8].split(b'\0',1)[0].decode('ascii','ignore'),'rva':u32(self.d,o+12),'vs':u32(self.d,o+8),'rs':u32(self.d,o+16),'rp':u32(self.d,o+20)})
 def off(self,r):
  for s in self.s:
   if s['rva']<=r<s['rva']+max(s['vs'],s['rs']) and r-s['rva']<s['rs']:return s['rp']+r-s['rva']
 def get(self,a,z):
  o=self.off(a);return b'' if o is None else self.d[o:o+z-a]
 def pdata(self,r):
  s=next((x for x in self.s if x['name']=='.pdata'),None)
  if not s:return None
  for i in range(s['rs']//12):
   o=s['rp']+i*12;b=u32(self.d,o);e=u32(self.d,o+4);w=u32(self.d,o+8)
   if b<=r<e:return {'begin':b,'end':e,'size':e-b,'unwind_rva':w,'pdata_index':i,'begin_hex':f'0x{b:X}','end_hex':f'0x{e:X}'}
def calls(pe):
 b=pe.get(FB,FE);o=[];by=defaultdict(list);i=0
 while i+5<=len(b):
  if b[i]==0xE8:
   r=FB+i;t=(r+5+s32(b,i+1))&0xffffffff;o.append({'rva':r,'target':t});by[t].append(r);i+=5
  else:i+=1
 return o,by
def scan(pe,a,z):
 b=pe.get(a,z);ev=[];imm={};i=0
 while i<len(b):
  r=a+i
  if i+5<=len(b) and b[i]==0xE8:ev.append({'rva':r,'kind':'CALL','target':(r+5+s32(b,i+1))&0xffffffff});i+=5;continue
  if i+10<=len(b) and b[i]==0x48 and 0xB8<=b[i+1]<=0xBF:
   rg=REG[b[i+1]-0xB8];q=u64(b,i+2);e={'rva':r,'kind':'IMM','reg':rg,'qword':q,'double':fd(q)};ev.append(e);imm[rg]=e;i+=10;continue
  if i+7<=len(b) and b[i]==0x48 and b[i+1] in (0x89,0x8B,0x8D):
   m=b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7
   if mod==2 and rm==5:
    rg=REG[rr];d=s32(b,i+3)
    if b[i+1]==0x89:
     e={'rva':r,'kind':'STORE','disp':d,'reg':rg};p=imm.get(rg)
     if p and 0<=r-p['rva']<=0x60:e['double']=p['double'];e['qword']=p['qword']
     ev.append(e)
    elif b[i+1]==0x8B:ev.append({'rva':r,'kind':'LOAD','disp':d,'reg':rg})
    else:ev.append({'rva':r,'kind':'LEA','disp':d,'reg':rg})
    i+=7;continue
  i+=1
 return ev
def near(ev,call,d):
 x=[e for e in ev if e['kind']=='STORE' and e.get('disp')==d and e.get('double') is not None and e['rva']<call and call-e['rva']<=0x140]
 return x[-1]['double'] if x else None
def args(pe,a,c,w=0xA0):
 b=pe.get(max(a,c-w),c);base=max(a,c-w);ev=[];i=0
 while i<len(b):
  r=base+i
  if i+10<=len(b) and b[i] in (0x48,0x49) and 0xB8<=b[i+1]<=0xBF:
   ix=b[i+1]-0xB8;rg=(XREG if b[i]&1 else REG)[ix];q=u64(b,i+2);ev.append({'rva':r,'kind':'IMM','dst':rg,'double':fd(q)});i+=10;continue
  if i+3<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x89,0x8B,0x8D):
   rx=b[i];op=b[i+1];m=b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7;rg=(XREG if rx&4 else REG)[rr];rmr=(XREG if rx&1 else REG)[rm]
   if mod==3 and op in (0x89,0x8B):
    d,s=(rmr,rg) if op==0x89 else (rg,rmr);ev.append({'rva':r,'kind':'MOV_REG','dst':d,'src':s});i+=3;continue
   if mod==2 and rm==5 and i+7<=len(b):
    d=s32(b,i+3);ev.append({'rva':r,'kind':'LOAD_RBP' if op==0x8B else 'LEA_RBP','dst':rg,'disp':d});i+=7;continue
  i+=1
 return {rg:(next((e for e in reversed(ev) if e.get('dst')==rg),None)) for rg in ('RCX','RDX','R8','R9')}
def extract(pe,preps):
 rows=[]
 for n,si in enumerate(PRIMARY):
  a=preps[si];z=preps[si+2] if si+2<len(preps) else FE;ev=scan(pe,a,z);cs=[e for e in ev if e['kind']=='CALL'];tc=[e for e in cs if e['target']==TARGET];nums=[e for e in ev if e['kind']=='STORE' and e.get('double') is not None];loc=defaultdict(list)
  for e in nums:loc[f"0x{e['disp']:X}"].append(e['double'])
  loc={k:uniq(v) for k,v in loc.items()};pay=[near(ev,c['rva'],0x1D0) for c in tc];rows.append({'candidate_ordinal':n,'segment_index':si,'known_name':KNOWN.get(si),'begin':a,'end':z,'target_payload_values':pay,'local_numeric_values':loc,'canonical_0x1D0':loc.get('0x1D0',[]),'aux_0x100':loc.get('0x100',[]),'calls':len(cs),'target_calls':len(tc),'item_helper_calls':sum(c['target']==ITEM for c in cs),'value_helper_calls':sum(c['target']==VALUE for c in cs),'cleanup_calls':sum(c['target']==CLEAN for c in cs),'helper_calls':[{'call_rva':c['rva'],'call_rva_hex':f"0x{c['rva']:X}",'args':args(pe,a,c['rva'])} for c in cs if c['target']==HELPER]})
 return rows
def helper_body(pe):
 f=pe.pdata(HELPER)
 if not f:return {'helper_hex':f'0x{HELPER:X}','bounds_found':False}
 a=f['begin'];z=f['end'];b=pe.get(a,z);cs=[];freq=Counter();refs=[];i=0
 while i<len(b):
  r=a+i
  if i+5<=len(b) and b[i]==0xE8:
   t=(r+5+s32(b,i+1))&0xffffffff;cs.append({'rva':r,'rva_hex':f'0x{r:X}','target':t,'target_hex':f'0x{t:X}'});freq[t]+=1;i+=5;continue
  if i+7<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x8B,0x8D) and (b[i+2]&0xC7)==0x05:
   t=r+7+s32(b,i+3);refs.append({'rva':r,'kind':'RIP_LEA' if b[i+1]==0x8D else 'RIP_LOAD','target':t,'target_hex':f'0x{t:X}'});i+=7;continue
  i+=1
 return {'helper_hex':f'0x{HELPER:X}','bounds_found':True,'function':f,'direct_calls':cs,'direct_call_frequency':[{'target':t,'target_hex':f'0x{t:X}','count':c} for t,c in freq.most_common()],'rip_refs':refs,'raw_prefix':b[:256].hex(' '),'raw_suffix':b[-256:].hex(' ')}
def survey(rows):
 mp=defaultdict(dict)
 for r in rows:
  for d,v in r['local_numeric_values'].items():mp[d][r['candidate_ordinal']]=tuple(v)
 o=[]
 for d,bm in mp.items():
  g=defaultdict(list)
  for x,v in bm.items():g[v].append(x)
  o.append({'disp':d,'coverage':len(bm),'distinct':len(g),'collisions':[{'values':list(v),'ordinals':x} for v,x in g.items() if len(x)>1]})
 return sorted(o,key=lambda x:(-x['coverage'],-x['distinct'],len(x['collisions'])))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('hero_siege_dir');a=ap.parse_args();root=Path(a.hero_siege_dir).resolve();exe=choose(root);d=desk();out=d/'hero_siege_master';state=d/'hero_siege_master_state';state.mkdir(exist_ok=True)
 if out.exists():shutil.rmtree(out)
 out.mkdir();zp=d/'hero_siege_master.zip';h=sha(exe);cp=state/'cache.json';cache={}
 if cp.exists():
  try:cache=json.loads(cp.read_text(encoding='utf-8'))
  except:pass
 pe=PE(exe);hit=cache.get('exe_sha256')==h and cache.get('calls') and cache.get('preps')
 if hit:
  cs=cache['calls'];preps=cache['preps'];by=defaultdict(list)
  for c in cs:by[c['target']].append(c['rva'])
 else:
  cs,by=calls(pe);preps=[c['rva'] for c in cs if c['target']==PREP];cp.write_text(json.dumps({'exe_sha256':h,'calls':cs,'preps':preps}),encoding='utf-8')
 rows=extract(pe,preps);g=defaultdict(list)
 for r in rows:g[tuple(r['canonical_0x1D0'])].append(r['candidate_ordinal'])
 col=[{'sequence':list(k),'ordinals':v} for k,v in g.items() if len(v)>1];val=[]
 for r in rows:
  if r['known_name']:
   sub,idv=EXPECT[r['known_name']];p=[x for x in r['target_payload_values'] if x is not None];val.append({'name':r['known_name'],'payload_ok':subseq(p,sub),'identity_ok':idv in r['aux_0x100'],'overall_ok':subseq(p,sub) and idv in r['aux_0x100']})
 hb=helper_body(pe);sv=survey(rows);nh={'target_hex':f'0x{HELPER:X}','total_calls':sum(len(r['helper_calls']) for r in rows),'per_block':[{'candidate_ordinal':r['candidate_ordinal'],'segment_index':r['segment_index'],'known_name':r['known_name'],'near_0x100':r['aux_0x100'],'canonical_0x1D0':r['canonical_0x1D0'],'calls':r['helper_calls']} for r in rows]}
 summary={'version':VERSION,'exe':str(exe),'exe_sha256':h,'cache_hit':bool(hit),'helper_counts':{'all_direct_calls':len(cs),'prep_calls':len(by.get(PREP,[])),'target_calls':len(by.get(TARGET,[])),'item_helper_calls':len(by.get(ITEM,[]))},'primary_candidate_count':len(rows),'canonical_0x1D0':{'coverage':sum(bool(r['canonical_0x1D0']) for r in rows),'distinct':len(g),'collision_count':len(col),'collisions':col},'known_validation':val,'consumer_helper':{'total_calls':nh['total_calls'],'function':hb.get('function'),'direct_call_frequency':hb.get('direct_call_frequency',[]),'rip_ref_count':len(hb.get('rip_refs',[]))},'best_local_discriminators':sv[:30]}
 for fn,obj in [('master_summary.json',summary),('canonical_records.json',rows),('consumer_helper_0xC566890.json',nh),('consumer_helper_0xC566890_body.json',hb),('local_discriminator_survey.json',sv),('canonical_record_collisions.json',col)]: (out/fn).write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')
 with (out/'primary_blocks.csv').open('w',newline='',encoding='utf-8-sig') as f:
  w=csv.writer(f);w.writerow(['ordinal','segment','known','0x1D0','0x100','TARGET']);[w.writerow([r['candidate_ordinal'],r['segment_index'],r['known_name'] or '',json.dumps(r['canonical_0x1D0']),json.dumps(r['aux_0x100']),json.dumps(r['target_payload_values'])]) for r in rows]
 diag=[f'Hero Siege Master {VERSION}',f'Cache hit: {bool(hit)}',f'Primary blocks: {len(rows)}',f'Canonical 0x1D0: {len(g)} distinct / {len(col)} collisions',f'0xC566890 calls: {nh["total_calls"]}',f'0xC566890 function: {hb.get("function")}',f'0xC566890 direct calls: {hb.get("direct_call_frequency",[])[:12]}','Validation:']+[f"  {v['name']}: {'OK' if v['overall_ok'] else 'CHECK'}" for v in val];(out/'diagnostics.txt').write_text('\n'.join(diag),encoding='utf-8')
 if zp.exists():zp.unlink()
 with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
  for p in out.rglob('*'):
   if p.is_file():z.write(p,p.relative_to(out))
 print('\n'.join(diag));print('ZIP:',zp)
if __name__=='__main__':main()
