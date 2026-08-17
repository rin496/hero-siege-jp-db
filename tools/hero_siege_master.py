#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
import argparse,csv,hashlib,json,os,shutil,struct,subprocess,time,zipfile
MASTER_VERSION='permanent-master-v25-static-repo-producer-xrefs'
EXPECTED_SHA='92e323592aeee63fcbdc80e9a1efe1ae7c0d12ced9fb3961b1843d2bf2f376f4'
JOURNAL_ROOT=0x093D9F60
KNOWN={
 'DefineItemInitialization':0x04FF54F0,'GetNormalRepoStruct':0x05012370,
 'GetUniqueRepoStruct':0x05012E80,'GetRunewordRepoStruct':0x05013990,
 'GetHeroicItem':0x05013C90,'GetItemTranslationServerData':0x05014970,'GetItemMask':0x0501A4E0}
TOKENS=['gml_Script_GetUniqueRepoStruct','gml_Script_GetNormalRepoStruct','gml_Script_GetRunewordRepoStruct','gml_Script_GetHeroicItem','gml_Script_GetItemTranslationServerData','gml_Script_GetItemMask','gml_Script_GetLootSprite','gml_Script_GetSetInformation','gml_Script_GetSetNames','gml_Script_GetSetName','gml_Script_GetItemSeed']
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def s32(b,o):return struct.unpack_from('<i',b,o)[0]
def savej(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding='utf-8')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()
def desk():
 for p in (Path.home()/'Desktop',Path.home()/'OneDrive'/'Desktop'):
  if p.exists():return p
 return Path.cwd()
def exe_at(root):
 for p in (root/'Hero_Siege.exe',root/'bin'/'Hero_Siege.exe'):
  if p.exists():return p
 xs=list(root.rglob('Hero_Siege.exe'))
 if not xs:raise SystemExit('Hero_Siege.exe not found')
 return xs[0]
class PE:
 def __init__(self,p):
  self.d=p.read_bytes();q=u32(self.d,0x3c);co=q+4;n=u16(self.d,co+2);op=co+20;sz=u16(self.d,co+16);self.base=u64(self.d,op+24);self.image=u32(self.d,op+56);self.sec=[]
  s0=op+sz
  for i in range(n):
   o=s0+i*40;self.sec.append({'name':self.d[o:o+8].split(b'\0',1)[0].decode('ascii','ignore'),'vs':u32(self.d,o+8),'rva':u32(self.d,o+12),'rs':u32(self.d,o+16),'rp':u32(self.d,o+20),'exec':bool(u32(self.d,o+36)&0x20000000)})
  ps=next(s for s in self.sec if s['name']=='.pdata');self.pdata=[]
  for i in range(ps['rs']//12):
   o=ps['rp']+i*12;self.pdata.append((u32(self.d,o),u32(self.d,o+4),u32(self.d,o+8)))
 def off(self,r):
  for s in self.sec:
   if s['rva']<=r<s['rva']+max(s['vs'],s['rs']):
    q=r-s['rva'];return s['rp']+q if q<s['rs'] else None
 def rvaoff(self,o):
  for s in self.sec:
   if s['rp']<=o<s['rp']+s['rs']:return s['rva']+o-s['rp']
 def rva(self,va):
  q=va-self.base;return q if 0<=q<self.image else None
 def get(self,a,z):
  o=self.off(a);return b'' if o is None else self.d[o:o+z-a]
 def bounds(self,r):
  for a,z,u in self.pdata:
   if a<=r<z:return {'begin':a,'end':z,'size':z-a}
 def exec(self,r):return any(s['exec'] and s['rva']<=r<s['rva']+max(s['vs'],s['rs']) for s in self.sec)
 def cstr(self,r,n=320):
  o=self.off(r)
  if o is None:return None
  b=self.d[o:o+n].split(b'\0',1)[0]
  try:s=b.decode('utf-8')
  except:return None
  return s if s and all((31<ord(c)<127) or c in '\t\r\n' for c in s) else None
def ascii_hits(pe,t):
 out=[];b=t.encode();p=0
 while 1:
  q=pe.d.find(b,p)
  if q<0:return out
  p=q+1;r=pe.rvaoff(q)
  if r is not None:out.append(r)
def regs_for_name(pe,r):
 needle=struct.pack('<Q',pe.base+r);out=[];p=0
 while 1:
  q=pe.d.find(needle,p)
  if q<0:break
  p=q+1
  if q+16>=len(pe.d):continue
  va=u64(pe.d,q+8);fr=pe.rva(va);bd=pe.bounds(fr) if fr is not None else None
  if bd and pe.exec(fr):out.append(bd['begin'])
 return sorted(set(out))
def reg_names_for_native(pe,r):
 needle=struct.pack('<Q',pe.base+r);p=0;out=[]
 while 1:
  q=pe.d.find(needle,p)
  if q<0:break
  p=q+1
  if q>=8:
   nr=pe.rva(u64(pe.d,q-8));s=pe.cstr(nr) if nr is not None else None
   if s and s.startswith('gml_'):out.append(s)
 return sorted(set(out))
def desc(pe,r):
 o=pe.off(r)
 if o is None or o+16>len(pe.d):return None
 cache=u64(pe.d,o);nr=pe.rva(u64(pe.d,o+8));name=pe.cstr(nr) if nr is not None else None
 return {'target':r,'target_hex':f'0x{r:X}','cache':cache,'cache_hex':f'0x{cache:X}','name':name} if name else None
def descriptor_table(pe):
 ks=('item','repo','unique','runeword','heroic','normal','set','loot','affix','attribute','rarity','socket','weapon','armor')
 out=[]
 for r in range(0x11990000,0x119B0000,0x10):
  x=desc(pe,r)
  if x and any(k in x['name'].lower() for k in ks):out.append(x)
 return out
def xrefs(pe,ds):
 targets={x['target']:x['name'] for x in ds};out=[]
 for s in pe.sec:
  if not s['exec']:continue
  b=pe.d[s['rp']:s['rp']+s['rs']];base=s['rva'];i=0
  while i+7<=len(b):
   cur=base+i;hit=None
   if 0x40<=b[i]<=0x4f and b[i+1] in (0x8b,0x89,0x8d) and (b[i+2]&0xc7)==5:
    t=(cur+7+s32(b,i+3))&0xffffffff;op=b[i+1];ln=7;i+=7
    if t in targets:hit=(t,'read64' if op==0x8b else ('write64' if op==0x89 else 'lea64'),b[i-ln:i])
   elif b[i] in (0x8b,0x89,0x8d) and (b[i+1]&0xc7)==5:
    t=(cur+6+s32(b,i+2))&0xffffffff;op=b[i];ln=6;i+=6
    if t in targets:hit=(t,'read32' if op==0x8b else ('write32' if op==0x89 else 'lea32'),b[i-ln:i])
   else:i+=1
   if hit:
    bd=pe.bounds(cur);out.append({'at_hex':f'0x{cur:X}','target_hex':f'0x{hit[0]:X}','descriptor_name':targets[hit[0]],'kind':hit[1],'bytes_hex':hit[2].hex(' '),'function_rva':bd['begin'] if bd else None,'function_rva_hex':f"0x{bd['begin']:X}" if bd else None})
 return out
def scan_func(pe,r):
 bd=pe.bounds(r)
 if not bd:return None
 b=pe.get(bd['begin'],bd['end']);calls=[];i=0
 while i+5<=len(b):
  if b[i]==0xe8:
   cur=bd['begin']+i;t=(cur+5+s32(b,i+1))&0xffffffff;tb=pe.bounds(t);calls.append(tb['begin'] if tb else t);i+=5
  else:i+=1
 return {'rva':bd['begin'],'size':bd['size'],'calls':calls}
def producer_report(pe,refs):
 by={}
 for x in refs:
  if x['function_rva'] is not None:by.setdefault(x['function_rva'],[]).append(x)
 rev={v:k for k,v in KNOWN.items()};out=[]
 for fr,rr in sorted(by.items()):
  f=scan_func(pe,fr)
  if not f:continue
  kc=sorted(set(rev[c] for c in f['calls'] if c in rev));names=reg_names_for_native(pe,fr)
  out.append({'function_rva_hex':f'0x{fr:X}','size':f['size'],'registered_names':names,'descriptor_names':sorted(set(x['descriptor_name'] for x in rr)),'descriptor_xref_count':len(rr),'known_item_calls':kc,'xrefs':rr})
 return out
def clip(zp):
 if os.name!='nt':return
 env=os.environ.copy();env['Z']=str(zp.resolve());ps="Add-Type -AssemblyName System.Windows.Forms;$c=New-Object System.Collections.Specialized.StringCollection;[void]$c.Add($env:Z);[System.Windows.Forms.Clipboard]::SetFileDropList($c)"
 try:
  p=subprocess.run(['powershell.exe','-NoProfile','-STA','-Command',ps],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15);print('Clipboard: ZIP file copied. Paste it directly into ChatGPT.' if p.returncode==0 else 'Clipboard copy failed.',flush=True)
 except:print('Clipboard copy failed.',flush=True)
def main():
 t=time.time();a=argparse.ArgumentParser();a.add_argument('hero_siege_dir');root=Path(a.parse_args().hero_siege_dir).resolve();ex=exe_at(root);h=sha(ex);print('EXE SHA256:',h,flush=True)
 if h!=EXPECTED_SHA:raise SystemExit('Hero_Siege.exe changed; refusing v25 anchors.')
 pe=PE(ex);d=desk();out=d/'hero_siege_master';zp=d/'hero_siege_master.zip'
 if out.exists():shutil.rmtree(out)
 out.mkdir(parents=True)
 tm=[]
 for i,tok in enumerate(TOKENS,1):
  hs=ascii_hits(pe,tok);rs=sorted(set(r for h0 in hs for r in regs_for_name(pe,h0)));tm.append({'token':tok,'hits':[f'0x{x:X}' for x in hs],'native_rvas':[f'0x{x:X}' for x in rs]});print(f'Token {i}/{len(TOKENS)} {tok}: hits={len(hs)} regs={len(rs)}',flush=True)
 print('Scanning item/repository descriptor table...',flush=True);ds=descriptor_table(pe);print('Interesting descriptors:',len(ds),flush=True)
 print('Scanning executable descriptor xrefs...',flush=True);xr=xrefs(pe,ds);print('Descriptor xrefs:',len(xr),flush=True)
 pr=producer_report(pe,xr);named=sum(bool(x['registered_names']) for x in pr);linked=sum(bool(x['known_item_calls']) for x in pr);print('Functions touching descriptors:',len(pr),flush=True);print('Functions with recovered registration names:',named,flush=True);print('Functions calling known item pipeline:',linked,flush=True)
 usage=[]
 for x in ds:
  a=[r for r in xr if r['descriptor_name']==x['name']];usage.append({'descriptor':x,'xref_count':len(a),'functions':sorted(set(r['function_rva_hex'] for r in a if r['function_rva_hex']))})
 usage.sort(key=lambda x:-x['xref_count'])
 assess={'interesting_descriptor_count':len(ds),'descriptor_xref_count':len(xr),'descriptor_user_function_count':len(pr),'named_user_function_count':named,'known_pipeline_link_count':linked,'define_item_initialization_rva_hex':'0x4FF54F0','recommended_next_step':'Prioritize named descriptor users that call DefineItemInitialization or repository getters; recover repository creation/assignment semantics statically.'}
 savej(out/'master_summary.json',{'version':MASTER_VERSION,'architecture':'static-only-no-runtime-access','exe_sha256':h,'assessment':assess});savej(out/'script_token_map.json',tm);savej(out/'item_repository_descriptors.json',ds);savej(out/'item_repository_descriptor_xrefs.json',xr);savej(out/'item_repository_descriptor_usage_summary.json',usage);savej(out/'item_repository_producer_functions.json',pr);savej(out/'strategy_assessment.json',assess)
 with (out/'item_repository_producer_functions.csv').open('w',newline='',encoding='utf-8-sig') as f:
  w=csv.DictWriter(f,fieldnames=['function_rva_hex','size','registered_names','descriptor_names','known_item_calls','descriptor_xref_count']);w.writeheader()
  for x in pr:w.writerow({'function_rva_hex':x['function_rva_hex'],'size':x['size'],'registered_names':';'.join(x['registered_names']),'descriptor_names':';'.join(x['descriptor_names']),'known_item_calls':';'.join(x['known_item_calls']),'descriptor_xref_count':x['descriptor_xref_count']})
 if zp.exists():zp.unlink()
 with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
  for p in out.rglob('*'):
   if p.is_file():z.write(p,p.relative_to(out))
 clip(zp);print('Done:',zp);print('Master:',MASTER_VERSION);print('Elapsed: %.1fs'%(time.time()-t))
if __name__=='__main__':main()
