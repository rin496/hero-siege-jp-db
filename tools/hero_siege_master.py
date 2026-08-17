#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
import argparse,csv,hashlib,json,shutil,struct,time,zipfile
from collections import Counter

MASTER_VERSION='permanent-master-v15.2-standalone-segment-survey'
PREP=0x0C54E830; SETTER=0x0C566890; TARGET=0x0C579810; SWORD=0x05856C00
EXPECTED_SHA='92e323592aeee63fcbdc80e9a1efe1ae7c0d12ced9fb3961b1843d2bf2f376f4'
BODIES={
'UniqueAmulets':0x243AD30,'UniqueBelts':0x2E51CA0,'UniqueBoots':0x32F9CA0,'UniqueCharms':0x3F8A950,
'UniqueChests':0x4EEAB10,'UniqueConsumable':0xF26A90,'UniqueFlask':0x2970A10,'UniqueGloves':0x5208700,
'UniqueHelmets':0x1F3DC0,'UniqueRings':0x3011100,'UniqueShields':0x5A31C80,'UniqueWeaponsAxe':0x108B40,
'UniqueWeaponsBook':0x583E890,'UniqueWeaponsBow':0x56F1E60,'UniqueWeaponsCane':0x51A5640,
'UniqueWeaponsChainsaw':0x2E9DDC0,'UniqueWeaponsClaw':0x19ED7B0,'UniqueWeaponsDagger':0xF9A680,
'UniqueWeaponsFlask':0xE2BB60,'UniqueWeaponsGun':0xD98E90,'UniqueWeaponsMace':0x5695440,
'UniqueWeaponsPolearm':0x2D5AFD0,'UniqueWeaponsSpellblade':0x4F930B0,'UniqueWeaponsStaff':0x3BA17E1,
'UniqueWeaponsSword':0x5856C00,'UniqueWeaponsThrowing':0x5F71D50,'UniqueWeaponsUniversal':0x3D2A4B0,
'UniqueWeaponsWand':0x58350}

def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def s32(b,o):return struct.unpack_from('<i',b,o)[0]
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
def savej(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding='utf-8')

class PE:
 def __init__(self,p):
  self.d=p.read_bytes(); pe=u32(self.d,0x3c); coff=pe+4; n=u16(self.d,coff+2); osz=u16(self.d,coff+16); sec=coff+20+osz
  self.s=[]
  for i in range(n):
   o=sec+i*40;self.s.append((self.d[o:o+8].split(b'\0',1)[0].decode('ascii','ignore'),u32(self.d,o+8),u32(self.d,o+12),u32(self.d,o+16),u32(self.d,o+20)))
  ps=next(x for x in self.s if x[0]=='.pdata');self.pdata_rows=[]
  for i in range(ps[3]//12):
   o=ps[4]+i*12;self.pdata_rows.append((u32(self.d,o),u32(self.d,o+4),u32(self.d,o+8)))
 def off(self,r):
  for _,vs,rv,rs,rp in self.s:
   if rv<=r<rv+max(vs,rs):
    q=r-rv
    if q<rs:return rp+q
 def get(self,a,z):
  o=self.off(a);return b'' if o is None else self.d[o:o+z-a]
 def bounds(self,r):
  for a,z,u in self.pdata_rows:
   if a==r:return {'begin':a,'end':z,'size':z-a,'unwind':u}
  for a,z,u in self.pdata_rows:
   if a<=r<z:return {'begin':a,'end':z,'size':z-a,'unwind':u}

def calls(pe,a,z):
 b=pe.get(a,z);out=[];i=0
 while i+5<=len(b):
  if b[i]==0xE8:
   r=a+i;out.append((r,(r+5+s32(b,i+1))&0xffffffff));i+=5
  else:i+=1
 return out

def segs(pe,bd):
 cs=calls(pe,bd['begin'],bd['end']);pre=[a for a,t in cs if t==PREP];rows=[]
 for i,a in enumerate(pre):
  z=pre[i+1] if i+1<len(pre) else bd['end']; cc=[(x,t) for x,t in cs if a<=x<z]; c=Counter(t for _,t in cc)
  rows.append({'segment_index':i,'begin_hex':f'0x{a:X}','end_hex':f'0x{z:X}','size':z-a,'call_count':len(cc),'target':c[TARGET],'setter':c[SETTER],'prep':c[PREP]})
 return cs,rows

def profile(rows):
 out=[]
 for parity in (0,1):
  xs=[r for r in rows if r['segment_index']%2==parity];c=Counter((r['target'],r['setter'],r['call_count']) for r in xs)
  out.append({'parity':parity,'count':len(xs),'top_signatures':[{'signature':list(k),'count':v} for k,v in c.most_common(12)]})
 return out

def main():
 t=time.time();ap=argparse.ArgumentParser();ap.add_argument('hero_siege_dir');root=Path(ap.parse_args().hero_siege_dir).resolve();exe=exe_at(root)
 h=sha(exe);print('EXE SHA256:',h,flush=True)
 if h!=EXPECTED_SHA:raise SystemExit('Hero_Siege.exe changed; refusing validated v14.2 body map.')
 pe=PE(exe);d=desk();out=d/'hero_siege_master';zp=d/'hero_siege_master.zip'
 if out.exists():shutil.rmtree(out)
 out.mkdir(parents=True);allr=[];sur=[];summ=[];names=sorted(BODIES)
 print('Validated Unique bodies:',len(names),flush=True)
 for i,n in enumerate(names,1):
  r=BODIES[n];bd=pe.bounds(r)
  if not bd or bd['begin']!=r:raise SystemExit(f'body boundary mismatch {n} 0x{r:X}')
  print(f'Survey start: {i}/{len(names)} {n} 0x{r:X}',flush=True)
  cs,rows=segs(pe,bd);c=Counter(t for _,t in cs)
  rec={'name':n,'body_rva_hex':f'0x{r:X}','body_size':bd['size'],'prep':c[PREP],'setter':c[SETTER],'target':c[TARGET],'direct_calls':len(cs),'segment_count':len(rows)}
  summ.append(rec);sur.append({**rec,'parity_profiles':profile(rows)})
  for x in rows:allr.append({'name':n,'body_rva_hex':f'0x{r:X}',**x})
  print(f'Survey done: {i}/{len(names)} segments={len(rows)} prep={c[PREP]}',flush=True)
 sword_ok=BODIES['UniqueWeaponsSword']==SWORD
 summary={'version':MASTER_VERSION,'architecture':'standalone-no-wrapper','resolver_mode':'validated-v14.2-body-map','exe_sha256':h,'unique_body_count':len(summ),'sword_body_regression':sword_ok,'bodies':summ,'design_status':'segment survey only; no segment is yet promoted to an item record'}
 savej(out/'master_summary.json',summary);savej(out/'unique_segment_survey.json',sur);savej(out/'all_unique_segments.json',allr)
 with (out/'unique_function_bodies.csv').open('w',newline='',encoding='utf-8-sig') as f:
  w=csv.DictWriter(f,fieldnames=list(summ[0]));w.writeheader();w.writerows(summ)
 with (out/'all_unique_segments.csv').open('w',newline='',encoding='utf-8-sig') as f:
  cols=['name','body_rva_hex','segment_index','begin_hex','end_hex','size','call_count','target','setter','prep'];w=csv.DictWriter(f,fieldnames=cols);w.writeheader();w.writerows(allr)
 if zp.exists():zp.unlink()
 with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
  for p in out.rglob('*'):
   if p.is_file():z.write(p,p.relative_to(out))
 print('Done:',zp);print('Master:',MASTER_VERSION);print('Sword body regression:',sword_ok);print('Elapsed: %.1fs'%(time.time()-t))
if __name__=='__main__':main()
