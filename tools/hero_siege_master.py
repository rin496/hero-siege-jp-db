#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hero Siege Standalone Journal -> Repo Consumer Scanner
======================================================
Focused follow-up to v16. Targets the actual Journal-side symbol spelling
(gml_Script_*) observed in native Journal functions, especially GetUniqueRepoStruct.

Static analysis only. No runtime injection.
"""
from pathlib import Path
import argparse,csv,hashlib,json,re,shutil,struct,time,zipfile
from collections import Counter,deque

MASTER_VERSION="permanent-master-v17-journal-repo-consumer"
EXPECTED_SHA="92e323592aeee63fcbdc80e9a1efe1ae7c0d12ced9fb3961b1843d2bf2f376f4"
JOURNAL_ROOT=0x093D9F60
KNOWN_REPO_CONSUMER=0x05012E80

TOKENS=[
 "gml_Script_GetUniqueRepoStruct",
 "gml_Script_GetNormalRepoStruct",
 "gml_Script_GetRunewordRepoStruct",
 "gml_Script_GetHeroicItem",
 "gml_Script_GetItemTranslationServerData",
 "gml_Script_GetItemMask",
 "gml_Script_GetLootSprite",
 "gml_Script_GetSetInformation",
 "gml_Script_GetSetNames",
 "gml_Script_GetSetName",
 "gml_Script_GetItemSeed",
]

def u16(b,o):return struct.unpack_from("<H",b,o)[0]
def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def u64(b,o):return struct.unpack_from("<Q",b,o)[0]
def s32(b,o):return struct.unpack_from("<i",b,o)[0]

def sha256(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for c in iter(lambda:f.read(1<<20),b""):h.update(c)
 return h.hexdigest()

def desktop():
 for p in (Path.home()/"Desktop",Path.home()/"OneDrive"/"Desktop"):
  if p.exists():return p
 return Path.cwd()

def choose_exe(root):
 for p in (root/"Hero_Siege.exe",root/"bin"/"Hero_Siege.exe",root/"Hero Siege.exe",root/"bin"/"Hero Siege.exe"):
  if p.exists():return p
 xs=list(root.rglob("Hero_Siege.exe"))
 if not xs:raise SystemExit("Hero_Siege.exe not found")
 return xs[0]

def savej(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding="utf-8")

class PE:
 def __init__(self,p):
  self.data=p.read_bytes();self.sections=[];self._parse()
 def _parse(self):
  d=self.data;pe=u32(d,0x3c);coff=pe+4;n=u16(d,coff+2);osz=u16(d,coff+16);opt=coff+20
  self.image_base=u64(d,opt+24);self.size_image=u32(d,opt+56);sec=opt+osz
  for i in range(n):
   o=sec+i*40
   self.sections.append({"name":d[o:o+8].split(b"\0",1)[0].decode("ascii","ignore"),
    "vs":u32(d,o+8),"rva":u32(d,o+12),"rs":u32(d,o+16),"rp":u32(d,o+20),
    "exec":bool(u32(d,o+36)&0x20000000)})
  ps=next(x for x in self.sections if x["name"]==".pdata");self.pdata=[]
  for i in range(ps["rs"]//12):
   o=ps["rp"]+i*12;self.pdata.append((u32(d,o),u32(d,o+4),u32(d,o+8)))
 def off(self,r):
  for s in self.sections:
   if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):
    q=r-s["rva"]
    if q<s["rs"]:return s["rp"]+q
 def rva_from_off(self,o):
  for s in self.sections:
   if s["rp"]<=o<s["rp"]+s["rs"]:return s["rva"]+(o-s["rp"])
 def va_to_rva(self,v):
  r=v-self.image_base
  return r if 0<=r<self.size_image else None
 def get(self,a,z):
  o=self.off(a);return b"" if o is None else self.data[o:o+z-a]
 def executable(self,r):
  return any(s["exec"] and s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]) for s in self.sections)
 def bounds(self,r):
  for a,z,u in self.pdata:
   if a<=r<z:return {"begin":a,"end":z,"size":z-a,"unwind":u}
 def section(self,r):
  for s in self.sections:
   if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):return s["name"]
 def cstr(self,r,n=220):
  o=self.off(r)
  if o is None:return None
  raw=self.data[o:o+n];q=raw.find(b"\0")
  if q>=0:raw=raw[:q]
  if not raw:return None
  try:s=raw.decode("utf-8")
  except:return None
  if not all((31<ord(c)<127) or c in "\t\r\n" for c in s):return None
  return s

def find_ascii(pe,text):
 needle=text.encode("ascii");out=[];pos=0
 while True:
  o=pe.data.find(needle,pos)
  if o<0:break
  pos=o+1;r=pe.rva_from_off(o)
  if r is not None:out.append({"rva":r,"rva_hex":f"0x{r:X}","off":o})
 return out

def registrations(pe,hit):
 needle=struct.pack("<Q",pe.image_base+hit["rva"]);d=pe.data;out=[];pos=0
 while True:
  q=d.find(needle,pos)
  if q<0:break
  pos=q+1
  if q+24>len(d):continue
  fv=u64(d,q+8);fr=pe.va_to_rva(fv)
  if fr is not None and pe.executable(fr) and pe.bounds(fr):
   out.append({"registration_off":q,"native_rva":pe.bounds(fr)["begin"],
               "native_rva_hex":f"0x{pe.bounds(fr)['begin']:X}","metadata_va":u64(d,q+16)})
 u={}
 for x in out:u[x["native_rva"]]=x
 return list(u.values())

def scan_function(pe,r):
 bd=pe.bounds(r)
 if not bd:return None
 a,z=bd["begin"],bd["end"];b=pe.get(a,z);calls=[];refs=[];strings=[];i=0
 while i<len(b):
  cur=a+i
  if i+5<=len(b) and b[i]==0xE8:
   t=(cur+5+s32(b,i+1))&0xffffffff
   calls.append({"at":cur,"at_hex":f"0x{cur:X}","target":t,"target_hex":f"0x{t:X}","exec":pe.executable(t)})
   i+=5;continue
  if i+6<=len(b) and b[i] in (0x8B,0x8D) and (b[i+1]&0xC7)==0x05:
   t=(cur+6+s32(b,i+2))&0xffffffff
   rec={"at":cur,"at_hex":f"0x{cur:X}","kind":"mov32" if b[i]==0x8B else "lea32",
        "target":t,"target_hex":f"0x{t:X}","section":pe.section(t)}
   refs.append(rec);s=pe.cstr(t)
   if s:strings.append({**rec,"text":s})
   i+=6;continue
  if i+7<=len(b) and 0x40<=b[i]<=0x4f and b[i+1] in (0x8B,0x8D) and (b[i+2]&0xC7)==0x05:
   t=(cur+7+s32(b,i+3))&0xffffffff
   rec={"at":cur,"at_hex":f"0x{cur:X}","kind":"mov64" if b[i+1]==0x8B else "lea64",
        "target":t,"target_hex":f"0x{t:X}","section":pe.section(t)}
   refs.append(rec);s=pe.cstr(t)
   if s:strings.append({**rec,"text":s})
   i+=7;continue
  i+=1
 ur={};us={}
 for x in refs:ur[(x["kind"],x["target"])]=x
 for x in strings:us[(x["target"],x["text"])]=x
 return {"rva":bd["begin"],"rva_hex":f"0x{bd['begin']:X}","end":bd["end"],"end_hex":f"0x{bd['end']:X}",
         "size":bd["size"],"calls":calls,"rip_refs":list(ur.values()),"string_refs":list(us.values())}

def graph(pe,start,depth=2,max_nodes=80):
 q=deque([(start,0,[start])]);seen=set();out=[]
 while q and len(out)<max_nodes:
  r,d,path=q.popleft();bd=pe.bounds(r)
  if not bd:continue
  r=bd["begin"]
  if r in seen:continue
  seen.add(r);n=scan_function(pe,r)
  if not n:continue
  out.append({"depth":d,"path":[f"0x{x:X}" for x in path],**n})
  if d>=depth:continue
  for c in n["calls"]:
   if c["exec"] and pe.bounds(c["target"]):
    q.append((pe.bounds(c["target"])["begin"],d+1,path+[pe.bounds(c["target"])["begin"]]))
 return out

def callers_of(pe,target):
 out=[]
 for a,z,u in pe.pdata:
  b=pe.get(a,z);i=0;hits=[]
  while i+5<=len(b):
   if b[i]==0xE8:
    r=a+i;t=(r+5+s32(b,i+1))&0xffffffff
    if t==target:hits.append(r)
    i+=5
   else:i+=1
  if hits:out.append({"caller_rva":a,"caller_rva_hex":f"0x{a:X}","size":z-a,
                      "call_sites":[f"0x{x:X}" for x in hits]})
 return out

def main():
 t0=time.time();ap=argparse.ArgumentParser();ap.add_argument("hero_siege_dir");args=ap.parse_args()
 exe=choose_exe(Path(args.hero_siege_dir).resolve());h=sha256(exe)
 print("EXE SHA256:",h,flush=True)
 if h!=EXPECTED_SHA:raise SystemExit("Hero_Siege.exe changed; refusing v17 anchor assumptions.")
 pe=PE(exe);d=desktop();out=d/"hero_siege_master";zp=d/"hero_siege_master.zip"
 if out.exists():shutil.rmtree(out)
 out.mkdir(parents=True)

 token_rows=[]
 for i,tok in enumerate(TOKENS,1):
  hs=find_ascii(pe,tok);regs=[]
  for h0 in hs:regs.extend(registrations(pe,h0))
  uq={x["native_rva"]:x for x in regs};regs=list(uq.values())
  token_rows.append({"token":tok,"hits":hs,"registrations":regs})
  print(f"Token {i}/{len(TOKENS)} {tok}: hits={len(hs)} regs={len(regs)}",flush=True)

 print(f"Scanning Journal root 0x{JOURNAL_ROOT:X}",flush=True)
 jgraph=graph(pe,JOURNAL_ROOT,depth=2,max_nodes=120)
 repo_nodes=[]
 for n in jgraph:
  if any(s["text"]=="gml_Script_GetUniqueRepoStruct" for s in n["string_refs"]):
   repo_nodes.append(n)

 print(f"Known repo consumer 0x{KNOWN_REPO_CONSUMER:X}",flush=True)
 repo=scan_function(pe,KNOWN_REPO_CONSUMER)
 repo_graph=graph(pe,KNOWN_REPO_CONSUMER,depth=2,max_nodes=120)
 repo_callers=callers_of(pe,KNOWN_REPO_CONSUMER)

 assessment={
  "journal_root_matches_expected":bool(pe.bounds(JOURNAL_ROOT)),
  "repo_consumer_matches_expected":bool(repo and repo["rva"]==KNOWN_REPO_CONSUMER),
  "journal_nodes_referencing_get_unique_repo_struct":[n["rva_hex"] for n in repo_nodes],
  "get_unique_repo_struct_exact_token_hits":len(next(x for x in token_rows if x["token"]=="gml_Script_GetUniqueRepoStruct")["hits"]),
  "get_unique_repo_struct_registration_count":len(next(x for x in token_rows if x["token"]=="gml_Script_GetUniqueRepoStruct")["registrations"]),
  "repo_consumer_direct_call_count":len(repo["calls"]) if repo else 0,
  "repo_consumer_rip_ref_count":len(repo["rip_refs"]) if repo else 0,
  "repo_consumer_callers_count":len(repo_callers),
  "recommended_next_step":
   "Identify which RIP-loaded globals/selectors in 0x5012E80 are inputs/outputs of GetUniqueRepoStruct, then map the Journal callsite around that function. "
   "If the function only materializes a runtime struct through GameMaker variable APIs, switch to a minimal read-only runtime repository dump instead of deeper producer disassembly."
 }

 summary={"version":MASTER_VERSION,"architecture":"standalone-no-wrapper","analysis_mode":"journal-to-repository-consumer",
          "exe_sha256":h,"token_results":[{"token":x["token"],"hits":len(x["hits"]),"registrations":len(x["registrations"]),
                                          "native_rvas":[r["native_rva_hex"] for r in x["registrations"]]} for x in token_rows],
          "journal_root_rva_hex":f"0x{JOURNAL_ROOT:X}","known_repo_consumer_rva_hex":f"0x{KNOWN_REPO_CONSUMER:X}",
          "assessment":assessment}
 savej(out/"master_summary.json",summary)
 savej(out/"script_token_map.json",token_rows)
 savej(out/"journal_root_graph.json",jgraph)
 savej(out/"repo_consumer.json",repo)
 savej(out/"repo_consumer_graph.json",repo_graph)
 savej(out/"repo_consumer_callers.json",repo_callers)
 savej(out/"strategy_assessment.json",assessment)

 with (out/"script_token_map.csv").open("w",newline="",encoding="utf-8-sig") as f:
  w=csv.DictWriter(f,fieldnames=["token","hits","registrations","native_rvas"]);w.writeheader()
  for x in token_rows:w.writerow({"token":x["token"],"hits":len(x["hits"]),"registrations":len(x["registrations"]),
                                  "native_rvas":";".join(r["native_rva_hex"] for r in x["registrations"])})
 with (out/"repo_consumer_callers.csv").open("w",newline="",encoding="utf-8-sig") as f:
  w=csv.DictWriter(f,fieldnames=["caller_rva_hex","size","call_sites"]);w.writeheader()
  for x in repo_callers:w.writerow({"caller_rva_hex":x["caller_rva_hex"],"size":x["size"],"call_sites":";".join(x["call_sites"])})

 if zp.exists():zp.unlink()
 with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:
  for p in out.rglob("*"):
   if p.is_file():z.write(p,p.relative_to(out))
 print("Done:",zp);print("Master:",MASTER_VERSION);print("Mode: journal-to-repository-consumer")
 print("Elapsed: %.1fs"%(time.time()-t0))

if __name__=="__main__":main()
