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

MASTER_VERSION="permanent-master-v21-variable-access-protocol"
EXPECTED_SHA="92e323592aeee63fcbdc80e9a1efe1ae7c0d12ced9fb3961b1843d2bf2f376f4"
JOURNAL_ROOT=0x093D9F60
KNOWN_REPO_CONSUMER=0x05012E80
COMPARE_CONSUMERS={
 "Normal":0x05012370,
 "Unique":0x05012E80,
 "Runeword":0x05013990,
 "Heroic":0x05013C90,
 "Translation":0x05014970,
 "Mask":0x0501A4E0,
}

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

def raw_at_rva(pe,r,n=32):
 o=pe.off(r)
 if o is None:return None
 b=pe.data[o:o+n]
 return {"rva":r,"rva_hex":f"0x{r:X}","section":pe.section(r),
         "hex":b.hex(" "),"u32":u32(b,0) if len(b)>=4 else None,
         "u64":u64(b,0) if len(b)>=8 else None}

def callsite_window(pe,at,before=96,after=96):
 bd=pe.bounds(at)
 if not bd:return None
 a=max(bd["begin"],at-before);z=min(bd["end"],at+after)
 return {"callsite_hex":f"0x{at:X}","function_begin_hex":f"0x{bd['begin']:X}",
         "start_hex":f"0x{a:X}","end_hex":f"0x{z:X}",
         "bytes_hex":pe.get(a,z).hex(" ")}

def compare_consumers(pe):
 rows=[]; all_ref_sets={}
 for name,r in COMPARE_CONSUMERS.items():
  n=scan_function(pe,r)
  if not n:
   rows.append({"name":name,"rva_hex":f"0x{r:X}","missing":True});continue
  refs=[]
  for rr in n["rip_refs"]:
   raw=raw_at_rva(pe,rr["target"],32)
   refs.append({**rr,"raw":raw})
  refset=set(rr["target_hex"] for rr in n["rip_refs"])
  all_ref_sets[name]=refset
  rows.append({"name":name,"rva_hex":n["rva_hex"],"size":n["size"],
               "call_count":len(n["calls"]),"rip_ref_count":len(n["rip_refs"]),
               "string_refs":n["string_refs"],"rip_refs":refs})
 common=sorted(set.intersection(*(s for s in all_ref_sets.values() if s))) if all_ref_sets else []
 pairwise=[]
 names=list(all_ref_sets)
 for i,a in enumerate(names):
  for b in names[i+1:]:
   inter=sorted(all_ref_sets[a]&all_ref_sets[b])
   if inter: pairwise.append({"a":a,"b":b,"shared_refs":inter,"count":len(inter)})
 return rows,common,pairwise

def describe_data_ref(pe,r,n=48):
 o=pe.off(r)
 if o is None:return {"rva_hex":f"0x{r:X}","unmapped":True}
 b=pe.data[o:o+n]
 qwords=[]; dwords=[]
 for off in range(0,min(len(b),32),8):
  if off+8<=len(b):
   v=u64(b,off); rr=pe.va_to_rva(v)
   ent={"offset":off,"value":v,"value_hex":f"0x{v:X}"}
   if rr is not None:
    ent["points_to_rva_hex"]=f"0x{rr:X}"
    ent["points_to_section"]=pe.section(rr)
    s=pe.cstr(rr,320)
    if s:ent["points_to_string"]=s
   qwords.append(ent)
 for off in range(0,min(len(b),24),4):
  if off+4<=len(b):
   dwords.append({"offset":off,"value":u32(b,off),"value_hex":f"0x{u32(b,off):X}"})
 return {"rva":r,"rva_hex":f"0x{r:X}","section":pe.section(r),
         "hex":b.hex(" "),"qwords":qwords,"dwords":dwords}

def selector_descriptor_report(pe,consumer_compare):
 rows=[]
 for c in consumer_compare:
  if c.get("missing"):continue
  for rr in c.get("rip_refs",[]):
   target=rr["target"]
   desc=describe_data_ref(pe,target,48)
   rows.append({"consumer":c["name"],"consumer_rva_hex":c["rva_hex"],
                "kind":rr["kind"],"target_hex":rr["target_hex"],"descriptor":desc})
 return rows

def exact_descriptor_label(pe,target):
 o=pe.off(target)
 if o is None:return None
 if o+16>len(pe.data):return None
 cache=u64(pe.data,o); nameva=u64(pe.data,o+8); nr=pe.va_to_rva(nameva)
 return {"target_hex":f"0x{target:X}","cache_value":cache,"cache_value_hex":f"0x{cache:X}",
         "name_va_hex":f"0x{nameva:X}","name_rva_hex":f"0x{nr:X}" if nr is not None else None,
         "name":pe.cstr(nr,320) if nr is not None else None}

def rip_ref_instruction_windows(pe,consumer_compare):
 out=[]
 for c in consumer_compare:
  if c.get("missing"):continue
  n=scan_function(pe,int(c["rva_hex"],16))
  if not n:continue
  for rr in n["rip_refs"]:
   at=rr["at"]; bd=pe.bounds(at)
   a=max(bd["begin"],at-48); z=min(bd["end"],at+80)
   out.append({"consumer":c["name"],"consumer_rva_hex":c["rva_hex"],
               "at_hex":rr["at_hex"],"kind":rr["kind"],"target_hex":rr["target_hex"],
               "descriptor":exact_descriptor_label(pe,rr["target"]),
               "window_start_hex":f"0x{a:X}","window_end_hex":f"0x{z:X}",
               "bytes_hex":pe.get(a,z).hex(" ")})
 return out

def find_variable_access_protocols(pe, consumer_compare):
 out=[]
 for c in consumer_compare:
  if c.get("missing"): continue
  r=int(c["rva_hex"],16); bd=pe.bounds(r)
  if not bd: continue
  b=pe.get(bd["begin"],bd["end"]); a=bd["begin"]
  i=0
  while i+19<=len(b):
   cur=a+i
   if (b[i:i+3]==b"\x48\x8b\x0d" and b[i+7:i+9]==b"\x8b\x15" and
       b[i+13:i+19]==b"\x48\x8b\x01\xff\x50\x08"):
    recv=(cur+7+s32(b,i+3))&0xffffffff
    desc=(cur+13+s32(b,i+9))&0xffffffff
    lab=exact_descriptor_label(pe,desc)
    out.append({"consumer":c["name"],"consumer_rva_hex":c["rva_hex"],
      "at_hex":f"0x{cur:X}","receiver_global_hex":f"0x{recv:X}",
      "receiver_section":pe.section(recv),"receiver_raw":raw_at_rva(pe,recv,32),
      "descriptor_hex":f"0x{desc:X}","descriptor_name":lab.get("name") if lab else None,
      "descriptor_cache":lab.get("cache_value") if lab else None,
      "protocol":"virtual_property_lookup_rcx_receiver_edx_selector_vtable_plus_8"})
    i+=19;continue
   i+=1
 return out

def main():
 t0=time.time();ap=argparse.ArgumentParser();ap.add_argument("hero_siege_dir");args=ap.parse_args()
 exe=choose_exe(Path(args.hero_siege_dir).resolve());h=sha256(exe)
 print("EXE SHA256:",h,flush=True)
 if h!=EXPECTED_SHA:raise SystemExit("Hero_Siege.exe changed; refusing v21 anchor assumptions.")
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
 print(f"Scanning known repo consumer 0x{KNOWN_REPO_CONSUMER:X}",flush=True)
 repo=scan_function(pe,KNOWN_REPO_CONSUMER);repo_graph=graph(pe,KNOWN_REPO_CONSUMER,depth=1,max_nodes=32)
 region_start=max(0,JOURNAL_ROOT-0x400000);region_end=JOURNAL_ROOT+0x400000;repo_callers=[]
 for a,z,u in pe.pdata:
  if z<region_start or a>region_end:continue
  b=pe.get(a,z);i=0;hits=[]
  while i+5<=len(b):
   if b[i]==0xE8:
    r=a+i;t=(r+5+s32(b,i+1))&0xffffffff
    if t==KNOWN_REPO_CONSUMER:hits.append(r)
    i+=5
   else:i+=1
  if hits:repo_callers.append({"caller_rva":a,"caller_rva_hex":f"0x{a:X}","size":z-a,"call_sites":[f"0x{x:X}" for x in hits]})
 print(f"Journal-region callers of repo consumer: {len(repo_callers)}",flush=True)
 callsite_windows=[]
 for c in repo_callers:
  for hs in c["call_sites"]:
   w=callsite_window(pe,int(hs,16),128,128)
   if w:callsite_windows.append(w)
 print(f"Captured Journal callsite windows: {len(callsite_windows)}",flush=True)
 consumer_compare,common_refs,pairwise_refs=compare_consumers(pe)
 print("Compared repository consumers:",len(consumer_compare),flush=True)
 descriptor_rows=selector_descriptor_report(pe,consumer_compare)
 exact_labels=[]
 for row in descriptor_rows:
  lab=exact_descriptor_label(pe,int(row["target_hex"],16))
  if lab and lab.get("name"):exact_labels.append({"consumer":row["consumer"],"consumer_rva_hex":row["consumer_rva_hex"],**lab})
 ref_windows=rip_ref_instruction_windows(pe,consumer_compare)
 variable_accesses=find_variable_access_protocols(pe,consumer_compare)
 named_ptrs=[]
 for row in descriptor_rows:
  for q in row["descriptor"].get("qwords",[]):
   s=q.get("points_to_string")
   if s:named_ptrs.append({"consumer":row["consumer"],"target_hex":row["target_hex"],"offset":q["offset"],"points_to_rva_hex":q.get("points_to_rva_hex"),"string":s})
 print(f"Resolved data-ref string pointers: {len(named_ptrs)}",flush=True)
 print(f"Exact descriptor labels: {len(exact_labels)}",flush=True)
 print(f"RIP-ref instruction windows: {len(ref_windows)}",flush=True)
 print(f"Variable access protocols: {len(variable_accesses)}",flush=True)
 repo_token=next(x for x in token_rows if x["token"]=="gml_Script_GetUniqueRepoStruct");repo_nodes=[]
 for reg in repo_token["registrations"]:
  n=scan_function(pe,reg["native_rva"])
  if n:repo_nodes.append(n)
 assessment={"journal_root_matches_expected":bool(pe.bounds(JOURNAL_ROOT)),"repo_consumer_matches_expected":bool(repo and repo["rva"]==KNOWN_REPO_CONSUMER),
  "get_unique_repo_struct_native_nodes":[n["rva_hex"] for n in repo_nodes],"get_unique_repo_struct_exact_token_hits":len(repo_token["hits"]),
  "get_unique_repo_struct_registration_count":len(repo_token["registrations"]),"repo_consumer_direct_call_count":len(repo["calls"]) if repo else 0,
  "repo_consumer_rip_ref_count":len(repo["rip_refs"]) if repo else 0,"repo_consumer_callers_count":len(repo_callers),
  "journal_callsite_window_count":len(callsite_windows),"compared_consumer_count":len(consumer_compare),
  "common_rip_refs_across_compared_consumers":common_refs,"resolved_data_ref_string_pointer_count":len(named_ptrs),
  "exact_descriptor_label_count":len(exact_labels),"rip_ref_instruction_window_count":len(ref_windows),
  "variable_access_protocol_count":len(variable_accesses),
  "recommended_next_step":"Use recovered receiver-global + descriptor-name property lookups to identify which GameMaker object owns itemRepoUnique/itemRepoRuneword/itemRequiredText and trace returned RValues. If repository objects remain runtime-only after this mapping, switch to a minimal read-only runtime dump."}
 summary={"version":MASTER_VERSION,"architecture":"standalone-no-wrapper","analysis_mode":"journal-to-repository-consumer","exe_sha256":h,
  "token_results":[{"token":x["token"],"hits":len(x["hits"]),"registrations":len(x["registrations"]),"native_rvas":[r["native_rva_hex"] for r in x["registrations"]]} for x in token_rows],
  "journal_root_rva_hex":f"0x{JOURNAL_ROOT:X}","known_repo_consumer_rva_hex":f"0x{KNOWN_REPO_CONSUMER:X}","assessment":assessment}
 savej(out/"master_summary.json",summary);savej(out/"script_token_map.json",token_rows);savej(out/"journal_region_repo_callers.json",repo_callers)
 savej(out/"get_unique_repo_struct_native_nodes.json",repo_nodes);savej(out/"repo_consumer.json",repo);savej(out/"repo_consumer_graph.json",repo_graph)
 savej(out/"repo_consumer_callers.json",repo_callers);savej(out/"journal_repo_callsite_windows.json",callsite_windows)
 savej(out/"repository_consumer_compare.json",consumer_compare);savej(out/"repository_consumer_shared_refs.json",{"common_all":common_refs,"pairwise":pairwise_refs})
 savej(out/"repository_selector_descriptors.json",descriptor_rows);savej(out/"repository_selector_names.json",named_ptrs)
 savej(out/"repository_exact_descriptor_labels.json",exact_labels);savej(out/"repository_rip_ref_instruction_windows.json",ref_windows)
 savej(out/"repository_variable_access_protocols.json",variable_accesses);savej(out/"strategy_assessment.json",assessment)
 with (out/"script_token_map.csv").open("w",newline="",encoding="utf-8-sig") as f:
  w=csv.DictWriter(f,fieldnames=["token","hits","registrations","native_rvas"]);w.writeheader()
  for x in token_rows:w.writerow({"token":x["token"],"hits":len(x["hits"]),"registrations":len(x["registrations"]),"native_rvas":";".join(r["native_rva_hex"] for r in x["registrations"])})
 with (out/"repo_consumer_callers.csv").open("w",newline="",encoding="utf-8-sig") as f:
  w=csv.DictWriter(f,fieldnames=["caller_rva_hex","size","call_sites"]);w.writeheader()
  for x in repo_callers:w.writerow({"caller_rva_hex":x["caller_rva_hex"],"size":x["size"],"call_sites":";".join(x["call_sites"])})
 if zp.exists():zp.unlink()
 with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:
  for p in out.rglob("*"):
   if p.is_file():z.write(p,p.relative_to(out))
 print("Done:",zp);print("Master:",MASTER_VERSION);print("Mode: variable-access-protocol");print("Elapsed: %.1fs"%(time.time()-t0))
if __name__=="__main__":main()
