#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hero Siege Standalone Unique Segment Survey
===========================================
No wrapper chain. Resolves registered DefineItemUnique* wrappers to their native
definition bodies, then surveys PREP-delimited segment structure across every
resolved Unique function. It does NOT yet promote segments to item records.
"""
from pathlib import Path
import argparse,csv,hashlib,json,re,shutil,struct,time,zipfile
from collections import Counter,defaultdict

MASTER_VERSION="permanent-master-v15-standalone-segment-survey"
PREP=0x0C54E830
FIELD_SETTER=0x0C566890
TARGET=0x0C579810
ITEM_HELPER=0x058A48A0
VALUE_HELPER=0x00056710
CLEANUP=0x00056560
SWORD_BEGIN=0x05856C00

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
        self.path=p;self.data=p.read_bytes();self.sections=[];self._parse()
    def _parse(self):
        d=self.data;pe=u32(d,0x3c);coff=pe+4;n=u16(d,coff+2);optsz=u16(d,coff+16);opt=coff+20
        self.image_base=u64(d,opt+24);self.size_image=u32(d,opt+56);sec=opt+optsz
        for i in range(n):
            o=sec+i*40
            self.sections.append({"name":d[o:o+8].split(b"\0",1)[0].decode("ascii","ignore"),
                "vs":u32(d,o+8),"rva":u32(d,o+12),"rs":u32(d,o+16),"rp":u32(d,o+20),
                "exec":bool(u32(d,o+36)&0x20000000)})
    def off(self,r):
        for s in self.sections:
            if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):
                q=r-s["rva"]
                if q<s["rs"]:return s["rp"]+q
    def rva_from_off(self,o):
        for s in self.sections:
            if s["rp"]<=o<s["rp"]+s["rs"]:return s["rva"]+(o-s["rp"])
    def get(self,a,z):
        o=self.off(a);return b"" if o is None else self.data[o:o+z-a]
    def executable_rva(self,r):
        return any(s["exec"] and s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]) for s in self.sections)
    def va_to_rva(self,v):
        r=v-self.image_base
        return r if 0<=r<self.size_image else None
    def pdata(self,r):
        s=next((x for x in self.sections if x["name"]==".pdata"),None)
        if not s:return None
        d=self.data
        for i in range(s["rs"]//12):
            o=s["rp"]+i*12;a=u32(d,o);z=u32(d,o+4)
            if a<=r<z:return {"begin":a,"end":z,"size":z-a,"unwind_rva":u32(d,o+8),"pdata_index":i}

def direct_calls(pe,a,z):
    b=pe.get(a,z);out=[];i=0
    while i+5<=len(b):
        if b[i]==0xE8:
            r=a+i;out.append((r,(r+5+s32(b,i+1))&0xffffffff));i+=5
        else:i+=1
    return out

def discover_regs(pe):
    d=pe.data;pat=re.compile(rb"gml_GlobalScript_DefineItem[A-Za-z0-9_]+");out=[]
    seen=set()
    for m in pat.finditer(d):
        name=m.group().decode("ascii","ignore")
        if not name.startswith("gml_GlobalScript_DefineItem"):continue
        srva=pe.rva_from_off(m.start())
        if srva is None:continue
        needle=struct.pack("<Q",pe.image_base+srva);pos=0
        while True:
            q=d.find(needle,pos)
            if q<0:break
            pos=q+1
            if q+24>len(d):continue
            fva=u64(d,q+8);frva=pe.va_to_rva(fva)
            if frva is None or not pe.executable_rva(frva) or not pe.pdata(frva):continue
            k=(name,frva)
            if k in seen:continue
            seen.add(k)
            out.append({"name":name,"wrapper_rva":frva,"wrapper_rva_hex":f"0x{frva:X}"})
    return sorted(out,key=lambda x:x["name"])

def resolve_one_level(pe,reg):
    wb=pe.pdata(reg["wrapper_rva"])
    if not wb:return None
    candidates=[]
    for at,t in direct_calls(pe,wb["begin"],wb["end"]):
        if not pe.executable_rva(t):continue
        bd=pe.pdata(t)
        if not bd:continue
        calls=direct_calls(pe,bd["begin"],bd["end"])
        cnt=Counter(x[1] for x in calls)
        score=cnt[PREP]*1000+cnt[FIELD_SETTER]*100+cnt[TARGET]*10+bd["size"]/100000
        candidates.append({"body_rva":bd["begin"],"body_rva_hex":f"0x{bd['begin']:X}",
            "body_end":bd["end"],"body_end_hex":f"0x{bd['end']:X}","body_size":bd["size"],
            "via_call_rva":at,"prep_count":cnt[PREP],"setter_count_raw":cnt[FIELD_SETTER],
            "target_count_raw":cnt[TARGET],"score":score})
    semantic=[x for x in candidates if x["prep_count"] or x["setter_count_raw"] or x["target_count_raw"]]
    semantic.sort(key=lambda x:-x["score"])
    return semantic[0] if semantic else None

def segment_features(pe,body):
    calls=direct_calls(pe,body["body_rva"],body["body_end"])
    preps=[at for at,t in calls if t==PREP]
    rows=[]
    for i,a in enumerate(preps):
        z=preps[i+1] if i+1<len(preps) else body["body_end"]
        scalls=[(at,t) for at,t in calls if a<=at<z]
        cnt=Counter(t for _,t in scalls)
        rows.append({"segment_index":i,"begin":a,"begin_hex":f"0x{a:X}",
            "end":z,"end_hex":f"0x{z:X}","size":z-a,
            "call_count":len(scalls),"prep":cnt[PREP],"target":cnt[TARGET],
            "setter":cnt[FIELD_SETTER],"item_helper":cnt[ITEM_HELPER],
            "value_helper":cnt[VALUE_HELPER],"cleanup":cnt[CLEANUP]})
    return rows

def alternating_profiles(rows):
    out=[]
    for parity in (0,1):
        xs=[r for r in rows if r["segment_index"]%2==parity]
        sig=Counter((r["target"],r["setter"],r["item_helper"],r["value_helper"],r["cleanup"]) for r in xs[:120])
        out.append({"parity":parity,"segments_considered":min(120,len(xs)),
            "top_signatures":[{"signature":list(k),"count":v} for k,v in sig.most_common(10)]})
    return out

def main():
    t0=time.time();ap=argparse.ArgumentParser();ap.add_argument("hero_siege_dir");args=ap.parse_args()
    root=Path(args.hero_siege_dir).resolve();exe=choose_exe(root);pe=PE(exe)
    desk=desktop();out=desk/"hero_siege_master";zp=desk/"hero_siege_master.zip"
    if out.exists():shutil.rmtree(out)
    out.mkdir(parents=True)
    regs=discover_regs(pe)
    uregs=[r for r in regs if "DefineItemUnique" in r["name"]]
    bodies=[];survey=[];all_segments=[]
    for idx,r in enumerate(uregs,1):
        body=resolve_one_level(pe,r)
        rec={**r,"resolved":body}
        bodies.append(rec)
        if body:
            segs=segment_features(pe,body)
            survey.append({"name":r["name"],"wrapper_rva_hex":r["wrapper_rva_hex"],
                "body":body,"segment_count":len(segs),"alternating_profiles":alternating_profiles(segs)})
            for s in segs:all_segments.append({"name":r["name"],"body_rva_hex":body["body_rva_hex"],**s})
        if idx==1 or idx%5==0 or idx==len(uregs):
            print(f"Survey progress: {idx}/{len(uregs)} {r['name']}",flush=True)
    sword=next((x for x in bodies if x["name"]=="gml_GlobalScript_DefineItemUniqueWeaponsSword"),None)
    sword_ok=bool(sword and sword["resolved"] and sword["resolved"]["body_rva"]==SWORD_BEGIN)
    summary={"version":MASTER_VERSION,"architecture":"standalone-no-wrapper","exe":str(exe),
        "exe_sha256":sha256(exe),"defineitem_registration_count":len(regs),
        "unique_registration_count":len(uregs),"unique_resolved_count":sum(1 for x in bodies if x["resolved"]),
        "sword_resolved_to_expected_body":sword_ok,
        "resolved_unique_bodies":[{"name":x["name"],"wrapper_rva_hex":x["wrapper_rva_hex"],
            "body_rva_hex":x["resolved"]["body_rva_hex"] if x["resolved"] else None,
            "prep_count":x["resolved"]["prep_count"] if x["resolved"] else None} for x in bodies],
        "design_status":"segment-survey-only; no cross-category item count or item identity is inferred yet",
        "next_design_goal":"derive a validated generic primary-record boundary rule from cross-function PREP segment signatures, anchored by Unique Sword"}
    savej(out/"master_summary.json",summary);savej(out/"unique_function_bodies.json",bodies)
    savej(out/"unique_segment_survey.json",survey);savej(out/"all_unique_segments.json",all_segments)
    with (out/"unique_function_bodies.csv").open("w",newline="",encoding="utf-8-sig") as f:
        cols=["name","wrapper_rva_hex","body_rva_hex","body_end_hex","body_size","prep_count","setter_count_raw","target_count_raw"]
        w=csv.DictWriter(f,fieldnames=cols);w.writeheader()
        for x in bodies:
            b=x["resolved"] or {}
            w.writerow({"name":x["name"],"wrapper_rva_hex":x["wrapper_rva_hex"],
                "body_rva_hex":b.get("body_rva_hex"),"body_end_hex":b.get("body_end_hex"),
                "body_size":b.get("body_size"),"prep_count":b.get("prep_count"),
                "setter_count_raw":b.get("setter_count_raw"),"target_count_raw":b.get("target_count_raw")})
    with (out/"all_unique_segments.csv").open("w",newline="",encoding="utf-8-sig") as f:
        cols=["name","body_rva_hex","segment_index","begin_hex","end_hex","size","call_count","target","setter","item_helper","value_helper","cleanup"]
        w=csv.DictWriter(f,fieldnames=cols);w.writeheader()
        for r in all_segments:w.writerow({k:r.get(k) for k in cols})
    (out/"diagnostics.txt").write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    if zp.exists():zp.unlink()
    with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:
        for p in out.rglob("*"):
            if p.is_file():z.write(p,p.relative_to(out))
    print("Done:",zp);print("Master:",MASTER_VERSION);print("Architecture: standalone-no-wrapper")
    print("Sword body regression:",sword_ok);print("Elapsed: %.1fs"%(time.time()-t0))

if __name__=="__main__":main()
