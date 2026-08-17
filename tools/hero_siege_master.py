#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hero Siege Standalone DefineItem Discovery Scanner
=================================================
No wrapper chain. This build keeps the validated Unique Sword regression checks
and adds automatic discovery of registered gml_GlobalScript_DefineItem* natives.
"""
from pathlib import Path
import argparse, csv, hashlib, json, math, re, shutil, struct, time, zipfile
from collections import Counter

MASTER_VERSION="permanent-master-v13-standalone-discovery"
SWORD_BEGIN=0x05856C00
SWORD_END=0x0588E599
PREP=0x0C54E830
FIELD_SETTER=0x0C566890
TARGET=0x0C579810

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]
def s32(b,o): return struct.unpack_from("<i",b,o)[0]

def sha256(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda:f.read(1<<20),b""): h.update(c)
    return h.hexdigest()

def desktop():
    for p in (Path.home()/"Desktop",Path.home()/"OneDrive"/"Desktop"):
        if p.exists(): return p
    return Path.cwd()

def choose_exe(root):
    for p in (root/"Hero_Siege.exe",root/"bin"/"Hero_Siege.exe",root/"Hero Siege.exe",root/"bin"/"Hero Siege.exe"):
        if p.exists(): return p
    xs=list(root.rglob("Hero_Siege.exe"))
    if not xs: raise SystemExit("Hero_Siege.exe not found")
    return xs[0]

def savej(p,x):
    p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding="utf-8")

class PE:
    def __init__(self,p):
        self.path=p; self.data=p.read_bytes(); self.sections=[]; self._parse()
    def _parse(self):
        d=self.data; pe=u32(d,0x3C); coff=pe+4
        n=u16(d,coff+2); optsz=u16(d,coff+16); opt=coff+20
        self.image_base=u64(d,opt+24); sec=opt+optsz
        for i in range(n):
            o=sec+i*40
            self.sections.append({
                "name":d[o:o+8].split(b"\0",1)[0].decode("ascii","ignore"),
                "vs":u32(d,o+8),"rva":u32(d,o+12),
                "rs":u32(d,o+16),"rp":u32(d,o+20),
                "chars":u32(d,o+36),
            })
    def off_to_rva(self,off):
        for s in self.sections:
            if s["rp"]<=off<s["rp"]+s["rs"]:
                return s["rva"]+(off-s["rp"])
        return None
    def rva_to_off(self,r):
        for s in self.sections:
            if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):
                q=r-s["rva"]
                if q<s["rs"]: return s["rp"]+q
        return None
    def get(self,a,z):
        o=self.rva_to_off(a)
        return b"" if o is None else self.data[o:o+z-a]
    def executable_rva(self,r):
        for s in self.sections:
            if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):
                return bool(s["chars"] & 0x20000000)
        return False
    def pdata(self,r):
        s=next((x for x in self.sections if x["name"]==".pdata"),None)
        if not s: return None
        for i in range(s["rs"]//12):
            o=s["rp"]+i*12
            if o+12>len(self.data): break
            a=u32(self.data,o); z=u32(self.data,o+4)
            if a<=r<z:
                return {"begin":a,"end":z,"size":z-a,"unwind_rva":u32(self.data,o+8),"pdata_index":i}
        return None

def direct_call_targets(pe,a,z):
    b=pe.get(a,z); out=[]; i=0
    while i+5<=len(b):
        if b[i]==0xE8:
            r=a+i; out.append((r,(r+5+s32(b,i+1))&0xffffffff)); i+=5
        else: i+=1
    return out

def count_call_target(pe,a,z,target):
    return sum(1 for _,t in direct_call_targets(pe,a,z) if t==target)

def discover_defineitem_strings(pe):
    data=pe.data
    pat=re.compile(rb"gml_GlobalScript_DefineItem[A-Za-z0-9_]{0,120}\x00")
    out=[]
    for m in pat.finditer(data):
        raw=m.group(0)[:-1]
        try: name=raw.decode("ascii")
        except: continue
        rva=pe.off_to_rva(m.start())
        if rva is None: continue
        out.append({"name":name,"string_off":m.start(),"string_rva":rva,"string_va":pe.image_base+rva})
    uniq={}
    for x in out: uniq[(x["name"],x["string_rva"])]=x
    return list(uniq.values())

def ptr_to_rva(pe,q):
    if pe.image_base<=q<pe.image_base+0x100000000:
        r=q-pe.image_base
        if pe.rva_to_off(r) is not None: return r
    if pe.rva_to_off(q) is not None: return q
    return None

def discover_registrations(pe):
    strings=discover_defineitem_strings(pe)
    data=pe.data
    regs=[]
    for s in strings:
        needle=struct.pack("<Q",s["string_va"])
        start=0
        refs=[]
        while True:
            j=data.find(needle,start)
            if j<0: break
            refs.append(j); start=j+1
        for off in refs:
            if off+24>len(data): continue
            fnq=u64(data,off+8); metaq=u64(data,off+16)
            fnr=ptr_to_rva(pe,fnq)
            if fnr is None or not pe.executable_rva(fnr): continue
            rr=pe.off_to_rva(off)
            pd=pe.pdata(fnr)
            regs.append({
                "name":s["name"],
                "registration_off":off,
                "registration_rva":rr,
                "registration_rva_hex":f"0x{rr:X}" if rr is not None else None,
                "function_ptr_raw":fnq,
                "function_rva":fnr,
                "function_rva_hex":f"0x{fnr:X}",
                "metadata_ptr_raw":metaq,
                "pdata":pd,
            })
    d={}
    for r in regs:
        k=(r["name"],r["function_rva"])
        if k not in d or r["registration_off"]<d[k]["registration_off"]: d[k]=r
    return sorted(d.values(),key=lambda x:(x["name"],x["function_rva"]))

def enrich_functions(pe,regs):
    out=[]
    for r in regs:
        q=dict(r)
        pd=r.get("pdata")
        if pd:
            a,z=pd["begin"],pd["end"]
            q["call_count"]=len(direct_call_targets(pe,a,z))
            q["prep_calls"]=count_call_target(pe,a,z,PREP)
            q["setter_calls"]=count_call_target(pe,a,z,FIELD_SETTER)
            q["target_calls"]=count_call_target(pe,a,z,TARGET)
        else:
            q["call_count"]=q["prep_calls"]=q["setter_calls"]=q["target_calls"]=None
        n=q["name"]
        q["family_hint"] = (
            "Unique" if "Unique" in n else
            "Heroic" if "Heroic" in n else
            "Angelic" if "Angelic" in n else
            "Set" if "Set" in n else
            "Other"
        )
        out.append(q)
    return out

def sword_regression(pe,funcs):
    names=[f for f in funcs if f["name"]=="gml_GlobalScript_DefineItemUniqueWeaponsSword"]
    exact=any(f["function_rva"]==SWORD_BEGIN for f in names)
    prep=count_call_target(pe,SWORD_BEGIN,SWORD_END,PREP)
    setter=count_call_target(pe,SWORD_BEGIN,SWORD_END,FIELD_SETTER)
    return {
        "registration_found":bool(names),
        "registration_maps_to_expected_rva":exact,
        "expected_function_rva_hex":f"0x{SWORD_BEGIN:X}",
        "prep_count":prep,
        "prep_count_is_326":prep==326,
        "direct_setter_count_raw":setter,
    }

def write_csv(path,rows):
    cols=["name","family_hint","function_rva_hex","registration_rva_hex","prep_calls","setter_calls","target_calls","call_count","pdata_begin","pdata_end","pdata_size"]
    with path.open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=cols); w.writeheader()
        for r in rows:
            pd=r.get("pdata") or {}
            w.writerow({
                "name":r["name"],"family_hint":r["family_hint"],
                "function_rva_hex":r["function_rva_hex"],
                "registration_rva_hex":r["registration_rva_hex"],
                "prep_calls":r["prep_calls"],"setter_calls":r["setter_calls"],
                "target_calls":r["target_calls"],"call_count":r["call_count"],
                "pdata_begin":f"0x{pd['begin']:X}" if pd else "",
                "pdata_end":f"0x{pd['end']:X}" if pd else "",
                "pdata_size":pd.get("size",""),
            })

def zip_dir(src,zp):
    if zp.exists(): zp.unlink()
    with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:
        for p in src.rglob("*"):
            if p.is_file(): z.write(p,p.relative_to(src))

def main():
    t0=time.time()
    ap=argparse.ArgumentParser(); ap.add_argument("hero_siege_dir"); args=ap.parse_args()
    root=Path(args.hero_siege_dir).resolve(); exe=choose_exe(root); pe=PE(exe)
    desk=desktop(); out=desk/"hero_siege_master"; zp=desk/"hero_siege_master.zip"
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)

    regs=discover_registrations(pe)
    funcs=enrich_functions(pe,regs)
    fam=Counter(x["family_hint"] for x in funcs)
    regression=sword_regression(pe,funcs)
    summary={
        "version":MASTER_VERSION,
        "architecture":"standalone-no-wrapper",
        "mode":"defineitem-registration-discovery",
        "exe":str(exe),"exe_sha256":sha256(exe),
        "defineitem_registration_count":len(funcs),
        "family_counts":dict(fam),
        "with_pdata":sum(1 for x in funcs if x.get("pdata")),
        "with_prep_calls":sum(1 for x in funcs if (x.get("prep_calls") or 0)>0),
        "with_setter_calls":sum(1 for x in funcs if (x.get("setter_calls") or 0)>0),
        "sword_regression":regression,
        "next_design_goal":"derive generic record segmentation per discovered DefineItem function, then bulk extract property assignments",
    }
    savej(out/"master_summary.json",summary)
    savej(out/"discovered_defineitem_functions.json",funcs)
    savej(out/"sword_regression.json",regression)
    write_csv(out/"discovered_defineitem_functions.csv",funcs)
    (out/"diagnostics.txt").write_text(
        "\n".join([
            f"MASTER_VERSION={MASTER_VERSION}",
            "ARCHITECTURE=standalone-no-wrapper",
            f"DEFINEITEM_REGISTRATIONS={len(funcs)}",
            f"FAMILY_COUNTS={dict(fam)}",
            f"SWORD_REGRESSION={regression}",
        ])+"\n",encoding="utf-8")
    zip_dir(out,zp)
    print(f"Done: {zp}")
    print(f"Master: {MASTER_VERSION}")
    print("Architecture: standalone-no-wrapper")
    print(f"Discovered DefineItem registrations: {len(funcs)}")
    print(f"Elapsed: {time.time()-t0:.1f}s")

if __name__=="__main__": main()
