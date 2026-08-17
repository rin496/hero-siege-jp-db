#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hero Siege Standalone DefineItem Resolver
=========================================
No wrapper chain. Discovers gml_GlobalScript_DefineItem* registration wrappers
and follows native code references to resolve their underlying item-definition bodies.
"""
from pathlib import Path
import argparse,csv,hashlib,json,re,shutil,struct,time,zipfile
from collections import Counter,deque

MASTER_VERSION="permanent-master-v14.1-standalone-resolver"
PREP=0x0C54E830
FIELD_SETTER=0x0C566890
TARGET=0x0C579810
SWORD_BEGIN=0x05856C00
SWORD_END=0x0588E599

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

def savej(p,x): p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding="utf-8")

class PE:
    def __init__(self,p):
        self.path=p; self.data=p.read_bytes(); self.sections=[]; self._parse()
    def _parse(self):
        d=self.data; pe=u32(d,0x3c); coff=pe+4; n=u16(d,coff+2); optsz=u16(d,coff+16); opt=coff+20
        self.image_base=u64(d,opt+24); self.size_image=u32(d,opt+56); sec=opt+optsz
        for i in range(n):
            o=sec+i*40
            self.sections.append({"name":d[o:o+8].split(b"\0",1)[0].decode("ascii","ignore"),
                "vs":u32(d,o+8),"rva":u32(d,o+12),"rs":u32(d,o+16),"rp":u32(d,o+20),
                "exec":bool(u32(d,o+36)&0x20000000)})
    def off(self,r):
        for s in self.sections:
            if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):
                q=r-s["rva"]
                if q<s["rs"]: return s["rp"]+q
    def rva_from_off(self,o):
        for s in self.sections:
            if s["rp"]<=o<s["rp"]+s["rs"]: return s["rva"]+(o-s["rp"])
    def get(self,a,z):
        o=self.off(a); return b"" if o is None else self.data[o:o+z-a]
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
            o=s["rp"]+i*12; a=u32(d,o); z=u32(d,o+4)
            if a<=r<z:
                return {"begin":a,"end":z,"size":z-a,"unwind_rva":u32(d,o+8),"pdata_index":i}

def direct_refs(pe,rva):
    bd=pe.pdata(rva)
    if not bd:return {"bounds":None,"refs":[],"counts":{}}
    a,z=bd["begin"],bd["end"]; b=pe.get(a,z); refs=[]; calls=[]
    i=0
    while i<len(b):
        cur=a+i
        if i+5<=len(b) and b[i] in (0xE8,0xE9):
            t=(cur+5+s32(b,i+1))&0xffffffff
            kind="call" if b[i]==0xE8 else "jmp"
            refs.append({"at":cur,"kind":kind,"target":t,"target_hex":f"0x{t:X}","exec":pe.executable_rva(t)})
            if kind=="call":calls.append(t)
            i+=5;continue
        if i+7<=len(b) and 0x40<=b[i]<=0x4f and b[i+1]==0x8d and (b[i+2]&0xC7)==0x05:
            t=(cur+7+s32(b,i+3))&0xffffffff
            if pe.executable_rva(t):
                refs.append({"at":cur,"kind":"rip_lea_code","target":t,"target_hex":f"0x{t:X}","exec":True})
            i+=7;continue
        if i+10<=len(b) and b[i] in (0x48,0x49) and 0xB8<=b[i+1]<=0xBF:
            v=u64(b,i+2); t=pe.va_to_rva(v)
            if t is not None and pe.executable_rva(t):
                refs.append({"at":cur,"kind":"movabs_code","target":t,"target_hex":f"0x{t:X}","exec":True})
            i+=10;continue
        i+=1
    cnt=Counter(calls)
    return {"bounds":{**bd,"begin_hex":f"0x{a:X}","end_hex":f"0x{z:X}"},
            "refs":refs,
            "counts":{"prep":cnt[PREP],"setter":cnt[FIELD_SETTER],"target":cnt[TARGET],"direct_calls":len(calls)}}

def discover_registrations(pe):
    d=pe.data
    pat=re.compile(rb"gml_GlobalScript_DefineItem[A-Za-z0-9_]+")
    names={}
    for m in pat.finditer(d):
        try:n=m.group().decode("ascii")
        except:continue
        names.setdefault(n,[]).append(m.start())
    out=[]
    for name,offs in sorted(names.items()):
        for so in offs:
            srva=pe.rva_from_off(so)
            if srva is None:continue
            nva=pe.image_base+srva
            needle=struct.pack("<Q",nva)
            pos=0
            while True:
                q=d.find(needle,pos)
                if q<0:break
                pos=q+1
                # YYC registration shape confirmed by v13: [name VA][native wrapper VA][metadata VA]
                # q points at the name VA field, so the executable function pointer is q+8.
                if q+24<=len(d):
                    fva=u64(d,q+8); frva=pe.va_to_rva(fva)
                    if frva is not None and pe.executable_rva(frva) and pe.pdata(frva):
                        rrva=pe.rva_from_off(q)
                        out.append({"name":name,"name_rva":srva,"name_rva_hex":f"0x{srva:X}",
                            "registration_off":q,"registration_rva":rrva,"registration_rva_hex":f"0x{rrva:X}" if rrva is not None else None,
                            "wrapper_va":fva,"wrapper_rva":frva,"wrapper_rva_hex":f"0x{frva:X}",
                            "metadata_va":u64(d,q+16)})
    uniq={}
    for x in out:uniq[(x["name"],x["wrapper_rva"])]=x
    return list(uniq.values())

def resolve_wrapper(pe,wrapper,max_depth=4,max_nodes=256):
    q=deque([(wrapper,0,[wrapper])]); seen=set(); nodes=[]; hits=[]
    while q and len(seen)<max_nodes:
        r,depth,path=q.popleft()
        if r in seen:continue
        seen.add(r)
        info=direct_refs(pe,r)
        node={"rva":r,"rva_hex":f"0x{r:X}","depth":depth,"path":[f"0x{x:X}" for x in path],
              "bounds":info["bounds"],"counts":info["counts"],"refs":info["refs"]}
        nodes.append(node)
        c=info["counts"]
        if c.get("prep") or c.get("setter") or c.get("target") or r==SWORD_BEGIN:
            score=c.get("prep",0)*1000+c.get("setter",0)*100+c.get("target",0)*10+(info["bounds"]["size"] if info["bounds"] else 0)/100000
            hits.append({"rva":r,"rva_hex":f"0x{r:X}","depth":depth,"score":score,
                         "path":[f"0x{x:X}" for x in path],"counts":c,"bounds":info["bounds"]})
        if depth>=max_depth:continue
        for ref in info["refs"]:
            t=ref["target"]
            if ref.get("exec") and t not in seen and pe.pdata(t):
                q.append((t,depth+1,path+[t]))
    hits.sort(key=lambda x:(-x["score"],x["depth"]))
    return {"wrapper_rva":wrapper,"wrapper_rva_hex":f"0x{wrapper:X}","nodes_examined":len(nodes),
            "hits":hits,"best":hits[0] if hits else None,"nodes":nodes}

def main():
    t0=time.time(); ap=argparse.ArgumentParser(); ap.add_argument("hero_siege_dir"); args=ap.parse_args()
    root=Path(args.hero_siege_dir).resolve(); exe=choose_exe(root); pe=PE(exe)
    desk=desktop(); out=desk/"hero_siege_master"; zp=desk/"hero_siege_master.zip"
    if out.exists():shutil.rmtree(out)
    out.mkdir(parents=True)
    regs=discover_registrations(pe)
    resolved=[]
    for r in regs:
        rr=resolve_wrapper(pe,r["wrapper_rva"])
        resolved.append({**r,"resolver":rr})
    sword=[x for x in resolved if x["name"]=="gml_GlobalScript_DefineItemUniqueWeaponsSword"]
    sword_found=any(any(h["rva"]==SWORD_BEGIN for h in x["resolver"]["hits"]) for x in sword)
    families=Counter()
    for x in resolved:
        n=x["name"]
        if "Unique" in n:families["Unique"]+=1
        elif "Heroic" in n:families["Heroic"]+=1
        elif "Angelic" in n:families["Angelic"]+=1
        elif "Normal" in n:families["Normal"]+=1
        else:families["Other"]+=1
    best_hits=sum(1 for x in resolved if x["resolver"]["best"])
    summary={"version":MASTER_VERSION,"architecture":"standalone-no-wrapper",
      "exe":str(exe),"exe_sha256":sha256(exe),"valid_registration_count":len(regs),
      "family_counts":dict(families),"resolved_with_semantic_hit":best_hits,
      "sword":{"registrations":len(sword),"resolved_to_expected_body":sword_found,
               "expected_body_hex":f"0x{SWORD_BEGIN:X}",
               "candidates":[{"wrapper":x["wrapper_rva_hex"],"best":x["resolver"]["best"],
                              "hit_rvas":[h["rva_hex"] for h in x["resolver"]["hits"][:10]]} for x in sword]},
      "next_design_goal":"if resolver reaches authoritative bodies, bulk segment all Unique/Heroic/Angelic functions; otherwise use resolver paths/refs to derive the missing indirection"}
    savej(out/"master_summary.json",summary);savej(out/"defineitem_registrations.json",regs);savej(out/"defineitem_resolver.json",resolved)
    with (out/"defineitem_resolver.csv").open("w",newline="",encoding="utf-8-sig") as f:
        cols=["name","wrapper_rva_hex","best_rva","best_depth","prep","setter","target"]
        w=csv.DictWriter(f,fieldnames=cols);w.writeheader()
        for x in resolved:
            b=x["resolver"]["best"] or {};c=b.get("counts") or {}
            w.writerow({"name":x["name"],"wrapper_rva_hex":x["wrapper_rva_hex"],"best_rva":b.get("rva_hex"),
                "best_depth":b.get("depth"),"prep":c.get("prep"),"setter":c.get("setter"),"target":c.get("target")})
    (out/"diagnostics.txt").write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    if zp.exists():zp.unlink()
    with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:
        for p in out.rglob("*"):
            if p.is_file():z.write(p,p.relative_to(out))
    print("Done:",zp);print("Master:",MASTER_VERSION);print("Architecture: standalone-no-wrapper")
    print("Sword resolved:",sword_found);print("Elapsed: %.1fs"%(time.time()-t0))

if __name__=="__main__":main()
