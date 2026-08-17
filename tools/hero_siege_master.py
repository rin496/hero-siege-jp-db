#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hero Siege Standalone Consumer / Repository Scanner
===================================================
Pivot away from reconstructing every DefineItem producer.
This scanner maps the consumer/repository side used by Journal/tooltips:
repository getters, translation/mask/set helpers, loot sprite helpers, and
UI_Journal_Items_obj-related native registrations.

No wrapper chain. Static evidence only; no runtime injection.
"""
from pathlib import Path
import argparse, csv, hashlib, json, re, shutil, struct, time, zipfile
from collections import Counter, deque

MASTER_VERSION = "permanent-master-v16-consumer-repository"
EXPECTED_SHA = "92e323592aeee63fcbdc80e9a1efe1ae7c0d12ced9fb3961b1843d2bf2f376f4"

TARGET_SYMBOLS = [
    "gml_GlobalScript_GetUniqueRepoStruct",
    "gml_GlobalScript_GetNormalRepoStruct",
    "gml_GlobalScript_GetRunewordRepoStruct",
    "gml_GlobalScript_GetHeroicItem",
    "gml_GlobalScript_GetItemTranslationServerData",
    "gml_GlobalScript_GetItemMask",
    "gml_GlobalScript_GetSetInformation",
    "gml_GlobalScript_GetSetNames",
    "gml_GlobalScript_GetSetName",
    "gml_GlobalScript_GetLootSprite",
]
JOURNAL_TOKEN = "UI_Journal_Items_obj"

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
    for p in (Path.home()/"Desktop", Path.home()/"OneDrive"/"Desktop"):
        if p.exists(): return p
    return Path.cwd()

def choose_exe(root):
    for p in (root/"Hero_Siege.exe", root/"bin"/"Hero_Siege.exe", root/"Hero Siege.exe", root/"bin"/"Hero Siege.exe"):
        if p.exists(): return p
    xs=list(root.rglob("Hero_Siege.exe"))
    if not xs: raise SystemExit("Hero_Siege.exe not found")
    return xs[0]

def savej(p,x): p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding="utf-8")

class PE:
    def __init__(self,p):
        self.path=p; self.data=p.read_bytes(); self.sections=[]; self._parse()
    def _parse(self):
        d=self.data; pe=u32(d,0x3c); coff=pe+4; n=u16(d,coff+2); osz=u16(d,coff+16); opt=coff+20
        self.image_base=u64(d,opt+24); self.size_image=u32(d,opt+56); sec=opt+osz
        for i in range(n):
            o=sec+i*40
            self.sections.append({
                "name":d[o:o+8].split(b"\0",1)[0].decode("ascii","ignore"),
                "vs":u32(d,o+8),"rva":u32(d,o+12),"rs":u32(d,o+16),"rp":u32(d,o+20),
                "exec":bool(u32(d,o+36)&0x20000000)
            })
        ps=next((x for x in self.sections if x["name"]==".pdata"),None)
        self.pdata_rows=[]
        if ps:
            for i in range(ps["rs"]//12):
                o=ps["rp"]+i*12
                self.pdata_rows.append((u32(d,o),u32(d,o+4),u32(d,o+8)))
    def off(self,r):
        for s in self.sections:
            if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):
                q=r-s["rva"]
                if q<s["rs"]: return s["rp"]+q
    def rva_from_off(self,o):
        for s in self.sections:
            if s["rp"]<=o<s["rp"]+s["rs"]: return s["rva"]+(o-s["rp"])
    def va_to_rva(self,v):
        r=v-self.image_base
        return r if 0<=r<self.size_image else None
    def get(self,a,z):
        o=self.off(a); return b"" if o is None else self.data[o:o+z-a]
    def executable(self,r):
        return any(s["exec"] and s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]) for s in self.sections)
    def bounds(self,r):
        for a,z,u in self.pdata_rows:
            if a<=r<z:return {"begin":a,"end":z,"size":z-a,"unwind":u}
    def cstring_rva(self,r,maxlen=240):
        o=self.off(r)
        if o is None:return None
        raw=self.data[o:o+maxlen]
        q=raw.find(b"\0")
        if q<0:q=len(raw)
        raw=raw[:q]
        if not raw:return None
        try:s=raw.decode("utf-8")
        except:return None
        if not all((31<ord(ch)<127) or ch in "\t\r\n" for ch in s):return None
        return s
    def section_name(self,r):
        for s in self.sections:
            if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):return s["name"]

def find_ascii(pe,text):
    needle=text.encode("ascii")
    out=[]; pos=0
    while True:
        o=pe.data.find(needle,pos)
        if o<0:break
        pos=o+1; r=pe.rva_from_off(o)
        if r is not None:out.append({"off":o,"rva":r,"rva_hex":f"0x{r:X}"})
    return out

def registration_for_string(pe,name_hit):
    """YYC registration shape: [name VA][native function VA][metadata VA]."""
    name_rva=name_hit["rva"]; needle=struct.pack("<Q",pe.image_base+name_rva); d=pe.data
    out=[]; pos=0
    while True:
        q=d.find(needle,pos)
        if q<0:break
        pos=q+1
        if q+24>len(d):continue
        fva=u64(d,q+8); frva=pe.va_to_rva(fva)
        if frva is None or not pe.executable(frva) or not pe.bounds(frva):continue
        rr=pe.rva_from_off(q)
        out.append({
            "registration_off":q,
            "registration_rva":rr,
            "registration_rva_hex":f"0x{rr:X}" if rr is not None else None,
            "native_rva":frva,"native_rva_hex":f"0x{frva:X}",
            "metadata_va":u64(d,q+16)
        })
    uniq={}
    for x in out:uniq[x["native_rva"]]=x
    return list(uniq.values())

def scan_function(pe,rva):
    bd=pe.bounds(rva)
    if not bd:return None
    a,z=bd["begin"],bd["end"]; b=pe.get(a,z)
    calls=[]; refs=[]; selectors=[]; strings=[]; i=0
    while i<len(b):
        cur=a+i
        if i+5<=len(b) and b[i]==0xE8:
            t=(cur+5+s32(b,i+1))&0xffffffff
            calls.append({"at":cur,"at_hex":f"0x{cur:X}","target":t,"target_hex":f"0x{t:X}",
                          "target_exec":pe.executable(t)})
            i+=5;continue
        if i+6<=len(b) and b[i] in (0x8B,0x8D) and (b[i+1]&0xC7)==0x05:
            inslen=6; t=(cur+inslen+s32(b,i+2))&0xffffffff
            kind="rip_mov32" if b[i]==0x8B else "rip_lea32"
            rec={"at":cur,"at_hex":f"0x{cur:X}","kind":kind,"target":t,"target_hex":f"0x{t:X}",
                 "section":pe.section_name(t)}
            refs.append(rec)
            s=pe.cstring_rva(t)
            if s: strings.append({**rec,"text":s})
            if b[i]==0x8B: selectors.append(rec)
            i+=inslen;continue
        if i+7<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x8B,0x8D) and (b[i+2]&0xC7)==0x05:
            inslen=7; t=(cur+inslen+s32(b,i+3))&0xffffffff
            kind="rip_mov64" if b[i+1]==0x8B else "rip_lea64"
            rec={"at":cur,"at_hex":f"0x{cur:X}","kind":kind,"target":t,"target_hex":f"0x{t:X}",
                 "section":pe.section_name(t)}
            refs.append(rec)
            s=pe.cstring_rva(t)
            if s: strings.append({**rec,"text":s})
            if b[i+1]==0x8B: selectors.append(rec)
            i+=inslen;continue
        i+=1
    ur={}; us={}
    for x in refs:ur[(x["kind"],x["target"])]=x
    for x in strings:us[(x["target"],x["text"])]=x
    return {
        "rva":bd["begin"],"rva_hex":f"0x{bd['begin']:X}",
        "end_rva":bd["end"],"end_rva_hex":f"0x{bd['end']:X}",
        "size":bd["size"],"direct_calls":calls,
        "rip_refs":list(ur.values()),"string_refs":list(us.values()),
        "selector_like_refs":selectors
    }

def shallow_graph(pe,start,max_depth=2,max_nodes=48):
    q=deque([(start,0,[start])]);seen=set();nodes=[]
    while q and len(nodes)<max_nodes:
        r,depth,path=q.popleft()
        bd=pe.bounds(r)
        if not bd:continue
        key=bd["begin"]
        if key in seen:continue
        seen.add(key)
        info=scan_function(pe,key)
        if not info:continue
        nodes.append({"depth":depth,"path":[f"0x{x:X}" for x in path],**info})
        if depth>=max_depth:continue
        for c in info["direct_calls"]:
            t=c["target"]
            if c["target_exec"] and pe.bounds(t):
                q.append((t,depth+1,path+[pe.bounds(t)["begin"]]))
    return nodes

def journal_strings(pe):
    pat=re.compile(rb"[ -~]{4,180}"+re.escape(JOURNAL_TOKEN.encode("ascii"))+rb"[ -~]{0,180}")
    out=[];seen=set()
    for m in pat.finditer(pe.data):
        raw=m.group()
        parts=raw.split(b"\0")
        for part in parts:
            if JOURNAL_TOKEN.encode() not in part:continue
            try:s=part.decode("ascii")
            except:continue
            o=pe.data.find(part,max(0,m.start()-8),min(len(pe.data),m.end()+8))
            r=pe.rva_from_off(o) if o>=0 else None
            k=(r,s)
            if r is not None and k not in seen:
                seen.add(k);out.append({"text":s,"rva":r,"rva_hex":f"0x{r:X}"})
    if not out:
        for h in find_ascii(pe,JOURNAL_TOKEN):
            out.append({"text":JOURNAL_TOKEN,"rva":h["rva"],"rva_hex":h["rva_hex"]})
    return out

def qword_xrefs(pe,target_rva,limit=200):
    needle=struct.pack("<Q",pe.image_base+target_rva);d=pe.data;out=[];pos=0
    while len(out)<limit:
        q=d.find(needle,pos)
        if q<0:break
        pos=q+1;r=pe.rva_from_off(q)
        out.append({"off":q,"rva":r,"rva_hex":f"0x{r:X}" if r is not None else None,
                    "section":pe.section_name(r) if r is not None else None})
    return out

def main():
    t0=time.time();ap=argparse.ArgumentParser();ap.add_argument("hero_siege_dir");args=ap.parse_args()
    root=Path(args.hero_siege_dir).resolve();exe=choose_exe(root);h=sha256(exe)
    print("EXE SHA256:",h,flush=True)
    if h!=EXPECTED_SHA:
        raise SystemExit("Hero_Siege.exe changed; refusing v16 anchor assumptions.")
    pe=PE(exe);d=desktop();out=d/"hero_siege_master";zp=d/"hero_siege_master.zip"
    if out.exists():shutil.rmtree(out)
    out.mkdir(parents=True)

    symbol_results=[];all_nodes=[];selector_freq=Counter();string_freq=Counter()
    print("Consumer scan: repository/helper symbols",flush=True)
    for idx,name in enumerate(TARGET_SYMBOLS,1):
        hits=find_ascii(pe,name);regs=[]
        for hit in hits:regs.extend(registration_for_string(pe,hit))
        uniq={x["native_rva"]:x for x in regs};regs=list(uniq.values())
        entry={"name":name,"string_hits":hits,"registrations":regs,"graphs":[]}
        for reg in regs[:4]:
            nodes=shallow_graph(pe,reg["native_rva"],max_depth=2,max_nodes=48)
            entry["graphs"].append({"native_rva_hex":reg["native_rva_hex"],"nodes":nodes})
            for n in nodes:
                all_nodes.append({"symbol":name,**n})
                for rr in n["selector_like_refs"]:selector_freq[rr["target_hex"]]+=1
                for sr in n["string_refs"]:string_freq[sr["text"]]+=1
        symbol_results.append(entry)
        print(f"  {idx}/{len(TARGET_SYMBOLS)} {name}: strings={len(hits)} regs={len(regs)}",flush=True)

    print("Consumer scan: Journal resources",flush=True)
    jstrings=journal_strings(pe);jentries=[]
    for j in jstrings[:80]:
        xrefs=qword_xrefs(pe,j["rva"])
        regc=[]
        for xr in xrefs[:80]:
            o=xr["off"]
            for delta in (-24,-16,-8,8,16,24):
                p=o+delta
                if p<0 or p+8>len(pe.data):continue
                v=u64(pe.data,p);r=pe.va_to_rva(v)
                if r is not None and pe.executable(r) and pe.bounds(r):
                    regc.append({"near_xref_off":o,"delta":delta,"candidate_rva":pe.bounds(r)["begin"],
                                 "candidate_rva_hex":f"0x{pe.bounds(r)['begin']:X}"})
        uq={}
        for x in regc:uq[x["candidate_rva"]]=x
        cands=list(uq.values())[:20]
        graphs=[]
        for c in cands[:6]:
            graphs.append({"candidate_rva_hex":c["candidate_rva_hex"],
                           "nodes":shallow_graph(pe,c["candidate_rva"],max_depth=1,max_nodes=24)})
        jentries.append({**j,"qword_xrefs":xrefs,"candidate_functions":cands,"graphs":graphs})
        print(f"  Journal string {j['rva_hex']}: xrefs={len(xrefs)} candidates={len(cands)}",flush=True)

    assessment={
        "static_repository_path_found": any(x["registrations"] for x in symbol_results if x["name"].endswith("GetUniqueRepoStruct")),
        "journal_native_candidates_found": any(x["candidate_functions"] for x in jentries),
        "recommended_next_step":
            "Resolve repository getter return/value access schema from consumer callsites before considering runtime dump. "
            "If getters only expose runtime-built structs with no static field-name path, instrument a minimal read-only runtime dump."
    }
    summary={
        "version":MASTER_VERSION,"architecture":"standalone-no-wrapper",
        "analysis_mode":"consumer-repository-first","exe_sha256":h,
        "target_symbol_count":len(TARGET_SYMBOLS),
        "symbols_with_registration":sum(1 for x in symbol_results if x["registrations"]),
        "journal_string_count":len(jstrings),
        "journal_entries_with_candidate_functions":sum(1 for x in jentries if x["candidate_functions"]),
        "selector_like_reference_frequency":[{"target":k,"count":v} for k,v in selector_freq.most_common(100)],
        "referenced_string_frequency":[{"text":k,"count":v} for k,v in string_freq.most_common(100)],
        "assessment":assessment
    }
    savej(out/"master_summary.json",summary)
    savej(out/"consumer_symbols.json",symbol_results)
    savej(out/"consumer_function_nodes.json",all_nodes)
    savej(out/"journal_consumer_candidates.json",jentries)
    savej(out/"repository_strategy_assessment.json",assessment)
    with (out/"consumer_symbols.csv").open("w",newline="",encoding="utf-8-sig") as f:
        cols=["name","string_hits","registration_count","native_rvas"]
        w=csv.DictWriter(f,fieldnames=cols);w.writeheader()
        for x in symbol_results:
            w.writerow({"name":x["name"],"string_hits":len(x["string_hits"]),
                        "registration_count":len(x["registrations"]),
                        "native_rvas":";".join(r["native_rva_hex"] for r in x["registrations"])})
    with (out/"consumer_function_summary.csv").open("w",newline="",encoding="utf-8-sig") as f:
        cols=["symbol","depth","rva_hex","end_rva_hex","size","direct_call_count","rip_ref_count","string_ref_count"]
        w=csv.DictWriter(f,fieldnames=cols);w.writeheader()
        for n in all_nodes:
            w.writerow({"symbol":n["symbol"],"depth":n["depth"],"rva_hex":n["rva_hex"],"end_rva_hex":n["end_rva_hex"],
                        "size":n["size"],"direct_call_count":len(n["direct_calls"]),
                        "rip_ref_count":len(n["rip_refs"]),"string_ref_count":len(n["string_refs"])})
    if zp.exists():zp.unlink()
    with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:
        for p in out.rglob("*"):
            if p.is_file():z.write(p,p.relative_to(out))
    print("Done:",zp);print("Master:",MASTER_VERSION)
    print("Mode: consumer-repository-first");print("Elapsed: %.1fs"%(time.time()-t0))

if __name__=="__main__":main()
