#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
import csv, json, os, struct, subprocess, sys, tempfile, urllib.request, zipfile
from collections import Counter

VERSION="permanent-master-v10-github"
BASE_COMMIT="75103e8ee9cf165fd332222594f7813405a8997c"
BASE_URL=f"https://raw.githubusercontent.com/rin496/hero-siege-jp-db/{BASE_COMMIT}/tools/hero_siege_master.py"
HELPER=0x0C566890
TAIL=0x0C566950

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]
def s32(b,o): return struct.unpack_from("<i",b,o)[0]

class PE:
    def __init__(self,p):
        self.data=Path(p).read_bytes(); self.sections=[]; self._parse()
    def _parse(self):
        d=self.data; pe=u32(d,0x3c); coff=pe+4; n=u16(d,coff+2); optsz=u16(d,coff+16); opt=coff+20
        self.image_base=u64(d,opt+24); sec=opt+optsz
        for i in range(n):
            o=sec+i*40
            self.sections.append({"name":d[o:o+8].split(b"\0",1)[0].decode("ascii","ignore"),
                "vs":u32(d,o+8),"rva":u32(d,o+12),"rs":u32(d,o+16),"rp":u32(d,o+20)})
    def rva_to_off(self,r):
        for s in self.sections:
            if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):
                x=r-s["rva"]
                if x<s["rs"]: return s["rp"]+x
    def get(self,a,z):
        o=self.rva_to_off(a); return b"" if o is None else self.data[o:o+z-a]
    def pdata(self,r):
        s=next((x for x in self.sections if x["name"]==".pdata"),None)
        if not s:return None
        for i in range(s["rs"]//12):
            o=s["rp"]+i*12; a=u32(self.data,o); z=u32(self.data,o+4)
            if a<=r<z:return {"begin":a,"end":z,"size":z-a,"unwind_rva":u32(self.data,o+8),"pdata_index":i}

def desktop():
    for p in (Path.home()/"Desktop",Path.home()/"OneDrive"/"Desktop"):
        if p.exists(): return p
    return Path.cwd()

def choose_exe(root):
    for p in (root/"bin"/"Hero_Siege.exe",root/"Hero_Siege.exe"):
        if p.exists(): return p
    xs=list(root.rglob("Hero_Siege.exe"))
    if not xs: raise SystemExit("Hero_Siege.exe not found")
    return xs[0]

REG=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"]
XREG=["R8","R9","R10","R11","R12","R13","R14","R15"]

def trace_chain(pe,begin,call,start="RDI",window=0x380):
    a=max(begin,call-window); b=pe.get(a,call); ev=[]; i=0
    while i<len(b):
        r=a+i
        if i+5<=len(b) and b[i]==0xE8:
            ev.append({"rva":r,"kind":"CALL","target":(r+5+s32(b,i+1))&0xffffffff}); i+=5; continue
        if i+10<=len(b) and b[i] in (0x48,0x49) and 0xB8<=b[i+1]<=0xBF:
            idx=b[i+1]-0xB8; reg=(XREG if b[i]&1 else REG)[idx]
            ev.append({"rva":r,"kind":"IMM","dst":reg,"qword":u64(b,i+2)}); i+=10; continue
        if i+3<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x89,0x8B,0x8D):
            rex=b[i]; op=b[i+1]; m=b[i+2]; mod=(m>>6)&3; rr=(m>>3)&7; rm=m&7
            reg=(XREG if rex&4 else REG)[rr]; rmreg=(XREG if rex&1 else REG)[rm]
            if mod==3 and op in (0x89,0x8B):
                dst,src=(rmreg,reg) if op==0x89 else (reg,rmreg)
                ev.append({"rva":r,"kind":"MOV_REG","dst":dst,"src":src}); i+=3; continue
            if mod==2 and rm==5 and i+7<=len(b):
                ev.append({"rva":r,"kind":"LOAD_RBP" if op==0x8B else "LEA_RBP","dst":reg,"disp":s32(b,i+3)}); i+=7; continue
        i+=1
    chain=[]; reg=start; cutoff=call
    for _ in range(8):
        xs=[e for e in ev if e.get("dst")==reg and e["rva"]<cutoff]
        if not xs: break
        e=xs[-1]; chain.append(e); cutoff=e["rva"]
        if e["kind"]=="MOV_REG": reg=e["src"]; continue
        break
    cs=[e for e in ev if e["kind"]=="CALL" and e["rva"]<(chain[-1]["rva"] if chain else call)]
    return {"chain":chain,"nearest_call_before_terminal":cs[-1] if cs else None}

def analyze(pe,out):
    helper=json.loads((out/"consumer_helper_0xC566890.json").read_text(encoding="utf-8"))
    primary={}
    with (out/"primary_blocks.csv").open("r",encoding="utf-8-sig",newline="") as f:
        for r in csv.DictReader(f):
            primary[int(r["candidate_ordinal"])]=r
    records=[]; stats=Counter()
    for br in helper.get("blocks",[]):
        ordinal=int(br["candidate_ordinal"]); row=primary.get(ordinal,{})
        begin=int(str(row.get("begin","0")),0)
        for c in br.get("calls",[]):
            rcx=c.get("args",{}).get("RCX"); rec={"candidate_ordinal":ordinal,"segment_index":br.get("segment_index"),
                "known_name":br.get("known_name"),"call_rva":c["call_rva"],"call_rva_hex":c.get("call_rva_hex"),"rcx_assignment":rcx}
            if rcx and rcx.get("kind")=="MOV_REG" and rcx.get("src")=="RDI" and begin:
                rec["rdi_chain"]=trace_chain(pe,begin,int(c["call_rva"]),"RDI"); stats["rcx_from_rdi"]+=1
            else: stats["rcx_other"]+=1
            records.append(rec)
    rcx={"summary":dict(stats),"known":[x for x in records if x.get("known_name")],"records":records}

    bd=pe.pdata(TAIL)
    structure={"found":False}
    if bd:
        b=pe.get(bd["begin"],bd["end"])
        structure={"found":True,"function":{**bd,"begin_hex":f"0x{bd['begin']:X}","end_hex":f"0x{bd['end']:X}"},
          "facts":{"sign_extends_ECX_to_RSI":bytes.fromhex("48 63 f1") in b[:64],
                   "copies_R9_to_R15":bytes.fromhex("4d 8b f9") in b[:64],
                   "sign_extends_EDX_to_R14":bytes.fromhex("4c 63 f2") in b[:64],
                   "copies_R8D_to_R12D":bytes.fromhex("45 8b e0") in b[:64],
                   "compares_ESI_minus3":bytes.fromhex("83 fe fd") in b[:96],
                   "compares_ESI_100000":bytes.fromhex("81 fe a0 86 01 00") in b},
          "raw_prefix":b[:192].hex(" ")}
    return rcx,structure

def rezip(folder,zpath):
    if zpath.exists(): zpath.unlink()
    with zipfile.ZipFile(zpath,"w",zipfile.ZIP_DEFLATED) as z:
        for p in folder.rglob("*"):
            if p.is_file(): z.write(p,p.relative_to(folder))

def main():
    if len(sys.argv)<2: raise SystemExit("usage: hero_siege_master.py <HeroSiege dir>")
    root=Path(sys.argv[1]).resolve()
    fd,tmp=tempfile.mkstemp(suffix=".py"); os.close(fd)
    try:
        req=urllib.request.Request(BASE_URL,headers={"User-Agent":"HeroSiegeMaster-v10","Cache-Control":"no-cache"})
        with urllib.request.urlopen(req,timeout=30) as r, open(tmp,"wb") as f:f.write(r.read())
        cp=subprocess.run([sys.executable,tmp,str(root)])
        if cp.returncode: raise SystemExit(cp.returncode)
    finally:
        try: os.remove(tmp)
        except: pass

    desk=desktop(); out=desk/"hero_siege_master"; zpath=desk/"hero_siege_master.zip"
    pe=PE(choose_exe(root)); rcx,structure=analyze(pe,out)
    (out/"consumer_rcx_source_chains.json").write_text(json.dumps(rcx,indent=2,ensure_ascii=False),encoding="utf-8")
    (out/"consumer_tail_0xC566950_structure.json").write_text(json.dumps(structure,indent=2,ensure_ascii=False),encoding="utf-8")
    sp=out/"master_summary.json"; s=json.loads(sp.read_text(encoding="utf-8")); s["version"]=VERSION
    s["rcx_source_chain_summary"]=rcx["summary"]; s["tail_common_structure"]=structure
    sp.write_text(json.dumps(s,indent=2,ensure_ascii=False),encoding="utf-8")
    dp=out/"diagnostics.txt"
    with dp.open("a",encoding="utf-8") as f:
        f.write(f"\nV10_WRAPPER={VERSION}\nRCX_SOURCE_CHAINS={rcx['summary']}\nTAIL_COMMON_STRUCTURE={structure.get('facts',{})}\n")
    rezip(out,zpath)
    print(f"V10 augmentation complete: {zpath}")

if __name__=="__main__": main()
