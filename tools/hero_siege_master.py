#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
import csv,json,os,struct,subprocess,sys,tempfile,urllib.request,zipfile,base64
from collections import Counter

VERSION="permanent-master-v11-github"
BASE_BLOB="6d1320dcc2657d525486b9a83a44a2a16458e970"
BASE_API=f"https://api.github.com/repos/rin496/hero-siege-jp-db/git/blobs/{BASE_BLOB}"
HELPER=0x0C566890

def u16(b,o):return struct.unpack_from("<H",b,o)[0]
def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def u64(b,o):return struct.unpack_from("<Q",b,o)[0]
def s32(b,o):return struct.unpack_from("<i",b,o)[0]

class PE:
    def __init__(self,p):
        self.data=Path(p).read_bytes();self.sections=[];self._parse()
    def _parse(self):
        d=self.data;pe=u32(d,0x3c);coff=pe+4;n=u16(d,coff+2);optsz=u16(d,coff+16);opt=coff+20
        self.image_base=u64(d,opt+24);sec=opt+optsz
        for i in range(n):
            o=sec+i*40
            self.sections.append({"name":d[o:o+8].split(b"\0",1)[0].decode("ascii","ignore"),
              "vs":u32(d,o+8),"rva":u32(d,o+12),"rs":u32(d,o+16),"rp":u32(d,o+20)})
    def rva_to_off(self,r):
        for s in self.sections:
            if s["rva"]<=r<s["rva"]+max(s["vs"],s["rs"]):
                x=r-s["rva"]
                if x<s["rs"]:return s["rp"]+x
    def get(self,a,z):
        o=self.rva_to_off(a);return b"" if o is None else self.data[o:o+z-a]
    def slot(self,r,n=16):
        o=self.rva_to_off(r)
        if o is None:return None
        b=self.data[o:o+n]
        return {"rva":r,"rva_hex":f"0x{r:X}","raw":b.hex(" "),
                "qword":u64(b,0) if len(b)>=8 else None}

def desktop():
    for p in (Path.home()/"Desktop",Path.home()/"OneDrive"/"Desktop"):
        if p.exists():return p
    return Path.cwd()

def choose_exe(root):
    for p in (root/"bin"/"Hero_Siege.exe",root/"Hero_Siege.exe"):
        if p.exists():return p
    xs=list(root.rglob("Hero_Siege.exe"))
    if not xs:raise SystemExit("Hero_Siege.exe not found")
    return xs[0]

def parse_int(x):
    if isinstance(x,int):return x
    return int(str(x),0)

def find_helper_protocol(pe, begin, call_rva):
    a=max(begin,call_rva-0x120);b=pe.get(a,call_rva+5)
    rec={"call_rva":call_rva,"call_rva_hex":f"0x{call_rva:X}"}

    selectors=[]
    for i in range(max(0,len(b)-0x80),len(b)-6):
        if b[i:i+2]==b"\x8B\x15":
            r=a+i;t=(r+6+s32(b,i+2))&0xffffffff
            selectors.append({"rva":r,"rva_hex":f"0x{r:X}","slot_rva":t,"slot_rva_hex":f"0x{t:X}"})
    rec["rdx_rip_loads_near_call"]=selectors
    rec["helper_selector"]=selectors[-1] if selectors else None

    r8s=[]
    for i in range(max(0,len(b)-0x60),len(b)-6):
        if b[i:i+2]==b"\x41\xB8":
            r8s.append({"rva":a+i,"rva_hex":f"0x{a+i:X}","imm":u32(b,i+2),"imm_hex":f"0x{u32(b,i+2):X}"})
    rec["r8d_imm"]=r8s[-1] if r8s else None

    vcalls=[]
    for i in range(0,len(b)-3):
        if b[i:i+3]==b"\xFF\x50\x08":
            r=a+i
            after=b[i+3:min(len(b),i+20)]
            movrdi=after.find(b"\x48\x89\xC7")
            if movrdi>=0:
                prev=[]
                for j in range(max(0,i-40),i):
                    if b[j:j+2]==b"\x8B\x15":
                        rr=a+j;tt=(rr+6+s32(b,j+2))&0xffffffff
                        prev.append({"rva":rr,"rva_hex":f"0x{rr:X}","slot_rva":tt,"slot_rva_hex":f"0x{tt:X}"})
                vcalls.append({"call_rva":r,"call_rva_hex":f"0x{r:X}",
                               "selector":prev[-1] if prev else None,
                               "rax_to_rdi_rva":r+3+movrdi,
                               "rax_to_rdi_rva_hex":f"0x{r+3+movrdi:X}"})
    rec["rcx_source_virtual_calls"]=vcalls
    rec["rcx_source_virtual_call"]=vcalls[-1] if vcalls else None

    marks=[]
    pat=b"\xC7\x85\x68\x01\x00\x00"
    pos=0
    while True:
        i=b.find(pat,pos)
        if i<0:break
        marks.append({"rva":a+i,"rva_hex":f"0x{a+i:X}","value":u32(b,i+6),"value_hex":f"0x{u32(b,i+6):X}"})
        pos=i+1
    rec["rbp_0x168_markers"]=marks

    q=rec.get("helper_selector")
    if q:q["slot"]=pe.slot(q["slot_rva"])
    vc=rec.get("rcx_source_virtual_call")
    if vc and vc.get("selector"):vc["selector"]["slot"]=pe.slot(vc["selector"]["slot_rva"])
    return rec

def analyze(pe,out):
    helper=json.loads((out/"consumer_helper_0xC566890.json").read_text(encoding="utf-8"))
    primary={}
    with (out/"primary_blocks.csv").open("r",encoding="utf-8-sig",newline="") as f:
        for r in csv.DictReader(f):
            key=next((k for k in r if k.lstrip("\ufeff")=="candidate_ordinal"),None)
            if key is not None:primary[int(r[key])]=r

    records=[];pairfreq=Counter();hfreq=Counter();vfreq=Counter();r8freq=Counter()
    for br in helper.get("blocks",[]):
        ordinal=int(br["candidate_ordinal"]);row=primary.get(ordinal,{})
        begin=parse_int(row.get("begin","0")) if row else 0
        for c in br.get("calls",[]):
            rec=find_helper_protocol(pe,begin,int(c["call_rva"]))
            rec.update({"candidate_ordinal":ordinal,"segment_index":br.get("segment_index"),"known_name":br.get("known_name"),
                        "aux_0x100":c.get("aux_0x100"),"canonical_0x1D0":c.get("canonical_0x1D0")})
            h=rec.get("helper_selector");v=rec.get("rcx_source_virtual_call",{}).get("selector") if rec.get("rcx_source_virtual_call") else None
            hs=h.get("slot_rva_hex") if h else None;vs=v.get("slot_rva_hex") if v else None
            pairfreq[(vs,hs)]+=1
            hfreq[hs]+=1;vfreq[vs]+=1
            r8=rec.get("r8d_imm");r8freq[r8.get("imm_hex") if r8 else None]+=1
            records.append(rec)

    return {
      "summary":{
        "calls":len(records),
        "selector_pairs":[{"virtual_selector":a,"helper_selector":b,"count":c} for (a,b),c in pairfreq.most_common()],
        "virtual_selector_frequency":[{"slot":k,"count":v} for k,v in vfreq.most_common()],
        "helper_selector_frequency":[{"slot":k,"count":v} for k,v in hfreq.most_common()],
        "r8d_frequency":[{"value":k,"count":v} for k,v in r8freq.most_common()],
      },
      "known":[x for x in records if x.get("known_name")],
      "records":records
    }

def rezip(folder,zpath):
    if zpath.exists():zpath.unlink()
    with zipfile.ZipFile(zpath,"w",zipfile.ZIP_DEFLATED) as z:
        for p in folder.rglob("*"):
            if p.is_file():z.write(p,p.relative_to(folder))

def main():
    if len(sys.argv)<2:raise SystemExit("usage: hero_siege_master.py <HeroSiege dir>")
    root=Path(sys.argv[1]).resolve()
    fd,tmp=tempfile.mkstemp(suffix=".py");os.close(fd)
    try:
        req=urllib.request.Request(BASE_API,headers={"User-Agent":"HeroSiegeMaster-v11","Accept":"application/vnd.github+json","Cache-Control":"no-cache"})
        with urllib.request.urlopen(req,timeout=30) as r:
            obj=json.loads(r.read().decode("utf-8"))
        data=base64.b64decode(obj["content"])
        Path(tmp).write_bytes(data)
        cp=subprocess.run([sys.executable,tmp,str(root)])
        if cp.returncode:raise SystemExit(cp.returncode)
    finally:
        try:os.remove(tmp)
        except:pass

    desk=desktop();out=desk/"hero_siege_master";zpath=desk/"hero_siege_master.zip"
    pe=PE(choose_exe(root));proto=analyze(pe,out)
    (out/"consumer_helper_protocol_v11.json").write_text(json.dumps(proto,indent=2,ensure_ascii=False),encoding="utf-8")
    sp=out/"master_summary.json";s=json.loads(sp.read_text(encoding="utf-8"));s["version"]=VERSION;s["helper_protocol_v11_summary"]=proto["summary"]
    sp.write_text(json.dumps(s,indent=2,ensure_ascii=False),encoding="utf-8")
    with (out/"diagnostics.txt").open("a",encoding="utf-8") as f:
        f.write("\nV11="+VERSION+"\nHELPER_PROTOCOL="+repr(proto["summary"])+"\n")
    rezip(out,zpath)
    print("V11 augmentation complete:",zpath)

if __name__=="__main__":main()
