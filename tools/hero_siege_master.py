#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
from collections import defaultdict,Counter
import argparse,csv,hashlib,json,math,shutil,struct,zipfile

VERSION="permanent-master-v7-github"
FB=0x05856C00;FE=0x0588E599;PREP=0x0C54E830;TARGET=0x0C579810
HELPER=0x0C566890;INNER=0x0C534390
PRIMARY=list(range(2,71,2))
KNOWN={8:"Godfather",20:"Thor",40:"Genji"}
EXPECT={"Godfather":([13315,1424,11],1855),"Thor":([8860,1424,83],16155),"Genji":([8866,1424,78],29455)}
REG=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"]

def u16(b,o):return struct.unpack_from("<H",b,o)[0]
def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def u64(b,o):return struct.unpack_from("<Q",b,o)[0]
def s32(b,o):return struct.unpack_from("<i",b,o)[0]
def desk():
    for p in (Path.home()/"Desktop",Path.home()/"OneDrive"/"Desktop"):
        if p.exists():return p
    return Path.cwd()
def sha(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda:f.read(1<<20),b""):h.update(c)
    return h.hexdigest()
def fd(q):
    try:
        x=struct.unpack("<d",struct.pack("<Q",q))[0]
        if not math.isfinite(x) or abs(x)>1e12:return None
        return int(round(x)) if abs(x-round(x))<1e-10 else x
    except:return None
def uniq(xs):
    o=[]
    for x in xs:
        if x not in o:o.append(x)
    return o
def subseq(seq,sub):
    j=0
    for x in seq:
        if j<len(sub) and x==sub[j]:j+=1
    return j==len(sub)
def choose(root):
    for p in (root/"Hero_Siege.exe",root/"bin"/"Hero_Siege.exe"):
        if p.exists():return p
    xs=list(root.rglob("Hero_Siege.exe"))
    if not xs:raise SystemExit("Hero_Siege.exe not found")
    return xs[0]

class PE:
    def __init__(self,p):
        self.p=p;self.d=p.read_bytes();self.s=[]
        pe=u32(self.d,0x3c);coff=pe+4;n=u16(self.d,coff+2);osz=u16(self.d,coff+16);sec=coff+20+osz
        for i in range(n):
            o=sec+i*40
            self.s.append({"name":self.d[o:o+8].split(b"\0",1)[0].decode("ascii","ignore"),"vs":u32(self.d,o+8),"va":u32(self.d,o+12),"rs":u32(self.d,o+16),"rp":u32(self.d,o+20)})
    def off(self,r):
        for s in self.s:
            if s["va"]<=r<s["va"]+max(s["vs"],s["rs"]) and r-s["va"]<s["rs"]:return s["rp"]+r-s["va"]
    def get(self,a,z):
        o=self.off(a);return b"" if o is None else self.d[o:o+z-a]
    def pdata(self,r):
        s=next((x for x in self.s if x["name"]==".pdata"),None)
        if not s:return None
        for i in range(s["rs"]//12):
            o=s["rp"]+i*12;a=u32(self.d,o);z=u32(self.d,o+4);uw=u32(self.d,o+8)
            if a<=r<z:return {"begin":a,"end":z,"size":z-a,"unwind_rva":uw,"pdata_index":i}

def calls(pe,a,z):
    b=pe.get(a,z);out=[];by=defaultdict(list);i=0
    while i+5<=len(b):
        if b[i]==0xE8:
            r=a+i;t=(r+5+s32(b,i+1))&0xffffffff;out.append({"rva":r,"target":t});by[t].append(r);i+=5
        else:i+=1
    return out,by

def scan(pe,a,z):
    b=pe.get(a,z);ev=[];imm={};i=0
    while i<len(b):
        r=a+i
        if i+5<=len(b) and b[i]==0xE8:
            ev.append({"rva":r,"kind":"CALL","target":(r+5+s32(b,i+1))&0xffffffff});i+=5;continue
        if i+10<=len(b) and b[i]==0x48 and 0xB8<=b[i+1]<=0xBF:
            reg=REG[b[i+1]-0xB8];q=u64(b,i+2);e={"rva":r,"kind":"IMM","reg":reg,"double":fd(q)};ev.append(e);imm[reg]=e;i+=10;continue
        if i+7<=len(b) and b[i]==0x48 and b[i+1] in (0x89,0x8B,0x8D):
            m=b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7
            if mod==2 and rm==5:
                reg=REG[rr];disp=s32(b,i+3)
                if b[i+1]==0x89:
                    e={"rva":r,"kind":"STORE","disp":disp,"reg":reg};p=imm.get(reg)
                    if p and 0<=r-p["rva"]<=0x60:e["double"]=p["double"]
                    ev.append(e)
                elif b[i+1]==0x8B:ev.append({"rva":r,"kind":"LOAD","disp":disp,"reg":reg})
                else:ev.append({"rva":r,"kind":"LEA","disp":disp,"reg":reg})
                i+=7;continue
        i+=1
    return ev

def near(ev,call,disp):
    x=[e for e in ev if e["kind"]=="STORE" and e.get("disp")==disp and e.get("double") is not None and e["rva"]<call and call-e["rva"]<=0x140]
    return x[-1]["double"] if x else None

def extract(pe,preps):
    rows=[]
    for n,si in enumerate(PRIMARY):
        a=preps[si];z=preps[si+2] if si+2<len(preps) else FE;ev=scan(pe,a,z)
        tc=[e for e in ev if e["kind"]=="CALL" and e["target"]==TARGET]
        loc=defaultdict(list)
        for e in ev:
            if e["kind"]=="STORE" and e.get("double") is not None:loc[f"0x{e['disp']:X}"].append(e["double"])
        loc={k:uniq(v) for k,v in loc.items()}
        rows.append({"candidate_ordinal":n,"segment_index":si,"known_name":KNOWN.get(si),"begin":a,"end":z,"target_payload_values":[near(ev,c["rva"],0x1D0) for c in tc],"canonical_0x1D0":loc.get("0x1D0",[]),"aux_0x100":loc.get("0x100",[]),"local_numeric_values":loc})
    return rows

def abs_switch(pe,rva):
    f=pe.pdata(rva)
    if not f:return {"found":False}
    a,z=f["begin"],f["end"];b=pe.get(a,z);cand=[]
    for o in range(max(0,len(b)-63)):
        vals=[u32(b,o+4*i) for i in range(16)]
        if all(a<=v<z for v in vals):cand.append({"table_rva":a+o,"table_rva_hex":f"0x{a+o:X}","entries":vals,"distinct_targets":len(set(vals))})
    cand.sort(key=lambda x:(x["distinct_targets"]<=1,-x["table_rva"]))
    t=cand[0] if cand else None
    cases=[] if not t else [{"index":i,"target":v,"target_hex":f"0x{v:X}"} for i,v in enumerate(t["entries"])]
    return {"found":True,"function":{**f,"begin_hex":f"0x{a:X}","end_hex":f"0x{z:X}"},"jump_table":t,"cases":cases,"case_target_frequency":[{"target":x,"target_hex":f"0x{x:X}","count":c} for x,c in Counter(v["target"] for v in cases).most_common()]}

def fn(pe,rva):
    f=pe.pdata(rva)
    if not f:return {"bounds_found":False}
    a,z=f["begin"],f["end"];b=pe.get(a,z);cs=[];i=0
    while i+5<=len(b):
        if b[i]==0xE8:
            r=a+i;t=(r+5+s32(b,i+1))&0xffffffff;cs.append({"rva":r,"target":t,"target_hex":f"0x{t:X}"});i+=5
        else:i+=1
    return {"bounds_found":True,"function":{**f,"begin_hex":f"0x{a:X}","end_hex":f"0x{z:X}"},"direct_calls":cs,"direct_call_frequency":[{"target":t,"target_hex":f"0x{t:X}","count":c} for t,c in Counter(x["target"] for x in cs).most_common()],"raw":b.hex(" ")}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("hero_siege_dir");q=ap.parse_args();root=Path(q.hero_siege_dir).resolve();exe=choose(root);D=desk();out=D/"hero_siege_master";zp=D/"hero_siege_master.zip"
    if out.exists():shutil.rmtree(out)
    out.mkdir();pe=PE(exe);cs,by=calls(pe,FB,FE);preps=by[PREP];rows=extract(pe,preps)
    groups=defaultdict(list)
    for r in rows:groups[tuple(r["canonical_0x1D0"])].append(r["candidate_ordinal"])
    coll=[{"sequence":list(k),"ordinals":v} for k,v in groups.items() if len(v)>1];val=[]
    for r in rows:
        if r["known_name"]:
            sub,idv=EXPECT[r["known_name"]];p=[x for x in r["target_payload_values"] if x is not None];val.append({"name":r["known_name"],"overall_ok":subseq(p,sub) and idv in r["aux_0x100"]})
    sw1=abs_switch(pe,HELPER);sw2=abs_switch(pe,INNER);f1=fn(pe,HELPER);f2=fn(pe,INNER)
    summary={"version":VERSION,"exe_sha256":sha(exe),"primary_candidate_count":len(rows),"canonical_0x1D0":{"coverage":sum(bool(r["canonical_0x1D0"]) for r in rows),"distinct":len(groups),"collision_count":len(coll)},"known_validation":val,"helper_switch":{"jump_table":sw1.get("jump_table"),"case_target_frequency":sw1.get("case_target_frequency")},"inner_switch":{"jump_table":sw2.get("jump_table"),"case_target_frequency":sw2.get("case_target_frequency")},"helper_calls":f1.get("direct_call_frequency"),"inner_calls":f2.get("direct_call_frequency")}
    for name,obj in [("master_summary.json",summary),("canonical_records.json",rows),("canonical_record_collisions.json",coll),("consumer_helper_0xC566890_switch.json",sw1),("consumer_inner_0xC534390_switch.json",sw2),("consumer_helper_0xC566890_body.json",f1),("consumer_inner_0xC534390.json",f2)]:
        (out/name).write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding="utf-8")
    with (out/"primary_blocks.csv").open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.writer(f);w.writerow(["ordinal","segment","known","0x1D0","0x100","TARGET"])
        for r in rows:w.writerow([r["candidate_ordinal"],r["segment_index"],r["known_name"] or "",json.dumps(r["canonical_0x1D0"]),json.dumps(r["aux_0x100"]),json.dumps(r["target_payload_values"])])
    diag=[f"Hero Siege Master {VERSION}",f"Primary blocks: {len(rows)}",f"Canonical 0x1D0: {len(groups)} distinct / {len(coll)} collisions","0xC566890 switch: "+repr(sw1.get("case_target_frequency")),"0xC534390 switch: "+repr(sw2.get("case_target_frequency")),"Validation:"]+[f"  {v['name']}: {'OK' if v['overall_ok'] else 'CHECK'}" for v in val]
    (out/"diagnostics.txt").write_text("\n".join(diag),encoding="utf-8")
    if zp.exists():zp.unlink()
    with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:
        for p in out.rglob("*"):
            if p.is_file():z.write(p,p.relative_to(out))
    print("\n".join(diag));print("ZIP:",zp)
if __name__=="__main__":main()
