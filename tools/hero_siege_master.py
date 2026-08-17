#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
import argparse,csv,hashlib,json,math,shutil,struct,time,zipfile
from collections import Counter,defaultdict

MASTER_VERSION="permanent-master-v12.1-standalone"
FUNC={"name":"DefineItemUniqueWeaponsSword","begin":0x05856C00,"end":0x0588E599,"prep":0x0C54E830,"primary":list(range(2,71,2)),"known":{8:"Godfather",20:"Thor",40:"Genji"}}
TARGET=0x0C579810
FIELD_SETTER=0x0C566890
KNOWN={"Godfather":([13315,1424,11],1855),"Thor":([8860,1424,83],16155),"Genji":([8866,1424,78],29455)}
REG=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI"]
XREG=["R8","R9","R10","R11","R12","R13","R14","R15"]

def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def s32(b,o):return struct.unpack_from('<i',b,o)[0]
def finite(q):
    try:
        x=struct.unpack('<d',struct.pack('<Q',q))[0]
        if not math.isfinite(x) or abs(x)>1e12:return None
        return int(round(x)) if abs(x-round(x))<1e-10 else x
    except:return None

def desktop():
    for p in (Path.home()/"Desktop",Path.home()/"OneDrive"/"Desktop"):
        if p.exists():return p
    return Path.cwd()
def choose_exe(root):
    for p in (root/'Hero_Siege.exe',root/'bin'/'Hero_Siege.exe',root/'Hero Siege.exe',root/'bin'/'Hero Siege.exe'):
        if p.exists():return p
    xs=list(root.rglob('Hero_Siege.exe'))
    if not xs:raise SystemExit('Hero_Siege.exe not found')
    return xs[0]
def sha256(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1<<20),b''):h.update(c)
    return h.hexdigest()
def savej(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding='utf-8')

class PE:
    def __init__(self,p):self.path=p;self.data=p.read_bytes();self.sections=[];self._parse()
    def _parse(self):
        d=self.data;pe=u32(d,0x3C);coff=pe+4;n=u16(d,coff+2);optsz=u16(d,coff+16);opt=coff+20;self.image_base=u64(d,opt+24);sec=opt+optsz
        for i in range(n):
            o=sec+i*40;self.sections.append({'name':d[o:o+8].split(b'\0',1)[0].decode('ascii','ignore'),'vs':u32(d,o+8),'rva':u32(d,o+12),'rs':u32(d,o+16),'rp':u32(d,o+20)})
    def off(self,r):
        for s in self.sections:
            if s['rva']<=r<s['rva']+max(s['vs'],s['rs']):
                q=r-s['rva']
                if q<s['rs']:return s['rp']+q
    def get(self,a,z):
        o=self.off(a);return b'' if o is None else self.data[o:o+z-a]
    def slot(self,r,n=16):
        o=self.off(r)
        if o is None:return None
        b=self.data[o:o+n]
        return {'rva':r,'rva_hex':f'0x{r:X}','raw':b.hex(' '),'u32':u32(b,0) if len(b)>=4 else None,'u64':u64(b,0) if len(b)>=8 else None}

def calls(pe,a,z):
    b=pe.get(a,z);out=[];i=0
    while i+5<=len(b):
        if b[i]==0xE8:
            r=a+i;out.append({'rva':r,'target':(r+5+s32(b,i+1))&0xffffffff});i+=5
        else:i+=1
    return out

def events(pe,a,z):
    b=pe.get(a,z);out=[];imm={};i=0
    while i<len(b):
        r=a+i
        if i+5<=len(b) and b[i]==0xE8:
            out.append({'rva':r,'kind':'CALL','target':(r+5+s32(b,i+1))&0xffffffff});i+=5;continue
        if i+10<=len(b) and b[i]==0x48 and 0xB8<=b[i+1]<=0xBF:
            reg=REG[b[i+1]-0xB8];q=u64(b,i+2);e={'rva':r,'kind':'IMM64','dst':reg,'qword':q,'double':finite(q)};out.append(e);imm[reg]=e;i+=10;continue
        if i+7<=len(b) and b[i]==0x48 and b[i+1] in (0x89,0x8B,0x8D):
            m=b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7
            if mod==2 and rm==5:
                reg=REG[rr];disp=s32(b,i+3)
                if b[i+1]==0x89:
                    e={'rva':r,'kind':'STORE_RBP','disp':disp,'src':reg};p=imm.get(reg)
                    if p and 0<=r-p['rva']<=0x60:e.update({'source_rva':p['rva'],'qword':p['qword'],'double':p['double']})
                    out.append(e)
                elif b[i+1]==0x8B:out.append({'rva':r,'kind':'LOAD_RBP','disp':disp,'dst':reg})
                else:out.append({'rva':r,'kind':'LEA_RBP','disp':disp,'dst':reg})
                i+=7;continue
        if i+3<=len(b) and 0x40<=b[i]<=0x4F and b[i+1] in (0x89,0x8B,0x8D):
            rex,op,m=b[i],b[i+1],b[i+2];mod=(m>>6)&3;rr=(m>>3)&7;rm=m&7;reg=(XREG if rex&4 else REG)[rr];rmreg=(XREG if rex&1 else REG)[rm]
            if mod==3 and op in (0x89,0x8B):
                dst,src=(rmreg,reg) if op==0x89 else (reg,rmreg);out.append({'rva':r,'kind':'MOV_REG','dst':dst,'src':src});i+=3;continue
            if mod==2 and rm==5 and i+7<=len(b):
                out.append({'rva':r,'kind':'LOAD_RBP' if op==0x8B else 'LEA_RBP','dst':reg,'disp':s32(b,i+3)});i+=7;continue
        i+=1
    return out

def nearest_store(ev,r,disp,lookback=0x300):
    x=[e for e in ev if e['kind']=='STORE_RBP' and e.get('disp')==disp and e.get('double') is not None and e['rva']<r and r-e['rva']<=lookback]
    return x[-1] if x else None
def lastreg(ev,reg,r):
    x=[e for e in ev if e.get('dst')==reg and e['rva']<r];return x[-1] if x else None

def selector_loads(pe,begin,r,window=0x120):
    a=max(begin,r-window);b=pe.get(a,r);out=[]
    for i in range(0,max(0,len(b)-5)):
        if b[i:i+2]==b'\x8B\x15':
            q=a+i;t=(q+6+s32(b,i+2))&0xffffffff;out.append({'rva':q,'rva_hex':f'0x{q:X}','slot_rva':t,'slot_rva_hex':f'0x{t:X}','slot':pe.slot(t)})
    return out

def r8_imm(pe,begin,r,window=0x80):
    a=max(begin,r-window);b=pe.get(a,r);out=[]
    # Exact MOV R8D,imm32. Include the final possible 6-byte instruction at len-6.
    for i in range(0,max(0,len(b)-5)):
        if b[i:i+2]==b'\x41\xB8':
            out.append({'rva':a+i,'rva_hex':f'0x{a+i:X}','imm':u32(b,i+2),'imm_hex':f'0x{u32(b,i+2):X}'})
    return out[-1] if out else None

def virtual_source(pe,begin,r,window=0x180):
    a=max(begin,r-window);b=pe.get(a,r);hits=[]
    for i in range(0,max(0,len(b)-2)):
        if b[i:i+3]!=b'\xFF\x50\x08':continue
        aft=b[i+3:min(len(b),i+24)];m=aft.find(b'\x48\x89\xC7')
        if m<0:continue
        sels=[]
        for j in range(max(0,i-48),i):
            if b[j:j+2]==b'\x8B\x15':
                q=a+j;t=(q+6+s32(b,j+2))&0xffffffff;sels.append({'rva':q,'rva_hex':f'0x{q:X}','slot_rva':t,'slot_rva_hex':f'0x{t:X}','slot':pe.slot(t)})
        q=a+i;hits.append({'call_rva':q,'call_rva_hex':f'0x{q:X}','return_to_rdi_rva':q+3+m,'selector':sels[-1] if sels else None})
    return hits[-1] if hits else None

def subseq(seq,sub):
    j=0
    for x in seq:
        if j<len(sub) and x==sub[j]:j+=1
    return j==len(sub)

def extract(pe):
    allcalls=calls(pe,FUNC['begin'],FUNC['end']);preps=[c['rva'] for c in allcalls if c['target']==FUNC['prep']];rows=[];assign=[]
    for ordinal,segidx in enumerate(FUNC['primary']):
        begin=preps[segidx];end=preps[segidx+2] if segidx+2<len(preps) else FUNC['end'];ev=events(pe,begin,end);bc=[e for e in ev if e['kind']=='CALL'];tc=[e for e in bc if e['target']==TARGET];sc=[e for e in bc if e['target']==FIELD_SETTER]
        payload=[]
        for c in tc:
            q=nearest_store(ev,c['rva'],0x1D0,0x180);payload.append(q['double'] if q else None)
        nums=defaultdict(list)
        for e in ev:
            if e['kind']=='STORE_RBP' and e.get('double') is not None:nums[e['disp']].append(e['double'])
        l1=list(dict.fromkeys(nums.get(0x1D0,[])));l0=list(dict.fromkeys(nums.get(0x100,[])));name=FUNC['known'].get(segidx)
        rows.append({'function':FUNC['name'],'candidate_ordinal':ordinal,'segment_index':segidx,'known_name':name,'begin':begin,'end':end,'size':end-begin,'call_count':len(bc),'setter_call_count':len(sc),'target_payloads':payload,'canonical_0x1D0':l1,'value_0x100':l0})
        for si,c in enumerate(sc):
            r=c['rva'];p=nearest_store(ev,r,0x100);sels=selector_loads(pe,begin,r);r9=lastreg(ev,'R9',r)
            assign.append({'function':FUNC['name'],'candidate_ordinal':ordinal,'segment_index':segidx,'known_name':name,'setter_index':si,'setter_call_rva':r,'setter_call_rva_hex':f'0x{r:X}','value':p.get('double') if p else None,'value_store_rva':p.get('rva') if p else None,'value_store_delta':r-p['rva'] if p else None,'r9_points_to_0x100':bool(r9 and r9.get('kind')=='LEA_RBP' and r9.get('disp')==0x100),'helper_selector':sels[-1] if sels else None,'virtual_source':virtual_source(pe,begin,r),'r8d':r8_imm(pe,begin,r),'canonical_0x1D0':l1})
    return allcalls,preps,rows,assign

def summarize(a):
    pair=Counter();hs=Counter();vs=Counter();r8=Counter();vals=[]
    for x in a:
        h=(x.get('helper_selector') or {}).get('slot_rva_hex');v=((x.get('virtual_source') or {}).get('selector') or {}).get('slot_rva_hex');q=(x.get('r8d') or {}).get('imm_hex');pair[(v,h)]+=1;hs[h]+=1;vs[v]+=1;r8[q]+=1
        if x.get('value') is not None:vals.append(x['value'])
    return {'assignment_count':len(a),'value_count':len(vals),'distinct_values':len(set(vals)),'selector_pairs':[{'virtual_selector':v,'helper_selector':h,'count':c} for (v,h),c in pair.most_common()],'helper_selector_frequency':[{'slot':k,'count':v} for k,v in hs.most_common()],'virtual_selector_frequency':[{'slot':k,'count':v} for k,v in vs.most_common()],'r8d_frequency':[{'value':k,'count':v} for k,v in r8.most_common()]}

def validate(rows):
    out=[]
    for r in rows:
        if not r['known_name']:continue
        sub,val=KNOWN[r['known_name']];x={'name':r['known_name'],'candidate_ordinal':r['candidate_ordinal'],'segment_index':r['segment_index'],'target_subsequence_ok':subseq(r['target_payloads'],sub),'value_0x100_ok':val in r['value_0x100']};x['overall_ok']=x['target_subsequence_ok'] and x['value_0x100_ok'];out.append(x)
    return out

def write_csv(path,rows):
    cols=['function','candidate_ordinal','segment_index','known_name','begin','end','size','call_count','setter_call_count','target_payloads','canonical_0x1D0','value_0x100']
    with path.open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=cols);w.writeheader()
        for r in rows:
            q=dict(r);q['begin']=f"0x{r['begin']:X}";q['end']=f"0x{r['end']:X}";q['known_name']=q['known_name'] or ''
            for k in ('target_payloads','canonical_0x1D0','value_0x100'):q[k]=json.dumps(q[k],ensure_ascii=False)
            w.writerow(q)
def zipdir(src,zp):
    if zp.exists():zp.unlink()
    with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
        for p in src.rglob('*'):
            if p.is_file():z.write(p,p.relative_to(src))

def main():
    t=time.time();ap=argparse.ArgumentParser();ap.add_argument('hero_siege_dir');a=ap.parse_args();root=Path(a.hero_siege_dir).resolve();exe=choose_exe(root);pe=PE(exe);desk=desktop();out=desk/'hero_siege_master';zp=desk/'hero_siege_master.zip'
    if out.exists():shutil.rmtree(out)
    out.mkdir(parents=True)
    cs,preps,rows,assign=extract(pe);sm=summarize(assign);known=validate(rows);canon=[r['canonical_0x1D0'] for r in rows];distinct=len({json.dumps(x) for x in canon})
    summary={'version':MASTER_VERSION,'architecture':'standalone-no-wrapper','exe':str(exe),'exe_sha256':sha256(exe),'functions_scanned':[{'function':FUNC['name'],'begin':FUNC['begin'],'end':FUNC['end'],'direct_call_count':len(cs),'prep_count':len(preps),'segment_count':len(preps)}],'primary_candidate_count':len(rows),'assignment_summary':sm,'canonical_0x1D0':{'coverage_full':len(canon)==35 and all(bool(x) for x in canon),'distinct':distinct,'collisions':len(canon)-distinct},'known_validation':known,'regression_checks':{'r8d_all_80000000':sm['r8d_frequency']==[{'value':'0x80000000','count':40}],'expected_assignment_count':len(assign)==40},'next_design_goal':'auto-discover and generalize across all DefineItem* functions'}
    savej(out/'master_summary.json',summary);savej(out/'item_records.json',rows);savej(out/'property_assignments.json',assign);savej(out/'selector_matrix.json',sm);savej(out/'known_validation.json',known);write_csv(out/'primary_blocks.csv',rows)
    (out/'diagnostics.txt').write_text('\n'.join([f'MASTER_VERSION={MASTER_VERSION}','ARCHITECTURE=standalone-no-wrapper',f'PRIMARY_CANDIDATES={len(rows)}',f'ASSIGNMENTS={len(assign)}',f'R8D={sm["r8d_frequency"]}',f'KNOWN={known}',f'SELECTORS={sm}'])+'\n',encoding='utf-8')
    zipdir(out,zp);print(f'Done: {zp}');print(f'Master: {MASTER_VERSION}');print('Architecture: standalone-no-wrapper');print(f'Elapsed: {time.time()-t:.1f}s')
if __name__=='__main__':main()
