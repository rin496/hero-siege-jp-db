#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
import argparse, ctypes, hashlib, json, os, shutil, struct, subprocess, sys, time, zipfile
from ctypes import wintypes

MASTER_VERSION="permanent-master-v24.3-auto-elevate-runtime-probe"
EXPECTED_SHA="92e323592aeee63fcbdc80e9a1efe1ae7c0d12ced9fb3961b1843d2bf2f376f4"
ROOT_RVA=0x11CD4BB8
DESCRIPTORS={
 "itemAmountUnique":0x119A80D8,
 "itemArgument":0x119A80E8,
 "itemRepoRuneword":0x119A8718,
 "itemRepoUnique":0x119A8728,
 "itemRequiredText":0x119A8738,
 "gml_Script_GetUniqueRepoStruct":0x119F9B98,
 "gml_Script_GetRunewordRepoStruct":0x119F9BA8,
 "gml_Script_GetHeroicItem":0x119F9BB8,
}
PROCESS_NAME="Hero_Siege.exe"

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
 for p in (root/"Hero_Siege.exe",root/"bin"/"Hero_Siege.exe"):
  if p.exists(): return p
 xs=list(root.rglob("Hero_Siege.exe"))
 if not xs: raise SystemExit("Hero_Siege.exe not found")
 return xs[0]

def savej(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding="utf-8")
def hx(v): return None if v is None else f"0x{v:X}"

class PROCESSENTRY32W(ctypes.Structure):
 _fields_=[("dwSize",wintypes.DWORD),("cntUsage",wintypes.DWORD),("th32ProcessID",wintypes.DWORD),("th32DefaultHeapID",ctypes.c_size_t),("th32ModuleID",wintypes.DWORD),("cntThreads",wintypes.DWORD),("th32ParentProcessID",wintypes.DWORD),("pcPriClassBase",ctypes.c_long),("dwFlags",wintypes.DWORD),("szExeFile",wintypes.WCHAR*260)]
class MODULEENTRY32W(ctypes.Structure):
 _fields_=[("dwSize",wintypes.DWORD),("th32ModuleID",wintypes.DWORD),("th32ProcessID",wintypes.DWORD),("GlblcntUsage",wintypes.DWORD),("ProccntUsage",wintypes.DWORD),("modBaseAddr",ctypes.POINTER(ctypes.c_byte)),("modBaseSize",wintypes.DWORD),("hModule",wintypes.HMODULE),("szModule",wintypes.WCHAR*256),("szExePath",wintypes.WCHAR*260)]

def kernel32():
 k=ctypes.WinDLL("kernel32",use_last_error=True)
 k.CreateToolhelp32Snapshot.argtypes=[wintypes.DWORD,wintypes.DWORD];k.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
 k.Process32FirstW.argtypes=[wintypes.HANDLE,ctypes.POINTER(PROCESSENTRY32W)];k.Process32FirstW.restype=wintypes.BOOL
 k.Process32NextW.argtypes=[wintypes.HANDLE,ctypes.POINTER(PROCESSENTRY32W)];k.Process32NextW.restype=wintypes.BOOL
 k.Module32FirstW.argtypes=[wintypes.HANDLE,ctypes.POINTER(MODULEENTRY32W)];k.Module32FirstW.restype=wintypes.BOOL
 k.Module32NextW.argtypes=[wintypes.HANDLE,ctypes.POINTER(MODULEENTRY32W)];k.Module32NextW.restype=wintypes.BOOL
 k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
 k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];k.OpenProcess.restype=wintypes.HANDLE
 k.ReadProcessMemory.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)];k.ReadProcessMemory.restype=wintypes.BOOL
 return k

def find_process():
 k=kernel32();snap=k.CreateToolhelp32Snapshot(0x2,0)
 if not snap or ctypes.c_void_p(snap).value==ctypes.c_void_p(-1).value:return None
 try:
  e=PROCESSENTRY32W();e.dwSize=ctypes.sizeof(e);ok=k.Process32FirstW(snap,ctypes.byref(e))
  while ok:
   if e.szExeFile.lower()==PROCESS_NAME.lower():return int(e.th32ProcessID)
   ok=k.Process32NextW(snap,ctypes.byref(e))
 finally:k.CloseHandle(snap)
 return None

def module_base(pid):
 k=kernel32();snap=k.CreateToolhelp32Snapshot(0x8|0x10,pid)
 if not snap or ctypes.c_void_p(snap).value==ctypes.c_void_p(-1).value:
  print(f"Module snapshot failed: WinError {ctypes.get_last_error()}",flush=True);return None
 try:
  m=MODULEENTRY32W();m.dwSize=ctypes.sizeof(m);ok=k.Module32FirstW(snap,ctypes.byref(m))
  while ok:
   if m.szModule.lower()==PROCESS_NAME.lower():return ctypes.cast(m.modBaseAddr,ctypes.c_void_p).value,int(m.modBaseSize),m.szExePath
   ok=k.Module32NextW(snap,ctypes.byref(m))
 finally:k.CloseHandle(snap)
 return None

def module_base_psapi(pid):
 k=kernel32();h=k.OpenProcess(0x0400|0x0010,False,pid)
 if not h:return None
 try:
  psapi=ctypes.WinDLL("psapi",use_last_error=True)
  psapi.EnumProcessModulesEx.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.HMODULE),wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.DWORD];psapi.EnumProcessModulesEx.restype=wintypes.BOOL
  psapi.GetModuleBaseNameW.argtypes=[wintypes.HANDLE,wintypes.HMODULE,wintypes.LPWSTR,wintypes.DWORD];psapi.GetModuleBaseNameW.restype=wintypes.DWORD
  psapi.GetModuleFileNameExW.argtypes=[wintypes.HANDLE,wintypes.HMODULE,wintypes.LPWSTR,wintypes.DWORD];psapi.GetModuleFileNameExW.restype=wintypes.DWORD
  class MODULEINFO(ctypes.Structure):_fields_=[("lpBaseOfDll",ctypes.c_void_p),("SizeOfImage",wintypes.DWORD),("EntryPoint",ctypes.c_void_p)]
  psapi.GetModuleInformation.argtypes=[wintypes.HANDLE,wintypes.HMODULE,ctypes.POINTER(MODULEINFO),wintypes.DWORD];psapi.GetModuleInformation.restype=wintypes.BOOL
  arr=(wintypes.HMODULE*1024)();needed=wintypes.DWORD()
  if not psapi.EnumProcessModulesEx(h,arr,ctypes.sizeof(arr),ctypes.byref(needed),0x03):return None
  count=min(needed.value//ctypes.sizeof(wintypes.HMODULE),len(arr))
  for i in range(count):
   mod=arr[i];namebuf=ctypes.create_unicode_buffer(260)
   if not psapi.GetModuleBaseNameW(h,mod,namebuf,len(namebuf)) or namebuf.value.lower()!=PROCESS_NAME.lower():continue
   info=MODULEINFO()
   if not psapi.GetModuleInformation(h,mod,ctypes.byref(info),ctypes.sizeof(info)):continue
   pathbuf=ctypes.create_unicode_buffer(1024);psapi.GetModuleFileNameExW(h,mod,pathbuf,len(pathbuf))
   return int(info.lpBaseOfDll),int(info.SizeOfImage),pathbuf.value
 finally:k.CloseHandle(h)
 return None

class Reader:
 def __init__(self,pid):
  self.k=kernel32();self.h=self.k.OpenProcess(0x10|0x400,False,pid)
  if not self.h:raise OSError(ctypes.get_last_error(),"OpenProcess failed")
 def close(self):
  if self.h:self.k.CloseHandle(self.h);self.h=None
 def read(self,addr,n):
  buf=(ctypes.c_ubyte*n)();got=ctypes.c_size_t();ok=self.k.ReadProcessMemory(self.h,ctypes.c_void_p(addr),buf,n,ctypes.byref(got))
  if not ok or got.value==0:return None
  return bytes(buf[:got.value])
 def u64(self,addr):
  b=self.read(addr,8);return struct.unpack("<Q",b)[0] if b and len(b)>=8 else None

def ptr_class(v,base,size):
 if not v:return "null"
 if base<=v<base+size:return "module"
 if 0x10000<=v<=0x00007FFFFFFFFFFF:return "user_pointer_candidate"
 return "scalar_or_invalid"

def pointer_samples(reader,blob,base,size,start_addr,max_samples=64):
 out=[]
 for off in range(0,len(blob)-7,8):
  v=struct.unpack_from("<Q",blob,off)[0];cls=ptr_class(v,base,size)
  if cls in ("scalar_or_invalid","null"):continue
  sm=reader.read(v,32);out.append({"offset":off,"field_addr_hex":hx(start_addr+off),"value_hex":hx(v),"class":cls,"module_rva_hex":hx(v-base) if cls=="module" else None,"sample_hex":sm.hex(" ") if sm else None})
  if len(out)>=max_samples:break
 return out

def copy_file_to_clipboard(path):
 if os.name!="nt":return False,"clipboard file copy is Windows-only"
 env=os.environ.copy();env["HS_ZIP_CLIP"]=str(Path(path).resolve())
 ps="Add-Type -AssemblyName System.Windows.Forms;$c=New-Object System.Collections.Specialized.StringCollection;[void]$c.Add($env:HS_ZIP_CLIP);[System.Windows.Forms.Clipboard]::SetFileDropList($c)"
 try:
  p=subprocess.run(["powershell.exe","-NoProfile","-STA","-Command",ps],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15)
  return (True,env["HS_ZIP_CLIP"]) if p.returncode==0 else (False,p.stderr.strip() or p.stdout.strip() or f"PowerShell exit {p.returncode}")
 except Exception as e:return False,repr(e)

def finish_zip_to_clipboard(zp):
 ok,detail=copy_file_to_clipboard(zp)
 print("Clipboard: ZIP file copied. You can paste it directly into ChatGPT." if ok else f"Clipboard: automatic file copy failed: {detail}",flush=True)
 return ok

def is_admin():
 try:return bool(ctypes.windll.shell32.IsUserAnAdmin())
 except Exception:return False

def relaunch_elevated_and_wait(script_path,game_dir):
 env=os.environ.copy();env["HS_MASTER_PY"]=str(Path(script_path).resolve());env["HS_MASTER_EXE"]=str(Path(sys.executable).resolve());env["HS_GAME_DIR"]=str(Path(game_dir).resolve())
 ps="$argList=@($env:HS_MASTER_PY,$env:HS_GAME_DIR);$p=Start-Process -FilePath $env:HS_MASTER_EXE -ArgumentList $argList -Verb RunAs -Wait -PassThru;exit $p.ExitCode"
 try:return int(subprocess.run(["powershell.exe","-NoProfile","-Command",ps],env=env,timeout=300).returncode)
 except subprocess.TimeoutExpired:return 124
 except Exception as e:print("Failed to request elevation:",repr(e),flush=True);return 125

def main():
 if os.name!="nt":raise SystemExit("v24 runtime probe must run on Windows.")
 t=time.time();ap=argparse.ArgumentParser();ap.add_argument("hero_siege_dir");root=Path(ap.parse_args().hero_siege_dir).resolve();exe=choose_exe(root);h=sha256(exe)
 print("EXE SHA256:",h,flush=True)
 if h!=EXPECTED_SHA:raise SystemExit("Hero_Siege.exe changed; refusing v24.3 anchors.")
 d=desktop();out=d/"hero_siege_master";zp=d/"hero_siege_master.zip"
 if out.exists():shutil.rmtree(out)
 out.mkdir(parents=True)
 pid=find_process()
 if pid is None:
  savej(out/"runtime_probe.json",{"version":MASTER_VERSION,"exe_sha256":h,"runtime_status":"game-not-running"})
  if zp.exists():zp.unlink()
  with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:z.write(out/"runtime_probe.json","runtime_probe.json")
  finish_zip_to_clipboard(zp);print("Hero_Siege.exe is not running.",flush=True);return
 mod=module_base(pid)
 if not mod:
  print("Toolhelp module lookup failed; trying PSAPI fallback...",flush=True);mod=module_base_psapi(pid)
 if not mod and not is_admin():
  print("Access is denied. Requesting Administrator permission automatically...",flush=True);print("Please approve the Windows UAC prompt.",flush=True)
  code=relaunch_elevated_and_wait(__file__,root);raise SystemExit(code)
 if not mod:
  savej(out/"runtime_probe.json",{"version":MASTER_VERSION,"exe_sha256":h,"runtime_status":"module-access-denied-even-as-admin","pid":pid,"is_admin":is_admin()})
  if zp.exists():zp.unlink()
  with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:z.write(out/"runtime_probe.json","runtime_probe.json")
  finish_zip_to_clipboard(zp);raise SystemExit(2)
 base,mod_size,mod_path=mod;print("Runtime PID:",pid,flush=True);print("Module base:",hx(base),flush=True);print("Module size:",hx(mod_size),flush=True)
 r=Reader(pid)
 try:
  root_slot=base+ROOT_RVA;root_ptr=r.u64(root_slot);print("Root slot:",hx(root_slot),flush=True);print("Root pointer:",hx(root_ptr),flush=True)
  desc=[]
  for name,rva in DESCRIPTORS.items():
   addr=base+rva;b=r.read(addr,16);rec={"name":name,"rva_hex":hx(rva),"address_hex":hx(addr),"bytes_hex":b.hex(" ") if b else None}
   if b and len(b)>=16:rec["runtime_cache_u64"]=struct.unpack_from("<Q",b,0)[0];rec["runtime_cache_u32"]=struct.unpack_from("<I",b,0)[0];rec["name_pointer_hex"]=hx(struct.unpack_from("<Q",b,8)[0])
   desc.append(rec)
  root_blob=r.read(root_ptr,0x400) if root_ptr else None;root_info={"slot_rva_hex":hx(ROOT_RVA),"slot_address_hex":hx(root_slot),"root_pointer_hex":hx(root_ptr),"root_pointer_class":ptr_class(root_ptr,base,mod_size)}
  if root_blob:
   root_info["root_bytes_hex"]=root_blob.hex(" ");root_info["root_pointer_samples"]=pointer_samples(r,root_blob,base,mod_size,root_ptr,96);vtable=struct.unpack_from("<Q",root_blob,0)[0];root_info["vtable_pointer_hex"]=hx(vtable);root_info["vtable_class"]=ptr_class(vtable,base,mod_size)
   if base<=vtable<base+mod_size:root_info["vtable_rva_hex"]=hx(vtable-base)
   vt=r.read(vtable,0x100) if vtable else None
   if vt:root_info["vtable_bytes_hex"]=vt.hex(" ");root_info["vtable_entries"]=[{"offset":off,"value_hex":hx(struct.unpack_from("<Q",vt,off)[0]),"module_rva_hex":hx(struct.unpack_from("<Q",vt,off)[0]-base) if base<=struct.unpack_from("<Q",vt,off)[0]<base+mod_size else None} for off in range(0,len(vt)-7,8)]
  adj_start=base+ROOT_RVA-0x200;adj=r.read(adj_start,0x400);adj_info={"start_address_hex":hx(adj_start),"start_rva_hex":hx(ROOT_RVA-0x200),"bytes_hex":adj.hex(" ") if adj else None}
  if adj:adj_info["pointer_samples"]=pointer_samples(r,adj,base,mod_size,adj_start,96)
  result={"version":MASTER_VERSION,"exe_sha256":h,"runtime_status":"ok","pid":pid,"module_base_hex":hx(base),"module_size_hex":hx(mod_size),"module_path":mod_path,"root":root_info,"descriptors":desc,"adjacent_globals":adj_info,"mode":"read-only external process memory probe; no injection, no writes"}
  savej(out/"runtime_probe.json",result);savej(out/"runtime_root.json",root_info);savej(out/"runtime_descriptors.json",desc);savej(out/"runtime_adjacent_globals.json",adj_info)
 finally:r.close()
 if zp.exists():zp.unlink()
 with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as z:
  for p in out.rglob("*"):
   if p.is_file():z.write(p,p.relative_to(out))
 finish_zip_to_clipboard(zp);print("Done:",zp);print("Master:",MASTER_VERSION);print("Elapsed: %.1fs"%(time.time()-t))
if __name__=="__main__":main()
