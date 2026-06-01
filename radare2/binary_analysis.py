"""
Binary Analysis Script using r2pipe + radare2
Author: samsonram
"""

import r2pipe
import json
import sys
import os
from datetime import datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "radare2/samples/notepad.exe"

print(f"\n{'='*60}")
print(f" AI SECURITY LAB — Binary Analysis")
print(f" Target    : {TARGET}")
print(f" Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}\n")

r2 = r2pipe.open(TARGET, flags=["-2"])
r2.cmd("aaa")

REPORT = {}

# File info
info = r2.cmdj("ij") or {}
binary_info = info.get("bin", {})
REPORT["file_info"] = binary_info
print("[*] File Info:")
print(f"    Format   : {binary_info.get('bintype', 'unknown')}")
print(f"    Arch     : {binary_info.get('arch', 'unknown')}")
print(f"    Bits     : {binary_info.get('bits', 'unknown')}")
print(f"    OS       : {binary_info.get('os', 'unknown')}")
print(f"    Stripped : {binary_info.get('stripped', 'unknown')}")

# Security — use iI output parsed manually
print("\n[*] Security Mitigations:")
canary = binary_info.get("canary", False)
nx = binary_info.get("nx", False)
pie = binary_info.get("pic", False)
relocs = binary_info.get("relocs", False)
print(f"    CANARY : {'✅ Enabled' if canary else '⚠️  Disabled'}")
print(f"    NX     : {'✅ Enabled' if nx else '⚠️  Disabled'}")
print(f"    PIE    : {'✅ Enabled' if pie else '⚠️  Disabled'}")
print(f"    RELOCS : {'✅ Present' if relocs else '⚠️  None'}")
REPORT["mitigations"] = {"canary": canary, "nx": nx, "pie": pie, "relocs": relocs}

# Functions
funcs = r2.cmdj("aflj") or []
print(f"\n[*] Functions Found: {len(funcs)}")
print("    Top 10 by size:")
sorted_funcs = sorted(funcs, key=lambda x: x.get("size", 0), reverse=True)
for fn in sorted_funcs[:10]:
    name = fn.get("name", "?")[:40]
    size = fn.get("size", 0)
    offset = fn.get("offset", 0)
    print(f"    0x{offset:08x}  {name:<40} size={size}")
REPORT["function_count"] = len(funcs)
REPORT["top_functions"] = [{"name": f.get("name"), "size": f.get("size"), "offset": f.get("offset")} for f in sorted_funcs[:10]]

# Dangerous imports
print("\n[*] Dangerous Imports:")
DANGEROUS = ["strcpy", "strcat", "sprintf", "gets", "system", "exec",
             "WinExec", "ShellExecute", "CreateProcess", "VirtualAlloc",
             "WriteProcessMemory", "LoadLibrary", "GetProcAddress", "URLDownloadToFile"]
imports = r2.cmdj("iij") or []
found_dangerous = [i.get("name","") for i in imports if any(d.lower() in i.get("name","").lower() for d in DANGEROUS)]
for name in found_dangerous:
    print(f"    ⚠️  {name}")
if not found_dangerous:
    print("    None found")
REPORT["dangerous_imports"] = found_dangerous

# Interesting strings
print("\n[*] Interesting Strings:")
KEYWORDS = ["password", "secret", "token", "http", "admin", "key", "auth", "debug"]
strings = r2.cmdj("izzj") or []
found_strings = [s.get("string","") for s in strings if any(k in s.get("string","").lower() for k in KEYWORDS)]
for s in found_strings[:10]:
    print(f"    📌 {s[:80]}")
if not found_strings:
    print("    None found")
REPORT["interesting_strings"] = found_strings[:20]

r2.quit()

# Summary
print(f"\n{'='*60}")
print(" SECURITY SUMMARY")
print(f"{'='*60}")
print(f"    Stack Canary    : {'✅' if canary else '⚠️ '} {'Enabled' if canary else 'Disabled'}")
print(f"    NX (DEP)        : {'✅' if nx else '⚠️ '} {'Enabled' if nx else 'Disabled'}")
print(f"    PIE/ASLR        : {'✅' if pie else '⚠️ '} {'Enabled' if pie else 'Disabled'}")
print(f"    Functions       : {len(funcs)}")
print(f"    Dangerous APIs  : {len(found_dangerous)}")
print(f"    Interesting Str : {len(found_strings)}")

os.makedirs("radare2", exist_ok=True)
report_path = f"radare2/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(report_path, "w") as f:
    json.dump(REPORT, f, indent=2)
print(f"\n[*] Report saved: {report_path}\n")