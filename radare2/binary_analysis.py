"""
Automated Binary Analysis using r2pipe + radare2
Extracts functions, strings, imports, and detects security mitigations.
Author: samsonram54
"""

import r2pipe
import json
import sys
import os
from datetime import datetime

def analyze_binary(binary_path: str):
    if not os.path.exists(binary_path):
        print(f"[!] File not found: {binary_path}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(" AI SECURITY LAB — Binary Analysis Report")
    print(f" Target    : {binary_path}")
    print(f" Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    r2 = r2pipe.open(binary_path, flags=["-2"])
    r2.cmd("aaa")  # full analysis

    # File info
    info = r2.cmdj("ij")
    print("[*] File Info:")
    if info and "bin" in info:
        b = info["bin"]
        print(f"    Format   : {b.get('bintype', 'unknown')}")
        print(f"    Arch     : {b.get('arch', 'unknown')}")
        print(f"    Bits     : {b.get('bits', 'unknown')}")
        print(f"    OS       : {b.get('os', 'unknown')}")
        print(f"    Stripped : {b.get('stripped', 'unknown')}")

    # Security mitigations
    print("\n[*] Security Mitigations (checksec):")
    checksec = r2.cmdj("iJj") or {}
    mitigations = {
        "canary":  checksec.get("canary", False),
        "nx":      checksec.get("nx", False),
        "pic":     checksec.get("pic", False),
        "relocs":  checksec.get("relocs", False),
    }
    for k, v in mitigations.items():
        status = "✅ Enabled" if v else "⚠️  Disabled"
        print(f"    {k.upper():<10}: {status}")

    # Functions list
    functions = r2.cmdj("aflj") or []
    print(f"\n[*] Functions Found: {len(functions)}")
    for fn in functions[:15]:
        print(f"    0x{fn['offset']:08x}  {fn.get('name', '?'):<40} size={fn.get('size', 0)}")
    if len(functions) > 15:
        print(f"    ... and {len(functions) - 15} more")

    # Interesting strings
    strings = r2.cmdj("izj") or []
    keywords = ["password", "token", "secret", "admin", "key", "auth", "flag", "hack"]
    interesting = [s for s in strings if any(k in s.get("string", "").lower() for k in keywords)]
    print(f"\n[*] Interesting Strings ({len(interesting)} found):")
    for s in interesting[:20]:
        print(f"    0x{s['vaddr']:08x}  {s['string']}")

    # Imports
    imports = r2.cmdj("iij") or []
    dangerous = ["system", "exec", "popen", "gets", "strcpy", "sprintf", "scanf"]
    risky_imports = [i for i in imports if i.get("name", "").lower() in dangerous]
    print(f"\n[*] Dangerous Imports ({len(risky_imports)} found):")
    for imp in risky_imports:
        print(f"    ⚠️  {imp.get('name')} @ {imp.get('plt', 'N/A')}")

    r2.quit()

    report = {
        "binary": binary_path,
        "timestamp": datetime.now().isoformat(),
        "info": info,
        "mitigations": mitigations,
        "function_count": len(functions),
        "interesting_strings": interesting,
        "risky_imports": risky_imports,
    }
    report_path = f"radare2/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Report saved to: {report_path}\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
    analyze_binary(target)