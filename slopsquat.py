#!/usr/bin/env python3
"""
Slopsquat Guard (slopsquat.py)
Defends programmers against AI Package Hallucination Attacks (Slopsquatting),
Typosquatting, and Malicious npm/PyPI lifecycle install hooks.
Queries live npm Registry & PyPI JSON API with zero external dependencies.
Author: Wallison Araujo (@WallisonWS) | License: MIT
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


POPULAR_PACKAGES = {
    "npm": ["react", "next", "express", "lodash", "axios", "typescript", "tailwindcss", "zod", "prisma", "dotenv", "chalk", "vite"],
    "pypi": ["requests", "fastapi", "django", "flask", "numpy", "pandas", "pydantic", "uvicorn", "boto3", "cryptography", "pytest"],
}

DANGEROUS_HOOK_RX = re.compile(r"(?i)(?:curl\s+|wget\s+|powershell|bash\s+-c|eval\(|atob\(|process\.env|child_process|/dev/tcp/|nc\s+-e|base64)")


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def check_registry(ecosystem: str, pkg: str) -> Dict[str, Any]:
    url = f"https://registry.npmjs.org/{pkg}" if ecosystem == "npm" else f"https://pypi.org/pypi/{pkg}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "Slopsquat-Guard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if ecosystem == "npm":
                versions = len(data.get("versions", {}))
                return {"exists": True, "versions_count": versions, "created": data.get("time", {}).get("created")}
            releases = len(data.get("releases", {}))
            return {"exists": True, "versions_count": releases, "author": data.get("info", {}).get("author")}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"exists": False, "alert": "UNREGISTERED_HALLUCINATION_RISK (Target for Slopsquatting!)"}
        return {"exists": None, "error": f"HTTP {e.code}"}
    except Exception as exc:
        return {"exists": None, "error": str(exc)}


def audit_package_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    deps = list({**data.get("dependencies", {}), **data.get("devDependencies", {})}.keys())
    scripts = data.get("scripts", {})
    alerts: List[Dict[str, Any]] = []

    for hook in ("preinstall", "install", "postinstall", "prepare"):
        cmd = scripts.get(hook)
        if cmd and DANGEROUS_HOOK_RX.search(cmd):
            alerts.append({"type": "Malicious Lifecycle Hook", "severity": "CRITICAL", "hook": hook, "command": cmd})

    results = []
    for pkg in deps:
        typo = [p for p in POPULAR_PACKAGES["npm"] if pkg != p and 1 <= levenshtein(pkg, p) <= 2]
        reg = check_registry("npm", pkg)
        if typo:
            alerts.append({"type": "Typosquatting Near Popular Package", "severity": "HIGH", "package": pkg, "similar_to": typo})
        if reg.get("exists") is False:
            alerts.append({"type": "Hallucinated / Unregistered Package (Slopsquatting Vector)", "severity": "CRITICAL", "package": pkg})
        results.append({"package": pkg, "typo_matches": typo, "registry": reg})

    return {"file": str(path), "packages_checked": len(deps), "alerts": alerts, "details": results}


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="slopsquat", description="AI Package Hallucination (Slopsquatting) & Lifecycle Hook Auditor")
    parser.add_argument("target", help="Path to package.json OR single package name")
    parser.add_argument("--ecosystem", choices=["npm", "pypi"], default="npm")
    args = parser.parse_args(argv)
    p = Path(args.target)
    if p.is_file() and p.name == "package.json":
        print(json.dumps(audit_package_json(p), indent=2))
    else:
        typo = [k for k in POPULAR_PACKAGES[args.ecosystem] if args.target != k and 1 <= levenshtein(args.target, k) <= 2]
        print(json.dumps({"package": args.target, "ecosystem": args.ecosystem, "typo_matches": typo, "registry": check_registry(args.ecosystem, args.target)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
