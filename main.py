#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import os
import re
import json
import yaml
import time
import requests
from typing import Dict, List, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_URL = "https://raw.githubusercontent.com/cinmou/singbox-rules/refs/heads/main/source.yml"
LOCAL_SOURCES_YML = os.path.join(ROOT, "source.yml")
OUT_JSON_DIR = os.path.join(ROOT, "output", "json")

UA = "singbox-rules-builder/1.0"
TIMEOUT = 30

# -------- parsing helpers --------

def _strip_comment(line: str) -> str:
    # remove comments: # ; //
    # keep URLs intact
    line = line.strip()
    if not line:
        return ""
    # handle inline comments cautiously
    for sep in (" #", " ;", " //"):
        idx = line.find(sep)
        if idx != -1:
            line = line[:idx].strip()
    return line.strip()

def parse_clash_or_plain(text: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Return (domain, domain_suffix, ip_cidr)
    Supports:
      - Clash rule provider: payload: [ "DOMAIN-SUFFIX,xx", ... ]
      - Plain list: xx.com / DOMAIN-SUFFIX,xx.com / IP-CIDR,1.2.3.0/24
    Ignores unsupported rules silently.
    """
    domains: List[str] = []
    suffixes: List[str] = []
    cidrs: List[str] = []

    # Try YAML payload first
    payload = None
    try:
        y = yaml.safe_load(text)
        if isinstance(y, dict) and "payload" in y and isinstance(y["payload"], list):
            payload = y["payload"]
    except Exception:
        payload = None

    lines: List[str]
    if payload is not None:
        lines = [str(x).strip() for x in payload if str(x).strip()]
    else:
        lines = [ln for ln in text.splitlines()]

    for raw in lines:
        line = _strip_comment(str(raw))
        if not line:
            continue

        # Allow "TYPE,VALUE" style
        if "," in line and not line.startswith("http"):
            parts = [p.strip() for p in line.split(",")]
            rule_type = parts[0].upper()
            value = parts[1] if len(parts) > 1 else ""
            if rule_type in ("DOMAIN",):
                if value:
                    domains.append(value)
                continue
            if rule_type in ("DOMAIN-SUFFIX",):
                if value:
                    suffixes.append(value)
                continue
            if rule_type in ("IP-CIDR", "IP-CIDR6"):
                if value:
                    cidrs.append(value)
                continue
            # unsupported: DOMAIN-KEYWORD / PROCESS-NAME / DST-PORT etc.
            continue

        # Plain domain line like "google.com"
        # skip obvious non-domain tokens
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", line):
            cidrs.append(line)
            continue
        if "." in line and " " not in line and "/" not in line:
            # treat as domain suffix by default (most lists are suffix lists)
            suffixes.append(line)
            continue

    # de-dup
    domains = sorted(set(domains))
    suffixes = sorted(set(suffixes))
    cidrs = sorted(set(cidrs))
    return domains, suffixes, cidrs

def fetch(url: str) -> str:
    r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT)
    r.raise_for_status()
    # keep text as-is (utf-8 fallback)
    r.encoding = r.apparent_encoding or "utf-8"
    return r.text

def build_ruleset_json(domains: List[str], suffixes: List[str], cidrs: List[str]) -> Dict:
    rules = []
    if domains:
        rules.append({"domain": domains})
    if suffixes:
        rules.append({"domain_suffix": suffixes})
    if cidrs:
        rules.append({"ip_cidr": cidrs})

    return {
        "version": 3,
        "rules": rules
    }

def main():
    os.makedirs(OUT_JSON_DIR, exist_ok=True)

    # Load source.yml (prefer remote, fallback to local)
    sources = None
    try:
        print(f"[INFO] Fetching sources from remote: {SOURCES_URL}")
        resp = requests.get(SOURCES_URL, headers={"User-Agent": UA}, timeout=TIMEOUT)
        resp.raise_for_status()
        sources = yaml.safe_load(resp.text)
    except Exception as e:
        print(f"[WARN] Remote fetch failed: {e}")
        print(f"[INFO] Falling back to local file: {LOCAL_SOURCES_YML}")
        with open(LOCAL_SOURCES_YML, "r", encoding="utf-8") as f:
            sources = yaml.safe_load(f)

    if not isinstance(sources, dict):
        raise RuntimeError("source.yml format invalid: expect mapping (dict)")

    meta = {"generated_at": int(time.time()), "sets": {}}

    for tag, urls in sources.items():
        if not isinstance(urls, list) or not urls:
            continue

        all_domain: List[str] = []
        all_suffix: List[str] = []
        all_cidr: List[str] = []

        for u in urls:
            text = fetch(str(u))
            d, s, c = parse_clash_or_plain(text)
            all_domain.extend(d)
            all_suffix.extend(s)
            all_cidr.extend(c)

        # dedup
        all_domain = sorted(set(all_domain))
        all_suffix = sorted(set(all_suffix))
        all_cidr = sorted(set(all_cidr))

        rs = build_ruleset_json(all_domain, all_suffix, all_cidr)

        out_path = os.path.join(OUT_JSON_DIR, f"{tag}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(rs, f, ensure_ascii=False, indent=2)

        meta["sets"][tag] = {
            "json": f"output/json/{tag}.json",
            "domain": len(all_domain),
            "domain_suffix": len(all_suffix),
            "ip_cidr": len(all_cidr),
            "sources": urls,
        }

        print(f"[OK] {tag}: domain={len(all_domain)} suffix={len(all_suffix)} cidr={len(all_cidr)}")

    # write index
    os.makedirs(os.path.join(ROOT, "output"), exist_ok=True)
    with open(os.path.join(ROOT, "output", "index.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
