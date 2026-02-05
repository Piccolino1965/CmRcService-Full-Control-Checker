###################################
# aiutocomputerhelp.it
# 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################



# CmRcService Full Control Checker (Windows)
# Legge il log CmRcService dalla cartella standard:
#    C:\Windows\CCM\Logs
#
#Cerca la presenza di:
# - "Session allowed: Full Control"
# ma potete cambiare a piacimnto
#
#Stampa a video un riepilogo e genera due file nella stessa cartella del log:
#- report_CmRcService_full_control.txt
#- evidence_CmRcService_full_control.log
#
# - bisogna avere diritti amministrativi sulla macchina -


from __future__ import annotations

import os
import re
from datetime import datetime
from typing import List, Dict, Optional


FULL_PATTERNS = [
    re.compile(r"Session allowed:\s*Full Control", re.IGNORECASE),
    re.compile(r"Session allowed:\s*Full Controll", re.IGNORECASE),
]

DATE_RE = re.compile(r'date="(?P<date>\d{2}-\d{2}-\d{4})"')
TIME_RE = re.compile(r'time="(?P<time>\d{2}:\d{2}:\d{2}\.\d+)(?P<tzbias>-[0-9]+)?"')
VIEWER_RE = re.compile(r"Viewer address:\s*(?P<viewer>.+?)\s*$", re.IGNORECASE)
HOST_RE = re.compile(r"Host address:\s*(?P<host>.+?)\s*$", re.IGNORECASE)
INCOMING_RE = re.compile(
    r"Incoming connection IP address:\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+Port:\s*(?P<port>\d+)",
    re.IGNORECASE,
)
AUTH_USER_RE = re.compile(r"Authorized viewer user:\s*(?P<user>.*)\s*$", re.IGNORECASE)

CONTEXT_BEFORE = 8
CONTEXT_AFTER = 40


def parse_dt(line: str) -> Optional[str]:
    dm = DATE_RE.search(line)
    tm = TIME_RE.search(line)
    if not (dm and tm):
        return None

    date_s = dm.group("date")  # MM-DD-YYYY
    time_s = tm.group("time")
    bias = tm.group("tzbias") or ""

    try:
        dt = datetime.strptime(f"{date_s} {time_s}", "%m-%d-%Y %H:%M:%S.%f")
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + (bias if bias else "")
    except Exception:
        return f"{date_s} {time_s}{bias}"


def scan_file(path: str) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    hits: List[Dict[str, object]] = []
    evidence_lines: List[str] = []

    for i, line in enumerate(lines):
        if any(p.search(line) for p in FULL_PATTERNS):
            start = max(0, i - CONTEXT_BEFORE)
            end = min(len(lines), i + CONTEXT_AFTER + 1)
            block = lines[start:end]

            ts = parse_dt(line) or "timestamp non rilevato"

            incoming_ip = None
            incoming_port = None
            viewer = None
            host = None
            auth_user = None

            for bl in block:
                m = INCOMING_RE.search(bl)
                if m and incoming_ip is None:
                    incoming_ip = m.group("ip")
                    incoming_port = m.group("port")

                mv = VIEWER_RE.search(bl)
                if mv and viewer is None:
                    viewer = mv.group("viewer").strip()

                mh = HOST_RE.search(bl)
                if mh and host is None:
                    host = mh.group("host").strip()

                mu = AUTH_USER_RE.search(bl)
                if mu and auth_user is None:
                    auth_user = mu.group("user").strip()

            hits.append(
                {
                    "index": i,
                    "timestamp": ts,
                    "incoming_ip": incoming_ip,
                    "incoming_port": incoming_port,
                    "viewer": viewer,
                    "host": host,
                    "auth_user": auth_user,
                    "block": block,
                }
            )

            evidence_lines.append(f"\n===== EVIDENCE BLOCK @ line {i+1} | {ts} =====\n")
            evidence_lines.extend(block)

    return {"hits": hits, "evidence": evidence_lines}


def write_reports(log_path: str, result: Dict[str, object]) -> Dict[str, str]:
    folder = os.path.dirname(os.path.abspath(log_path))

    report_path = os.path.join(folder, "report_CmRcService_full_control.txt")
    evidence_path = os.path.join(folder, "evidence_CmRcService_full_control.log")

    hits: List[Dict[str, object]] = result["hits"]  # type: ignore

    with open(report_path, "w", encoding="utf-8") as r:
        r.write("Report: rilevazione sessioni 'Full Control' in CmRcService\n")
        r.write("https://aiutocomputerhelp.it \n")
        r.write(f"File analizzato: {log_path}\n")
        r.write(f"Eventi trovati: {len(hits)}\n\n")

        if not hits:
            r.write("Nessuna occorrenza di 'Session allowed: Full Control/Full Controll' trovata.\n")
        else:
            for n, h in enumerate(hits, start=1):
                r.write(f"Evento #{n}\n")
                r.write(f"  Timestamp: {h.get('timestamp')}\n")
                r.write(f"  Incoming IP: {h.get('incoming_ip') or 'n/d'}\n")
                r.write(f"  Incoming Port: {h.get('incoming_port') or 'n/d'}\n")
                r.write(f"  Viewer address: {h.get('viewer') or 'n/d'}\n")
                r.write(f"  Host address: {h.get('host') or 'n/d'}\n")
                au = h.get("auth_user")
                r.write(f"  Authorized viewer user: {au if au is not None else 'n/d'}\n")
                r.write(f"  Riga nel file: {int(h.get('index', 0)) + 1}\n\n")

    with open(evidence_path, "w", encoding="utf-8") as e:
        evidence: List[str] = result["evidence"]  # type: ignore
        if not evidence:
            e.write("Nessun evidence block generato: nessun evento trovato.\n")
        else:
            e.writelines(evidence)

    return {"report": report_path, "evidence": evidence_path}


def main() -> int:
    logs_dir = r"C:\Windows\CCM\Logs"
    log_candidates = ["CmRcService.log", "CmRcService.txt"]

    found = None
    for name in log_candidates:
        p = os.path.join(logs_dir, name)
        if os.path.isfile(p):
            found = p
            break

    if not found:
        print("[ERRORE] Nessun file trovato tra:")
        for name in log_candidates:
            print(f"  {os.path.join(logs_dir, name)}")
        return 2

    result = scan_file(found)
    hits = result["hits"]

    print("=== CmRcService Full Control Checker ===")
    print(f"File: {found}")
    print(f"Eventi 'Full Control/Full Controll' trovati: {len(hits)}")

    if hits:
        for n, h in enumerate(hits, start=1):
            print(f"\nEvento #{n}")
            print(f"  Timestamp: {h.get('timestamp')}")
            print(f"  Incoming IP: {h.get('incoming_ip') or 'n/d'}")
            print(f"  Incoming Port: {h.get('incoming_port') or 'n/d'}")
            print(f"  Viewer address: {h.get('viewer') or 'n/d'}")
            print(f"  Host address: {h.get('host') or 'n/d'}")
            au = h.get("auth_user")
            print(f"  Authorized viewer user: {au if au is not None else 'n/d'}")
            print(f"  Riga nel file: {int(h.get('index', 0)) + 1}")

    paths = write_reports(found, result)
    print("\n=== File generati ===")
    print(f"Report:   {paths['report']}")
    print(f"Evidence: {paths['evidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

