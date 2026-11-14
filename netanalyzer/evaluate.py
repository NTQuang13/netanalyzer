"""Đánh giá độ chính xác theo ground_truth.yml + đo hiệu năng parser."""
import fnmatch
import glob
import os
import time

import yaml

from .detectors import run_all
from .parser import pcap_to_df


def load_truth(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def expected_for(rel, truth):
    for pat, exp in truth.items():
        if fnmatch.fnmatch(rel, pat):
            return set(exp)
    return None


def discover(pcap_dir, truth):
    out = []
    for f in sorted(glob.glob(os.path.join(pcap_dir, "**", "*.pcap"), recursive=True)):
        rel = os.path.relpath(f, pcap_dir).replace(os.sep, "/")
        exp = expected_for(rel, truth)
        if exp is not None:
            out.append((rel, f, exp))
    return out


def evaluate(pcap_dir, truth_path, policy, engine="fast"):
    rows, tp = [], dict(tp=0, fn=0, fp=0, exact=0)
    for rel, f, exp in discover(pcap_dir, load_truth(truth_path)):
        found = {a["type"] for a in run_all(pcap_to_df(f, engine), policy)}
        tp["tp"] += len(exp & found); tp["fn"] += len(exp - found); tp["fp"] += len(found - exp)
        ok = found == exp
        tp["exact"] += ok
        rows.append((rel, sorted(exp), sorted(found), ok))
    return rows, tp, len(rows)


def format_table(rows, tp, n):
    lines = ["| pcap | kỳ vọng | phát hiện | kết quả |", "|---|---|---|---|"]
    for rel, exp, found, ok in rows:
        lines.append(f"| {rel} | {', '.join(exp) or '(sạch)'} | {', '.join(found) or '(không)'} | {'✅' if ok else '❌'} |")
    p = tp["tp"] / (tp["tp"] + tp["fp"]) if tp["tp"] + tp["fp"] else 1.0
    r = tp["tp"] / (tp["tp"] + tp["fn"]) if tp["tp"] + tp["fn"] else 1.0
    lines.append(f"\n**{tp['exact']}/{n} pcap đúng hoàn toàn** · TP={tp['tp']} FN={tp['fn']} FP={tp['fp']} · "
                 f"precision={p:.2%} recall={r:.2%}")
    return "\n".join(lines)


def bench(path, engines=("scapy", "fast"), repeat=3):
    res = {}
    for e in engines:
        best = None
        for _ in range(repeat):
            t0 = time.perf_counter()
            df = pcap_to_df(path, e)
            dt = time.perf_counter() - t0
            best = dt if best is None else min(best, dt)
        res[e] = {"packets": len(df), "seconds": round(best, 3), "pps": round(len(df) / best)}
    t0 = time.perf_counter()
    run_all(df, {"portscan": {"window_s": 5, "min_ports": 20}, "portscan_slow": {"enabled": False},
                 "arp_spoof": {}, "dhcp": {}, "bcast": {"max_pps": 200}, "vlan_subnets": {}, "vlan_deny_flows": []})
    res["detectors_seconds"] = round(time.perf_counter() - t0, 3)
    return res
