"""CLI:  python -m netanalyzer.cli <analyze|live|synth|evaluate|bench> ..."""
import argparse
import json
import logging
import sys
import time

from . import stats
from .alert import notify
from .evaluate import bench, evaluate, format_table
from .parser import pcap_to_df, save_sqlite
from .policy import load_policy
from .detectors import run_all
from .report import build_report


def cmd_analyze(a):
    pol = load_policy(a.policy)
    t0 = time.perf_counter()
    df = pcap_to_df(a.pcap, a.engine, a.max_packets)
    t_parse = time.perf_counter() - t0
    alerts = run_all(df, pol)
    d = stats.add_vlan_eff(df, pol["vlan_subnets"])
    if not a.quiet:
        s = stats.summary(d)
        print(f"== {a.pcap}: {s['packets']} gói, {s['bytes']} byte, {s['duration_s']}s, "
              f"parse {t_parse:.2f}s ({len(df) / max(t_parse, 1e-9):.0f} gói/s, engine={a.engine})")
        print("\n-- Giao thức\n" + stats.proto_dist(d).to_string())
        print("\n-- Top talkers\n" + stats.top_talkers(d, 5).to_string())
        print("\n-- Theo VLAN\n" + stats.vlan_traffic(d).to_string())
        rtt = stats.tcp_handshake_rtt(d)
        print(f"\n-- TCP handshake: {len(rtt)} kết nối, RTT TB "
              f"{rtt['rtt_ms'].mean():.2f} ms" if len(rtt) else "\n-- TCP handshake: không có")
        print(f"-- TCP retransmission rate: {stats.retransmission_rate(d):.2%}")
        print(f"\n== {len(alerts)} cảnh báo")
    for al in alerts:
        if a.jsonl or a.telegram:
            notify(al, a.jsonl, telegram=a.telegram)
        if not a.quiet:
            print(f"[{al['severity']:6}] {al['type']:22} {al['detail']}")
    if a.report:
        print("Báo cáo:", build_report(d, alerts, pol, a.report, source=a.pcap, offline_js=a.offline_js))
    if a.db:
        save_sqlite(df, a.db)
        print("SQLite:", a.db)
    if a.alerts_json:
        json.dump(alerts, open(a.alerts_json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return 0


def cmd_live(a):
    from .live import run_live
    run_live(a.iface, load_policy(a.policy), a.window, a.every, a.jsonl, a.offline)
    return 0


def cmd_synth(a):
    from .synth import generate
    for p in generate(a.out):
        print("tạo", p)
    return 0


def cmd_evaluate(a):
    rows, tp, n = evaluate(a.pcap_dir, a.truth, load_policy(a.policy), a.engine)
    print(format_table(rows, tp, n))
    return 0 if tp["exact"] == n else 1


def cmd_bench(a):
    print(json.dumps(bench(a.pcap), indent=2))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="netanalyzer")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("analyze", help="phân tích file pcap")
    s.add_argument("pcap")
    s.add_argument("--policy", default="policy.yml")
    s.add_argument("--engine", choices=["fast", "scapy"], default="fast")
    s.add_argument("--report", help="xuất báo cáo HTML")
    s.add_argument("--offline-js", action="store_true", help="nhúng plotly.js vào HTML (xem offline)")
    s.add_argument("--db", help="lưu gói vào SQLite")
    s.add_argument("--jsonl", help="ghi cảnh báo ra file JSONL")
    s.add_argument("--alerts-json")
    s.add_argument("--telegram", action="store_true", help="gửi Telegram (cần TG_TOKEN, TG_CHAT)")
    s.add_argument("--max-packets", type=int)
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("live", help="phân tích thời gian thực")
    s.add_argument("--iface", default="eth1")
    s.add_argument("--policy", default="policy.yml")
    s.add_argument("--window", type=int, default=10)
    s.add_argument("--every", type=int, default=2)
    s.add_argument("--jsonl")
    s.add_argument("--offline", help="phát lại 1 file pcap thay vì bắt thật (để test)")
    s.set_defaults(fn=cmd_live)

    s = sub.add_parser("synth", help="sinh pcap tổng hợp")
    s.add_argument("--out", default="pcaps/synthetic")
    s.set_defaults(fn=cmd_synth)

    s = sub.add_parser("evaluate", help="so với ground_truth, in bảng TP/FN/FP")
    s.add_argument("--pcap-dir", default="pcaps")
    s.add_argument("--truth", default="tests/ground_truth.yml")
    s.add_argument("--policy", default="policy.yml")
    s.add_argument("--engine", choices=["fast", "scapy"], default="fast")
    s.set_defaults(fn=cmd_evaluate)

    s = sub.add_parser("bench", help="đo gói/giây của từng engine")
    s.add_argument("pcap")
    s.set_defaults(fn=cmd_bench)

    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
