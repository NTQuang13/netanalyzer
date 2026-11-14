#!/usr/bin/env python3
"""Đối chiếu số liệu của netanalyzer với tshark (và tuỳ chọn Zeek).

    python tools/compare_tools.py pcaps/synthetic/*.pcap [--zeek]

In bảng markdown để dán vào README. Sai lệch nào cũng cần giải thích (xem cột ghi chú).
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netanalyzer import stats                       # noqa: E402
from netanalyzer.detectors import run_all            # noqa: E402
from netanalyzer.parser import pcap_to_df            # noqa: E402
from netanalyzer.policy import load_policy           # noqa: E402


def tshark_count(pcap, display_filter=None):
    cmd = ["tshark", "-r", pcap, "-n"] + (["-Y", display_filter] if display_filter else [])
    out = subprocess.run(cmd, capture_output=True, text=True)
    return len([ln for ln in out.stdout.splitlines() if ln.strip()])


def tshark_rtts(pcap):
    cmd = ["tshark", "-r", pcap, "-n", "-Y", "tcp.flags.syn==1 && tcp.flags.ack==1 && tcp.analysis.ack_rtt",
           "-T", "fields", "-e", "tcp.analysis.ack_rtt"]
    vals = [float(x) * 1000 for x in subprocess.run(cmd, capture_output=True, text=True).stdout.split()]
    return vals


def zeek_scan_notices(pcap):
    """Chạy Zeek trong docker (misc/scan) và đếm notice Scan::Port_Scan / Scan::Address_Scan."""
    d = tempfile.mkdtemp()
    ap = os.path.abspath(pcap)
    subprocess.run(["docker", "run", "--rm", "-v", f"{os.path.dirname(ap)}:/pcaps:ro", "-v", f"{d}:/out", "-w", "/out",
                    "zeek/zeek", "zeek", "-C", "-r", f"/pcaps/{os.path.basename(ap)}", "local", "misc/scan"],
                   capture_output=True)
    notice, conn = os.path.join(d, "notice.log"), os.path.join(d, "conn.log")
    n_scan = 0
    if os.path.exists(notice):
        n_scan = sum(1 for ln in open(notice) if "Scan::" in ln and not ln.startswith("#"))
    n_conn = sum(1 for ln in open(conn) if not ln.startswith("#")) if os.path.exists(conn) else 0
    return n_scan, n_conn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--policy", default="policy.yml")
    ap.add_argument("--zeek", action="store_true")
    a = ap.parse_args()
    if not shutil.which("tshark"):
        sys.exit("Cần cài tshark: sudo apt install tshark")
    pol = load_policy(a.policy)
    head = ("| pcap | gói (ta/tshark) | SYN (ta/tshark) | ARP (ta/tshark) | DHCP (ta/tshark) | "
            "retrans (ta/tshark) | RTT TB ms (ta/tshark) | cảnh báo |")
    print(head + ("\n|---|---|---|---|---|---|---|---|" if not a.zeek else " Zeek scan/conn |\n|---|---|---|---|---|---|---|---|---|"))
    for f in a.pcaps:
        df = pcap_to_df(f)
        t = df[df["proto"] == "TCP"]
        ours = dict(pk=len(df), syn=int((t["tcp_flags"] == "S").sum()), arp=int((df["proto"] == "ARP").sum()),
                    dhcp=int((df["proto"] == "DHCP").sum()),
                    retr=int(t[t["payload_len"] > 0].duplicated(
                        subset=["src_mac", "src_ip", "dst_ip", "sport", "dport", "seq"]).sum()))
        ts = dict(pk=tshark_count(f), syn=tshark_count(f, "tcp.flags.syn==1 && tcp.flags.ack==0"),
                  arp=tshark_count(f, "arp"), dhcp=tshark_count(f, "bootp"),
                  retr=tshark_count(f, "tcp.analysis.retransmission || tcp.analysis.fast_retransmission"))
        rt_o = stats.tcp_handshake_rtt(df)["rtt_ms"]
        rt_t = tshark_rtts(f)
        fmt = lambda x: f"{x:.2f}" if x == x else "n/a"
        mean_o = rt_o.mean() if len(rt_o) else float("nan")
        mean_t = sum(rt_t) / len(rt_t) if rt_t else float("nan")
        types = sorted({al["type"] for al in run_all(df, pol)})
        row = (f"| {os.path.basename(f)} | {ours['pk']}/{ts['pk']} | {ours['syn']}/{ts['syn']} | {ours['arp']}/{ts['arp']} | "
               f"{ours['dhcp']}/{ts['dhcp']} | {ours['retr']}/{ts['retr']} | {fmt(mean_o)}/{fmt(mean_t)} | {', '.join(types) or '-'} |")
        if a.zeek:
            sc, cn = zeek_scan_notices(f)
            row += f" {sc}/{cn} |"
        print(row)
    print("\nGhi chú: tshark đếm 'bootp' gồm mọi gói BOOTP/DHCP; retransmission của Wireshark có thêm heuristic "
          "(fast/spurious), và coi gói định tuyến thấy 2 lần trên trunk (trước/sau gateway) là retransmission; "
          "công cụ này phân biệt bằng src_mac nên có thể lệch.")


if __name__ == "__main__":
    main()
