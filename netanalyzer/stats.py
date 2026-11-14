"""Thống kê lưu lượng bằng pandas."""
import ipaddress

import numpy as np
import pandas as pd


def vlan_of_ip(ip, subnets):
    """Tra VLAN theo subnet (policy.vlan_subnets). None nếu không khớp / không phải IP."""
    if not isinstance(ip, str):
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for cidr, vid in subnets.items():
        if a in ipaddress.ip_network(cidr):
            return vid
    return None


def add_vlan_eff(df, subnets):
    """vlan_eff = tag 802.1Q nếu có, nếu không suy ra từ subnet của src_ip, còn lại 0.
    (Gói mirror từ cổng access không còn tag, nên cần bước suy ra này.)"""
    df = df.copy()
    uniq = {ip: vlan_of_ip(ip, subnets) for ip in df["src_ip"].dropna().unique()}
    inferred = df["src_ip"].map(uniq)
    df["vlan_eff"] = df["vlan"].fillna(inferred).fillna(0).astype(int)
    return df


def summary(df):
    if df.empty:
        return {"packets": 0, "bytes": 0, "duration_s": 0.0, "avg_pps": 0.0}
    dur = float(df["ts"].max() - df["ts"].min())
    return {"packets": int(len(df)), "bytes": int(df["len"].sum()), "duration_s": round(dur, 3),
            "avg_pps": round(len(df) / dur, 1) if dur > 0 else float(len(df)),
            "avg_len": round(float(df["len"].mean()), 1)}


def top_talkers(df, n=10):
    ip = df.dropna(subset=["src_ip"])
    return (ip.groupby("src_ip")["len"].agg(packets="count", bytes="sum")
              .sort_values("bytes", ascending=False).head(n))


def proto_dist(df):
    return df["proto"].fillna("Unknown").value_counts()


def vlan_traffic(df, subnets=None):
    d = add_vlan_eff(df, subnets or {}) if "vlan_eff" not in df else df
    return d.groupby("vlan_eff")["len"].agg(packets="count", bytes="sum")


def pkt_size_hist(df, bins=(0, 64, 128, 256, 512, 1024, 1500, 9000)):
    return pd.cut(df["len"], bins=list(bins)).value_counts().sort_index()


def traffic_timeline(df, freq="1s"):
    t = df.set_index("time")["len"].resample(freq).agg(["count", "sum"])
    return t.rename(columns={"count": "packets", "sum": "bytes"})


def tcp_handshake_rtt(df):
    """RTT = thời gian từ SYN đầu tiên tới SYN-ACK đầu tiên của cùng một kết nối
    (đo tại điểm bắt gói, gồm cả đường đi tới server và ngược lại)."""
    t = df[df["proto"] == "TCP"]
    syn = t[t["tcp_flags"] == "S"].sort_values("ts")
    sa = t[t["tcp_flags"] == "SA"].sort_values("ts")
    if syn.empty or sa.empty:
        return pd.DataFrame(columns=["src_ip", "dst_ip", "dport", "rtt_ms"])
    left = pd.DataFrame({"src_ip": syn.src_ip, "dst_ip": syn.dst_ip, "sport": syn.sport,
                         "dport": syn.dport, "exp_ack": syn.seq + 1, "ts_syn": syn.ts})
    right = pd.DataFrame({"src_ip": sa.dst_ip, "dst_ip": sa.src_ip, "sport": sa.dport,
                          "dport": sa.sport, "exp_ack": sa.ack, "ts_sa": sa.ts})
    key = ["src_ip", "dst_ip", "sport", "dport", "exp_ack"]
    m = left.drop_duplicates(key).merge(right.drop_duplicates(key), on=key)
    m["rtt_ms"] = (m["ts_sa"] - m["ts_syn"]) * 1000.0
    return m[m["rtt_ms"] >= 0][["src_ip", "dst_ip", "dport", "rtt_ms"]].reset_index(drop=True)


def retransmission_rate(df):
    """Tỷ lệ gói TCP có payload mà cùng (src_mac, 5-tuple, seq) đã xuất hiện trước đó.
    Có src_mac để không đếm nhầm gói định tuyến (thấy 2 lần trên trunk: trước và sau gateway)."""
    t = df[(df["proto"] == "TCP") & (df["payload_len"] > 0)]
    if t.empty:
        return 0.0
    dup = t.duplicated(subset=["src_mac", "src_ip", "dst_ip", "sport", "dport", "seq"], keep="first")
    return float(dup.sum()) / len(t)
