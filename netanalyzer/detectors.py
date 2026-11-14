"""5 bộ phát hiện bất thường tầng 2-3-4. Mỗi detector nhận DataFrame (schema parser.COLUMNS)
và trả về list alert (dict JSON-serializable)."""
import numpy as np
import pandas as pd

from .stats import vlan_of_ip

BCAST = "ff:ff:ff:ff:ff:ff"


def _alert(kind, severity, detail, ts=None, **kw):
    a = {"type": kind, "severity": severity, "detail": detail,
         "ts": None if ts is None else float(ts)}
    a.update(kw)
    return a


# ---------------------------------------------------------------- 1. port scan (vertical)
def detect_port_scan(df, window_s=5, min_ports=20, kind="port_scan", severity="high", skip_src=()):
    """Một nguồn gửi SYN (không kèm ACK) tới >= min_ports cổng khác nhau của cùng một đích
    trong cửa sổ trượt window_s giây. Gộp thành 1 cảnh báo / nguồn."""
    syn = df[(df["proto"] == "TCP") & (df["tcp_flags"] == "S")]
    hits = {}
    for (src, dst), g in syn.groupby(["src_ip", "dst_ip"], sort=False):
        if src in skip_src:
            continue
        ts, ports = g["ts"].to_numpy(), g["dport"].to_numpy()
        o = np.argsort(ts, kind="stable")
        ts, ports = ts[o], ports[o]
        counts, lo, best, first = {}, 0, 0, None
        for hi in range(len(ts)):
            counts[ports[hi]] = counts.get(ports[hi], 0) + 1
            while ts[hi] - ts[lo] > window_s:
                counts[ports[lo]] -= 1
                if counts[ports[lo]] == 0:
                    del counts[ports[lo]]
                lo += 1
            if len(counts) > best:
                best, first = len(counts), ts[lo]
        if best >= min_ports:
            hits.setdefault(src, []).append((dst, best, float(first)))
    out = []
    for src, lst in hits.items():
        top = max(lst, key=lambda x: x[1])
        out.append(_alert(kind, severity, f"{top[1]} cổng khác nhau trong {window_s}s tới {top[0]}",
                          ts=min(x[2] for x in lst), src_ip=src, ports=int(top[1]),
                          targets=sorted(x[0] for x in lst)))
    return out


# ---------------------------------------------------------------- 2. ARP spoofing
def detect_arp_spoof(df, ignore_ips=(), ignore_mac_prefixes=()):
    """Một IP được các gói ARP (reply hoặc request) gán cho >1 MAC khác nhau.
    Bỏ qua sender 0.0.0.0 (ARP probe), IP/prefix MAC whitelist (VRRP/HSRP)."""
    a = df[(df["proto"] == "ARP") & df["arp_psrc"].notna() & (df["arp_psrc"] != "0.0.0.0")]
    out = []
    for ip, g in a.groupby("arp_psrc"):
        if ip in ignore_ips:
            continue
        macs = sorted(m for m in g["arp_hwsrc"].unique()
                      if not any(m.lower().startswith(p) for p in ignore_mac_prefixes))
        if len(macs) > 1:
            first = g.groupby("arp_hwsrc")["ts"].min()
            out.append(_alert("arp_spoof", "high", f"IP {ip} được gán {len(macs)} MAC: {', '.join(macs)}",
                              ts=first[macs].max(), ip=ip, macs=macs))
    return out


# ---------------------------------------------------------------- 3. rogue DHCP
def detect_rogue_dhcp(df, allowed_servers=()):
    """Có allowlist: nguồn trả Offer/Ack/Nak không thuộc allowlist -> rogue_dhcp.
    Không có allowlist: >1 nguồn trả lời -> multiple_dhcp_servers (heuristic)."""
    r = df[df["dhcp_type"].isin(["offer", "ack", "nak"]) & df["src_ip"].notna()]
    servers = {ip: g for ip, g in r.groupby("src_ip")}
    out = []
    if allowed_servers:
        for ip, g in servers.items():
            if ip not in allowed_servers:
                out.append(_alert("rogue_dhcp", "high", f"DHCP server {ip} không nằm trong allowlist",
                                  ts=g["ts"].min(), src_ip=ip, macs=sorted(g["src_mac"].unique()),
                                  offers=int(len(g))))
    elif len(servers) > 1:
        out.append(_alert("multiple_dhcp_servers", "medium",
                          f"{len(servers)} nguồn trả lời DHCP: {', '.join(sorted(servers))}",
                          ts=r["ts"].min(), servers=sorted(servers)))
    return out


# ---------------------------------------------------------------- 4. broadcast storm
def detect_broadcast_storm(df, max_pps=200):
    b = df[df["dst_mac"] == BCAST]
    if b.empty:
        return []
    sec = np.floor(b["ts"]).astype("int64")
    cnt = b.groupby(sec).size()
    bad = sorted(cnt[cnt > max_pps].index)
    if not bad:
        return []
    events, cur = [], [bad[0]]
    for s in bad[1:]:                      # gộp các giây liên tiếp thành một sự kiện
        if s - cur[-1] <= 1:
            cur.append(s)
        else:
            events.append(cur)
            cur = [s]
    events.append(cur)
    out = []
    for ev in events:
        sel = b[(sec >= ev[0]) & (sec <= ev[-1])]
        top = sel["src_mac"].value_counts()
        out.append(_alert("broadcast_storm", "high",
                          f"đỉnh {int(cnt[ev].max())} broadcast/s (> {max_pps}) trong {len(ev)}s, "
                          f"nguồn chính {top.index[0]}", ts=float(ev[0]), peak_pps=int(cnt[ev].max()),
                          seconds=len(ev), top_src_mac=top.index[0], packets=int(len(sel))))
    return out


# ---------------------------------------------------------------- 5. luồng liên VLAN bị cấm
def detect_vlan_violation(df, subnets, deny_flows):
    if not subnets or not deny_flows:
        return []
    ip = df.dropna(subset=["src_ip", "dst_ip"])
    pairs = ip.groupby(["src_ip", "dst_ip"]).agg(packets=("ts", "size"), ts=("ts", "min")).reset_index()
    deny = {tuple(x) for x in deny_flows}
    out = []
    for r in pairs.itertuples(index=False):
        vs, vd = vlan_of_ip(r.src_ip, subnets), vlan_of_ip(r.dst_ip, subnets)
        if vs is not None and vd is not None and (vs, vd) in deny:
            out.append(_alert("vlan_violation", "medium", f"{r.src_ip} (VLAN {vs}) -> {r.dst_ip} (VLAN {vd}) bị cấm",
                              ts=r.ts, src_ip=r.src_ip, dst_ip=r.dst_ip, src_vlan=vs, dst_vlan=vd,
                              packets=int(r.packets)))
    return out


# ---------------------------------------------------------------- tổng hợp
def run_all(df, policy):
    alerts = detect_port_scan(df, **policy["portscan"])
    slow = policy.get("portscan_slow", {})
    if slow.get("enabled"):
        fast_src = {a["src_ip"] for a in alerts}
        alerts += detect_port_scan(df, window_s=slow["window_s"], min_ports=slow["min_ports"],
                                   kind="port_scan_slow", severity="medium", skip_src=fast_src)
    alerts += detect_arp_spoof(df, policy["arp_spoof"].get("ignore_ips", []),
                               policy["arp_spoof"].get("ignore_mac_prefixes", []))
    alerts += detect_rogue_dhcp(df, policy["dhcp"].get("allowed_servers", []))
    alerts += detect_broadcast_storm(df, policy["bcast"]["max_pps"])
    alerts += detect_vlan_violation(df, policy["vlan_subnets"], policy["vlan_deny_flows"])
    return sorted(alerts, key=lambda a: (a["ts"] is None, a["ts"]))
