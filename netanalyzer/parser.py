"""pcap -> DataFrame / SQLite.

Hai engine cho cùng một schema:
  * scapy : dễ đọc, hỗ trợ pcapng, chậm (~vài nghìn gói/s)
  * fast  : RawPcapReader + struct, chỉ bóc header cần thiết (nhanh hơn nhiều lần)
Test tests/test_parser_equivalence.py bảo đảm hai engine cho kết quả giống nhau.
"""
import logging
import socket
import sqlite3
import struct

import pandas as pd
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Dot1Q, Ether, PcapReader, RawPcapReader
from scapy.layers.dhcp import DHCP
from scapy.layers.inet6 import IPv6

log = logging.getLogger("nta.parser")

COLUMNS = ["ts", "len", "src_mac", "dst_mac", "vlan", "l3", "src_ip", "dst_ip", "proto",
           "sport", "dport", "tcp_flags", "seq", "ack", "payload_len", "icmp_type",
           "arp_op", "arp_psrc", "arp_pdst", "arp_hwsrc", "dhcp_type", "dns_qname"]

DHCP_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack",
              6: "nak", 7: "release", 8: "inform"}


def _empty(ts=0.0, ln=0):
    r = dict.fromkeys(COLUMNS)
    r["ts"], r["len"], r["payload_len"] = ts, ln, 0
    return r


# --------------------------------------------------------------------------- scapy engine
def parse_packet(pkt) -> dict:
    r = _empty(float(pkt.time), len(pkt))
    if Ether not in pkt:
        return r
    eth = pkt[Ether]
    r["src_mac"], r["dst_mac"] = eth.src, eth.dst
    if Dot1Q in pkt:
        r["vlan"] = int(pkt[Dot1Q].vlan)
    if ARP in pkt:
        a = pkt[ARP]
        r.update(l3="ARP", proto="ARP", arp_op=int(a.op), arp_psrc=a.psrc,
                 arp_pdst=a.pdst, arp_hwsrc=a.hwsrc)
        return r
    if IP in pkt:
        ip = pkt[IP]
        r.update(l3="IPv4", src_ip=ip.src, dst_ip=ip.dst, proto="IP")
        l4_len = ip.len - ip.ihl * 4 if ip.len else 0
        if ip.frag:  # fragment không đầu: không có header L4
            return r
        if TCP in pkt:
            t = pkt[TCP]
            r.update(proto="TCP", sport=int(t.sport), dport=int(t.dport), tcp_flags=str(t.flags),
                     seq=int(t.seq), ack=int(t.ack),
                     payload_len=max(0, l4_len - t.dataofs * 4))
        elif UDP in pkt:
            u = pkt[UDP]
            r.update(proto="UDP", sport=int(u.sport), dport=int(u.dport),
                     payload_len=max(0, int(u.len) - 8))
            if DHCP in pkt:
                r["proto"] = "DHCP"
                for o in pkt[DHCP].options:
                    if isinstance(o, tuple) and o[0] == "message-type":
                        r["dhcp_type"] = DHCP_TYPES.get(o[1], str(o[1]))
            elif DNS in pkt and pkt[DNS].qd is not None and DNSQR in pkt:
                r["proto"] = "DNS"
                q = pkt[DNSQR].qname
                r["dns_qname"] = q.decode(errors="ignore") if isinstance(q, bytes) else str(q)
        elif ICMP in pkt:
            r.update(proto="ICMP", icmp_type=int(pkt[ICMP].type))
        return r
    if IPv6 in pkt:
        r.update(l3="IPv6", src_ip=pkt[IPv6].src, dst_ip=pkt[IPv6].dst, proto="IPv6")
        return r
    r["proto"] = "Other"
    return r


# --------------------------------------------------------------------------- fast engine
_FLAGS = ["".join(c for i, c in enumerate("FSRPAUEC") if v >> i & 1) for v in range(256)]
_mac_cache = {}


def _mac(b: bytes) -> str:
    m = _mac_cache.get(b)
    if m is None:
        h = b.hex()
        m = _mac_cache[b] = ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return m


def _dhcp_type(p: bytes):
    """p = payload UDP của BOOTP. Trả về (is_dhcp, message_type_str)."""
    if len(p) < 241 or p[236:240] != b"\x63\x82\x53\x63":
        return False, None
    i, n = 240, len(p)
    while i < n:
        code = p[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= n:
            break
        ln = p[i + 1]
        if code == 53 and ln >= 1 and i + 2 < n:
            return True, DHCP_TYPES.get(p[i + 2], str(p[i + 2]))
        i += 2 + ln
    return True, None


def _dns_qname(p: bytes):
    if len(p) < 13 or ((p[4] << 8) | p[5]) < 1:
        return None
    i, labels = 12, []
    while i < len(p):
        ln = p[i]
        if ln == 0:
            break
        if ln & 0xC0 or i + 1 + ln > len(p):
            return None
        labels.append(p[i + 1:i + 1 + ln].decode(errors="ignore"))
        i += 1 + ln
    return ".".join(labels) + "."


def parse_raw(d: bytes, ts: float, wirelen: int) -> dict:
    r = _empty(ts, wirelen)
    if len(d) < 14:
        return r
    r["dst_mac"], r["src_mac"] = _mac(d[0:6]), _mac(d[6:12])
    et, off = (d[12] << 8) | d[13], 14
    if et == 0x8100 and len(d) >= 18:          # 802.1Q (scapy chỉ bóc Dot1Q 0x8100)
        r["vlan"] = ((d[14] << 8) | d[15]) & 0x0FFF
        et, off = (d[16] << 8) | d[17], 18
    if et == 0x0806:
        if len(d) < off + 28:
            return r
        r.update(l3="ARP", proto="ARP", arp_op=(d[off + 6] << 8) | d[off + 7],
                 arp_hwsrc=_mac(d[off + 8:off + 14]), arp_psrc=socket.inet_ntoa(d[off + 14:off + 18]),
                 arp_pdst=socket.inet_ntoa(d[off + 24:off + 28]))
        return r
    if et == 0x86DD and len(d) >= off + 40:
        r.update(l3="IPv6", proto="IPv6", src_ip=socket.inet_ntop(socket.AF_INET6, d[off + 8:off + 24]),
                 dst_ip=socket.inet_ntop(socket.AF_INET6, d[off + 24:off + 40]))
        return r
    if et != 0x0800 or len(d) < off + 20:
        r["proto"] = "Other"
        return r
    ihl = (d[off] & 0x0F) * 4
    tot = (d[off + 2] << 8) | d[off + 3]
    frag = ((d[off + 6] << 8) | d[off + 7]) & 0x1FFF
    ipproto = d[off + 9]
    r.update(l3="IPv4", proto="IP", src_ip=socket.inet_ntoa(d[off + 12:off + 16]),
             dst_ip=socket.inet_ntoa(d[off + 16:off + 20]))
    l4, l4_len = off + ihl, tot - ihl
    if frag or len(d) < l4 + 8:
        return r
    if ipproto == 6 and len(d) >= l4 + 20:
        sport, dport, seq, ack = struct.unpack_from(">HHII", d, l4)
        dataoff = (d[l4 + 12] >> 4) * 4
        r.update(proto="TCP", sport=sport, dport=dport, seq=seq, ack=ack,
                 tcp_flags=_FLAGS[d[l4 + 13]], payload_len=max(0, l4_len - dataoff))
    elif ipproto == 17:
        sport, dport, ulen = struct.unpack_from(">HHH", d, l4)
        r.update(proto="UDP", sport=sport, dport=dport, payload_len=max(0, ulen - 8))
        payload = d[l4 + 8:]
        if sport in (67, 68) or dport in (67, 68):
            is_dhcp, mt = _dhcp_type(payload)
            if is_dhcp:
                r["proto"], r["dhcp_type"] = "DHCP", mt
        elif sport in (53, 5353) or dport in (53, 5353):
            q = _dns_qname(payload)
            if q is not None:
                r["proto"], r["dns_qname"] = "DNS", q
    elif ipproto == 1:
        r.update(proto="ICMP", icmp_type=d[l4])
    return r


# --------------------------------------------------------------------------- API
def _is_pcapng(path):
    with open(path, "rb") as f:
        return f.read(4) == b"\x0a\x0d\x0d\x0a"


def iter_rows(path, engine="fast", max_packets=None):
    """Sinh từng dict (một gói). Không giữ cả file trong RAM."""
    if engine == "fast" and _is_pcapng(path):
        log.warning("pcapng: chuyển sang engine scapy (hoặc dùng `editcap -F pcap`)")
        engine = "scapy"
    n = 0
    if engine == "scapy":
        with PcapReader(path) as rd:
            for pkt in rd:
                yield parse_packet(pkt)
                n += 1
                if max_packets and n >= max_packets:
                    return
    else:
        rd = RawPcapReader(path)
        try:
            if rd.linktype != 1:
                raise ValueError(f"linktype {rd.linktype} chưa hỗ trợ (cần Ethernet=1)")
            nano = getattr(rd, "nano", False)
            for data, meta in rd:
                ts = meta.sec + meta.usec * (1e-9 if nano else 1e-6)
                yield parse_raw(data, ts, meta.wirelen)
                n += 1
                if max_packets and n >= max_packets:
                    return
        finally:
            rd.close()


def rows_to_df(rows) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["time"] = pd.to_datetime(df["ts"], unit="s")
    return df


def pcap_to_df(path, engine="fast", max_packets=None) -> pd.DataFrame:
    return rows_to_df(iter_rows(path, engine, max_packets))


def save_sqlite(df, db="traffic.db", table="packets", chunk=100_000):
    out = df.drop(columns=["time"], errors="ignore")
    with sqlite3.connect(db) as con:
        for i in range(0, max(len(out), 1), chunk):
            out.iloc[i:i + chunk].to_sql(table, con, if_exists="replace" if i == 0 else "append", index=False)
        con.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_ts ON {table}(ts)")


def load_sqlite(db="traffic.db", table="packets") -> pd.DataFrame:
    with sqlite3.connect(db) as con:
        df = pd.read_sql(f"SELECT * FROM {table}", con)
    df["time"] = pd.to_datetime(df["ts"], unit="s")
    return df
