"""Sinh pcap tổng hợp xác định (không ngẫu nhiên) mô phỏng đúng 5 kịch bản + 1 pcap sạch.
Dùng cho unit test / CI khi chưa có lab, và để kết quả tái lập 100%.

    python -m netanalyzer.cli synth --out pcaps/synthetic
"""
import os

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Dot1Q, Ether, wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import mac2str

T0 = 1_700_000_000.0          # mốc thời gian cố định (số nguyên giây)
BC = "ff:ff:ff:ff:ff:ff"
GW, DHCPS, H10A, H10B, H20A, ATT = ("02:00:00:00:00:%02x" % x for x in (0x01, 0x02, 0x11, 0x12, 0x21, 0x66))
IP_GW10, IP_GW20, IP_DHCP, IP_H10A, IP_H10B, IP_H20A, IP_ATT = (
    "10.10.10.1", "10.20.20.1", "10.10.10.2", "10.10.10.11", "10.10.10.12", "10.20.20.11", "10.10.10.66")
HANDSHAKE_RTT_MS = 2.0        # RTT cố định trong pcap sạch để test thống kê


def _eth(src, dst, vlan=None):
    e = Ether(src=src, dst=dst)
    return e / Dot1Q(vlan=vlan) if vlan else e


def _at(p, t):
    p.time = t
    return p


def arp(op, hwsrc, psrc, pdst, t, eth_dst=None, vlan=None, hwdst="00:00:00:00:00:00"):
    dst = eth_dst or (BC if op == 1 else hwdst)
    return _at(_eth(hwsrc, dst, vlan) / ARP(op=op, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst), t)


def icmp(smac, dmac, sip, dip, t, typ=8, seq=1, vlan=None):
    return _at(_eth(smac, dmac, vlan) / IP(src=sip, dst=dip) / ICMP(type=typ, id=1, seq=seq) / (b"x" * 32), t)


def tcp(smac, dmac, sip, dip, sport, dport, flags, seq, ack, t, payload=b"", vlan=None):
    return _at(_eth(smac, dmac, vlan) / IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / payload, t)


def dhcp(smac, dmac, sip, dip, sport, dport, op, xid, mtype, cmac, t, yiaddr="0.0.0.0", server=None):
    opts = [("message-type", mtype)] + ([("server_id", server)] if server else []) + ["end"]
    return _at(_eth(smac, dmac) / IP(src=sip, dst=dip) / UDP(sport=sport, dport=dport) /
               BOOTP(op=op, xid=xid, chaddr=mac2str(cmac), yiaddr=yiaddr) / DHCP(options=opts), t)


def dora(t, xid, cmac, servers):
    """Một lượt DISCOVER -> OFFER(s) -> REQUEST -> ACK. servers = [(mac, ip, offered_ip)]; server đầu tiên thắng."""
    pk = [dhcp(cmac, BC, "0.0.0.0", "255.255.255.255", 68, 67, 1, xid, "discover", cmac, t)]
    for i, (smac, sip, off) in enumerate(servers):
        pk.append(dhcp(smac, BC, sip, "255.255.255.255", 67, 68, 2, xid, "offer", cmac, t + 0.010 + 0.002 * i,
                       yiaddr=off, server=sip))
    smac, sip, off = servers[0]
    pk.append(dhcp(cmac, BC, "0.0.0.0", "255.255.255.255", 68, 67, 1, xid, "request", cmac, t + 0.030))
    pk.append(dhcp(smac, BC, sip, "255.255.255.255", 67, 68, 2, xid, "ack", cmac, t + 0.040, yiaddr=off, server=sip))
    return pk


def tcp_flow(t, cmac, smac, cip, sip, sport, dport=80, rtt=HANDSHAKE_RTT_MS / 1000, retrans=False):
    isn, ssn = 1000 + sport, 5000 + sport
    r = [tcp(cmac, smac, cip, sip, sport, dport, "S", isn, 0, t),
         tcp(smac, cmac, sip, cip, dport, sport, "SA", ssn, isn + 1, t + rtt),
         tcp(cmac, smac, cip, sip, sport, dport, "A", isn + 1, ssn + 1, t + rtt + 0.0005),
         tcp(cmac, smac, cip, sip, sport, dport, "PA", isn + 1, ssn + 1, t + 0.005, b"GET / HTTP/1.0\r\n\r\n"),
         tcp(smac, cmac, sip, cip, dport, sport, "PA", ssn + 1, isn + 19, t + 0.008, b"A" * 200),
         tcp(cmac, smac, cip, sip, sport, dport, "A", isn + 19, ssn + 201, t + 0.009)]
    if retrans:   # gửi lại đúng gói dữ liệu của server (cùng seq) sau 200 ms
        r.append(tcp(smac, cmac, sip, cip, dport, sport, "PA", ssn + 1, isn + 19, t + 0.208, b"A" * 200))
    r += [tcp(cmac, smac, cip, sip, sport, dport, "FA", isn + 19, ssn + 201, t + 0.3),
          tcp(smac, cmac, sip, cip, dport, sport, "FA", ssn + 201, isn + 20, t + 0.301)]
    return r


# ----------------------------------------------------------------------------- kịch bản
def clean(t0=T0):
    p = []
    # ARP chuẩn: request broadcast + reply unicast (gói của gateway thấy trên trunk nên có tag)
    for i, (m, ip_, gwip, v) in enumerate([(H10A, IP_H10A, IP_GW10, 10), (H10B, IP_H10B, IP_GW10, 10), (H20A, IP_H20A, IP_GW20, 20)]):
        p.append(arp(1, m, ip_, gwip, t0 + 0.1 * i, vlan=v))
        p.append(arp(2, GW, gwip, ip_, t0 + 0.1 * i + 0.001, eth_dst=m, hwdst=m, vlan=v))
    p.append(arp(1, ATT, "0.0.0.0", "10.10.10.200", t0 + 0.5))                  # ARP probe: phải bị bỏ qua
    p.append(arp(1, H10A, IP_H10A, IP_H10A, t0 + 0.6))                          # gratuitous ARP hợp lệ
    for i in range(10):                                                         # ping nội VLAN
        p.append(icmp(H10B, H10A, IP_H10B, IP_H10A, t0 + 1 + i, 8, i))
        p.append(icmp(H10A, H10B, IP_H10A, IP_H10B, t0 + 1 + i + 0.0005, 0, i))
    for i in range(5):                                                          # 5 kết nối HTTP, 1 có retransmission
        p += tcp_flow(t0 + 2 + i * 1.5, H10B, H10A, IP_H10B, IP_H10A, 40000 + i, retrans=(i == 2))
    p += dora(t0 + 3, 0xAAAA0001, H10B, [(DHCPS, IP_DHCP, "10.10.10.100")])    # DHCP chỉ có server hợp lệ
    p.append(_at(_eth(H10A, GW, 10) / IP(src=IP_H10A, dst=IP_GW10) / UDP(sport=53000, dport=53) /
                 DNS(rd=1, qd=DNSQR(qname="example.com")), t0 + 4))
    p.append(_at(_eth(GW, H10A, 10) / IP(src=IP_GW10, dst=IP_H10A) / UDP(sport=53, dport=53000) /
                 DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34")), t0 + 4.01))
    return sorted(p, key=lambda x: float(x.time))


def portscan(t0=T0):
    p = clean(t0)[:20]
    for i, port in enumerate(range(1, 201)):         # 200 cổng trong ~1 s, giống nmap -sS -T4
        t = t0 + 10 + i * 0.005
        p.append(tcp(ATT, H10A, IP_ATT, IP_H10A, 51000, port, "S", 7000 + i, 0, t))
        p.append(tcp(H10A, ATT, IP_H10A, IP_ATT, port, 51000, "RA", 0, 7001 + i, t + 0.0004))
    return sorted(p, key=lambda x: float(x.time))


def arpspoof(t0=T0):
    p = clean(t0)[:20]
    p.append(arp(1, H10A, IP_H10A, IP_GW10, t0 + 9.0))
    p.append(arp(2, GW, IP_GW10, IP_H10A, t0 + 9.001, eth_dst=H10A, hwdst=H10A))   # binding thật
    for i in range(10):                                                            # attacker đầu độc cả hai chiều
        t = t0 + 10 + 2 * i
        p.append(arp(2, ATT, IP_GW10, IP_H10A, t, eth_dst=H10A, hwdst=H10A))
        p.append(arp(2, ATT, IP_H10A, IP_GW10, t + 0.001, eth_dst=GW, hwdst=GW))
    return sorted(p, key=lambda x: float(x.time))


def rogue_dhcp(t0=T0):
    p = clean(t0)[:20]
    legit, rogue = (DHCPS, IP_DHCP, "10.10.10.100"), (ATT, IP_ATT, "10.10.10.200")
    for i in range(3):
        p += dora(t0 + 10 + 3 * i, 0xBBBB0000 + i, H10B, [legit, rogue])
    return sorted(p, key=lambda x: float(x.time))


def bcast(t0=T0):
    p = clean(t0)[:20]
    n, pps = 3000, 600                                # 600 broadcast/s trong 5 s (ngưỡng 200)
    for i in range(n):
        p.append(_at(Ether(src=ATT, dst=BC) / IP(src=IP_ATT, dst="10.10.10.255") / UDP(sport=4000, dport=9) / (b"S" * 18),
                     t0 + 10 + i / pps))
    return sorted(p, key=lambda x: float(x.time))


def vlan_viol(t0=T0):
    p = clean(t0)[:20]
    t = t0 + 10
    for i in range(5):                                # ping VLAN20 -> VLAN10 qua gateway (thấy 2 chặng trên trunk)
        p.append(icmp(H20A, GW, IP_H20A, IP_H10A, t + i, 8, i, vlan=20))
        p.append(icmp(GW, H10A, IP_H20A, IP_H10A, t + i + 0.0003, 8, i, vlan=10))
        p.append(icmp(H10A, GW, IP_H10A, IP_H20A, t + i + 0.0006, 0, i, vlan=10))
        p.append(icmp(GW, H20A, IP_H10A, IP_H20A, t + i + 0.0009, 0, i, vlan=20))
    for j, port in enumerate((22, 80)):
        p.append(tcp(H20A, GW, IP_H20A, IP_H10A, 52000, port, "S", 9000 + j, 0, t + 6 + j, vlan=20))
        p.append(tcp(GW, H10A, IP_H20A, IP_H10A, 52000, port, "S", 9000 + j, 0, t + 6 + j + 0.0003, vlan=10))
        p.append(tcp(H10A, GW, IP_H10A, IP_H20A, port, 52000, "RA", 0, 9001 + j, t + 6 + j + 0.0006, vlan=10))
    return sorted(p, key=lambda x: float(x.time))


def mixed(t0=T0):
    p = clean(t0)
    for k, fn in enumerate((portscan, arpspoof, rogue_dhcp, bcast, vlan_viol)):
        p += [x for x in fn(t0 + 20 + 25 * k) if float(x.time) >= t0 + 20 + 25 * k + 9]
    return sorted(p, key=lambda x: float(x.time))


SCENARIOS = {"clean": clean, "portscan": portscan, "arpspoof": arpspoof, "rogue_dhcp": rogue_dhcp,
             "bcast": bcast, "vlan_viol": vlan_viol, "mixed": mixed}


def generate(out_dir="pcaps/synthetic"):
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for name, fn in SCENARIOS.items():
        path = os.path.join(out_dir, f"{name}.pcap")
        wrpcap(path, fn())
        paths.append(path)
    return paths
