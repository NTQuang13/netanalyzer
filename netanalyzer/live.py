"""Phân tích thời gian thực bằng cửa sổ trượt.

* Cửa sổ ngắn (window) cho: port scan, broadcast storm, vlan violation.
* Trạng thái dài hơn (state_window) cho: ARP binding, DHCP server (vì spoof/rogue cần thấy cả
  gói hợp lệ lẫn gói giả, có thể cách nhau hơn vài giây).
* Đồng hồ lấy theo timestamp của gói => cùng code chạy cho cả live lẫn replay pcap (--offline).
"""
import logging
import threading
import time
from collections import deque

import pandas as pd

from . import detectors as D
from .parser import COLUMNS, parse_packet, rows_to_df
from .alert import notify

log = logging.getLogger("nta.live")


def _key(a):
    who = a.get("src_ip") or a.get("ip") or ",".join(a.get("servers", [])) or a.get("top_src_mac") or ""
    return (a["type"], who, a.get("dst_ip", ""))


class LiveAnalyzer:
    def __init__(self, policy, window=10, every=2, state_window=600, cooldown=60, on_alert=None):
        self.policy, self.window, self.every = policy, window, every
        self.state_window, self.cooldown = state_window, cooldown
        self.on_alert = on_alert or (lambda a: None)
        self.buf, self.state = deque(), deque()
        self.seen, self.latest, self.last_tick = {}, 0.0, None
        self.lock = threading.Lock()
        self.total = 0

    def feed(self, row):
        with self.lock:
            self.buf.append(row)
            if row["proto"] in ("ARP", "DHCP"):
                self.state.append(row)
            self.latest = max(self.latest, row["ts"])
            self.total += 1

    def advance(self, ts):
        """Gọi TRƯỚC khi feed gói có timestamp ts: chạy đủ các mốc tick nằm giữa gói trước và gói này,
        để khoảng im lặng của mạng không làm cửa sổ trượt 'quên' sự kiện chưa kịp kiểm tra."""
        out = []
        if self.last_tick is None:
            self.last_tick = ts
            return out
        while self.last_tick + self.every <= ts:
            self.last_tick += self.every
            out += self.tick(self.last_tick)
            if not self.buf:                 # cửa sổ đã rỗng: nhảy thẳng tới ts
                self.last_tick = ts
                break
        return out

    def tick(self, now=None):
        with self.lock:
            now = now or self.latest
            while self.buf and self.buf[0]["ts"] < now - self.window:
                self.buf.popleft()
            while self.state and self.state[0]["ts"] < now - self.state_window:
                self.state.popleft()
            win, st = list(self.buf), list(self.state)
        if not win:
            return []
        p, dfw = self.policy, rows_to_df(win)
        dfs = rows_to_df(st) if st else dfw.iloc[0:0]
        alerts = (D.detect_port_scan(dfw, **p["portscan"]) +
                  D.detect_broadcast_storm(dfw, p["bcast"]["max_pps"]) +
                  D.detect_vlan_violation(dfw, p["vlan_subnets"], p["vlan_deny_flows"]) +
                  D.detect_arp_spoof(dfs, p["arp_spoof"].get("ignore_ips", []),
                                     p["arp_spoof"].get("ignore_mac_prefixes", [])) +
                  D.detect_rogue_dhcp(dfs, p["dhcp"].get("allowed_servers", [])))
        fresh = []
        for a in alerts:                      # khử trùng: cùng (loại, nguồn) chỉ báo lại sau `cooldown` giây
            k = _key(a)
            if now - self.seen.get(k, -1e18) >= self.cooldown:
                self.seen[k] = now
                fresh.append(a)
                self.on_alert(a)
        return fresh


def replay(path, policy, **kw):
    """Phát lại pcap qua LiveAnalyzer (không chờ thật). Trả về toàn bộ cảnh báo."""
    from scapy.all import PcapReader
    out = []
    la = LiveAnalyzer(policy, on_alert=out.append, **kw)
    with PcapReader(path) as rd:
        for pkt in rd:
            row = parse_packet(pkt)
            la.advance(row["ts"])
            la.feed(row)
    la.tick(la.latest)
    return out


def run_live(iface, policy, window=10, every=2, jsonl=None, offline=None):
    if offline:
        la = LiveAnalyzer(policy, window, every, on_alert=lambda a: notify(a, jsonl))
        from scapy.all import PcapReader
        with PcapReader(offline) as rd:
            for pkt in rd:
                row = parse_packet(pkt)
                la.advance(row["ts"])
                la.feed(row)
        la.tick(la.latest)
        log.info("replay xong: %d gói", la.total)
        return
    from scapy.all import AsyncSniffer
    la = LiveAnalyzer(policy, window, every, on_alert=lambda a: notify(a, jsonl))
    sn = AsyncSniffer(iface=iface, prn=lambda p: la.feed(parse_packet(p)), store=False)
    sn.start()
    log.info("đang bắt trên %s (Ctrl+C để dừng), window=%ss every=%ss", iface, window, every)
    try:
        while True:
            time.sleep(every)
            la.tick(time.time())
    except KeyboardInterrupt:
        pass
    finally:
        sn.stop()
        log.info("tổng %d gói", la.total)
