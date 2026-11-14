#!/usr/bin/env bash
# Broadcast storm có kiểm soát: ~500 gói/s x 10 s (ngưỡng mặc định 200 pps). Không dùng --flood để pcap không phình to.
# METHOD=scapy nếu hping3 không gửi được tới địa chỉ broadcast.
HERE="$(cd "$(dirname "$0")/.." && pwd)"; source "$HERE/common.sh"
if [ "${METHOD:-hping3}" = "hping3" ]; then
  dx attacker hping3 -2 -p 9 -i u2000 -c 5000 --data 18 10.10.10.255 >/dev/null 2>&1 || true
else
  dx attacker python3 -c '
from scapy.all import *
p = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst="10.10.10.255")/UDP(sport=4000,dport=9)/("S"*18)
sendp(p, iface="eth1", inter=0.002, count=5000, verbose=0)'
fi
