#!/usr/bin/env bash
# Cấu hình lab sau khi `containerlab deploy`: VLAN trên switch, mirror, IP, gateway, DHCP, HTTP.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/common.sh"

echo "[1/6] Switch sw1: bridge + VLAN filtering + mirror"
dx sw1 bash -ec '
ip link add br0 type bridge vlan_filtering 1 2>/dev/null || true
ip link set br0 up
for i in 1 2 3 4 5 6 7; do
  ip link set eth$i master br0; ip link set eth$i up
  bridge vlan del dev eth$i vid 1 2>/dev/null || true
done
bridge vlan add dev eth1 vid 10 2>/dev/null || true          # trunk tới gateway
bridge vlan add dev eth1 vid 20 2>/dev/null || true
for p in 2 3 4 6; do bridge vlan add dev eth$p vid 10 pvid untagged 2>/dev/null || true; done   # access VLAN10
bridge vlan add dev eth5 vid 20 pvid untagged 2>/dev/null || true                               # access VLAN20
# Mirror CHỈ chiều ingress của cổng 1-6 -> eth7: mỗi frame vào switch đúng 1 lần nên không bị nhân đôi
for i in 1 2 3 4 5 6; do
  tc qdisc del dev eth$i ingress 2>/dev/null || true
  tc qdisc add dev eth$i ingress
  tc filter add dev eth$i parent ffff: protocol all u32 match u8 0 0 action mirred egress mirror dev eth7
done'

echo "[2/6] Gateway: sub-interface VLAN + ip_forward"
dx gw bash -ec '
sysctl -qw net.ipv4.ip_forward=1
ip link set eth1 up
ip link add link eth1 name eth1.10 type vlan id 10 2>/dev/null || true
ip link add link eth1 name eth1.20 type vlan id 20 2>/dev/null || true
ip addr replace 10.10.10.1/24 dev eth1.10; ip addr replace 10.20.20.1/24 dev eth1.20
ip link set eth1.10 up; ip link set eth1.20 up'

echo "[3/6] Host IP"
cfg() { dx "$1" bash -ec "ip addr replace $2 dev eth1; ip link set eth1 up; ip route replace 10.0.0.0/8 via $3"; }
cfg dhcp     10.10.10.2/24  10.10.10.1
cfg h10a     10.10.10.11/24 10.10.10.1
cfg h10b     10.10.10.12/24 10.10.10.1
cfg attacker 10.10.10.66/24 10.10.10.1
cfg h20a     10.20.20.11/24 10.20.20.1

echo "[4/6] Sniffer: promisc, không IP"
dx sniffer bash -ec 'ip link set eth1 up; ip link set eth1 promisc on'

echo "[5/6] DHCP server hợp lệ (10.10.10.2) + web server trên h10a"
dx dhcp pkill dnsmasq 2>/dev/null || true
dxd dhcp dnsmasq --no-daemon --interface=eth1 --bind-interfaces --except-interface=lo --port=0 \
    --dhcp-range=10.10.10.100,10.10.10.150,12h --dhcp-option=3,10.10.10.1 \
    --dhcp-leasefile=/tmp/dnsmasq.leases --dhcp-authoritative
dx h10a pkill -f "http.server" 2>/dev/null || true
dxd h10a python3 -m http.server 80 --bind 10.10.10.11
sleep 1

echo "[6/6] Kiểm tra nhanh"
dx h10a ping -c 2 -W 1 10.10.10.1 >/dev/null && echo "  OK  h10a -> gw (VLAN10)"
dx h20a ping -c 2 -W 1 10.20.20.1 >/dev/null && echo "  OK  h20a -> gw (VLAN20)"
dx h20a ping -c 2 -W 1 10.10.10.11 >/dev/null && echo "  OK  h20a -> h10a (định tuyến liên VLAN qua gw)"
dx sniffer timeout 3 tcpdump -nn -c 3 -i eth1 >/dev/null 2>&1 && echo "  OK  sniffer thấy traffic mirror" || echo "  !!  sniffer chưa thấy gói: xem Troubleshooting (modprobe cls_u32 act_mirred)"
