#!/usr/bin/env bash
# Traffic bình thường (để đo false positive): ARP, ping, HTTP, DNS-less, DHCP chỉ với server hợp lệ.
HERE="$(cd "$(dirname "$0")/.." && pwd)"; source "$HERE/common.sh"
for h in h10a h10b h20a gw; do dx $h ip neigh flush all; done
dx h10b ping -c 10 -i 0.3 10.10.10.11 >/dev/null
dx h10a ping -c 3 10.10.10.1 >/dev/null
dx h20a ping -c 3 10.20.20.1 >/dev/null
for i in 1 2 3 4 5; do dx h10b curl -s -m 3 -o /dev/null http://10.10.10.11/ || true; sleep 0.5; done
# DORA với server hợp lệ; -sf /bin/true: không đổi cấu hình IP của host
dx h10b timeout 6 dhclient -d -sf /bin/true -pf /tmp/dhc.pid -lf /tmp/dhc.lease eth1 >/dev/null 2>&1 || true
sleep 1
