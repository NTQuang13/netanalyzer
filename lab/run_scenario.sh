#!/usr/bin/env bash
# Dùng:  lab/run_scenario.sh <kịch_bản> [tên_file_ra]
#   kịch bản: clean | portscan | arpspoof | rogue_dhcp | bcast | vlan_viol
# Bắt gói trên sniffer, chạy kịch bản, lưu vào pcaps/lab/<tên>.pcap
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/common.sh"
SC="${1:?thiếu tên kịch bản}"; NAME="${2:-$SC}"
OUT="$HERE/../pcaps/lab"; mkdir -p "$OUT"
[ -f "$HERE/attacks/$SC.sh" ] || { echo "không có attacks/$SC.sh"; exit 1; }

dx sniffer rm -f "/tmp/$NAME.pcap"
dxd sniffer tcpdump -i eth1 -nn -U -s 0 -w "/tmp/$NAME.pcap"
sleep 2
echo ">>> chạy kịch bản: $SC"
bash "$HERE/attacks/$SC.sh"
sleep 2
dx sniffer pkill -INT tcpdump || true
sleep 1
docker cp "clab-$LAB-sniffer:/tmp/$NAME.pcap" "$OUT/$NAME.pcap"
echo ">>> đã lưu $OUT/$NAME.pcap ($(du -h "$OUT/$NAME.pcap" | cut -f1))"
