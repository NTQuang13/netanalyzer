#!/usr/bin/env bash
# Bắt pcap cho cả 6 kịch bản (+ vài biến thể nmap). Chạy:  lab/run_all.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for sc in clean portscan arpspoof rogue_dhcp bcast vlan_viol; do
  bash "$HERE/run_scenario.sh" "$sc"; sleep 3
done
NMAP_TIMING=-T3 bash "$HERE/run_scenario.sh" portscan portscan_T3; sleep 3
NMAP_TIMING=-T5 bash "$HERE/run_scenario.sh" portscan portscan_T5; sleep 3
bash "$HERE/run_scenario.sh" clean clean2
echo "Xong. Chạy:  python -m netanalyzer.cli evaluate"
