#!/usr/bin/env bash
# Port scan SYN. Đổi tốc độ:  NMAP_TIMING=-T2 PORTS=1-200 lab/run_scenario.sh portscan portscan_T2
HERE="$(cd "$(dirname "$0")/.." && pwd)"; source "$HERE/common.sh"
dx attacker nmap -sS -Pn -n "${NMAP_TIMING:--T4}" -p "${PORTS:-1-1000}" 10.10.10.11
