#!/usr/bin/env bash
# Traffic VLAN20 -> VLAN10 trái chính sách (gateway đang định tuyến tự do nên traffic đi được).
HERE="$(cd "$(dirname "$0")/.." && pwd)"; source "$HERE/common.sh"
dx h20a ping -c 5 10.10.10.11 >/dev/null || true
dx h20a nmap -Pn -sS -n -p 22,80 10.10.10.11 >/dev/null
dx h20a curl -s -m 3 -o /dev/null http://10.10.10.11/ || true
