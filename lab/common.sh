# Hàm dùng chung. Dùng:  source lab/common.sh
LAB="${LAB:-nta}"
dx()  { local n="$1"; shift; docker exec "clab-$LAB-$n" "$@"; }          # chạy lệnh trong node
dxd() { local n="$1"; shift; docker exec -d "clab-$LAB-$n" "$@"; }       # chạy nền
