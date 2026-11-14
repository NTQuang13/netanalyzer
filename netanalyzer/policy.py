"""Nạp policy.yml và gộp với giá trị mặc định."""
import copy
import yaml

DEFAULT_POLICY = {
    "portscan": {"window_s": 5, "min_ports": 20},
    "portscan_slow": {"enabled": True, "window_s": 300, "min_ports": 15},
    "arp_spoof": {
        "ignore_ips": [],
        # VRRP (00:00:5e:00:01:xx) và HSRP (00:00:0c:07:ac:xx): một IP ảo, nhiều router
        "ignore_mac_prefixes": ["00:00:5e:00:01", "00:00:0c:07:ac"],
    },
    "dhcp": {"allowed_servers": []},
    "bcast": {"max_pps": 200},
    "vlan_subnets": {},
    "vlan_deny_flows": [],
}


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_policy(path=None):
    if not path:
        return copy.deepcopy(DEFAULT_POLICY)
    with open(path, encoding="utf-8") as f:
        return _merge(DEFAULT_POLICY, yaml.safe_load(f) or {})
