import os

import pytest

from netanalyzer.detectors import run_all
from netanalyzer.evaluate import discover, load_truth
from netanalyzer.parser import pcap_to_df
from netanalyzer.policy import load_policy

POLICY = load_policy("policy.yml")
CASES = discover("pcaps", load_truth("tests/ground_truth.yml"))


@pytest.mark.parametrize("engine", ["fast", "scapy"])
@pytest.mark.parametrize("rel,path,expected", CASES, ids=[c[0] for c in CASES])
def test_detection_exact(rel, path, expected, engine):
    found = {a["type"] for a in run_all(pcap_to_df(path, engine), POLICY)}
    assert found == expected, f"{rel}: thiếu {expected - found}, thừa {found - expected}"


def test_arp_whitelist_vrrp():
    from netanalyzer.detectors import detect_arp_spoof
    import pandas as pd
    df = pd.DataFrame([dict(proto="ARP", arp_psrc="10.0.0.1", arp_hwsrc="00:00:5e:00:01:01", ts=1.0),
                       dict(proto="ARP", arp_psrc="10.0.0.1", arp_hwsrc="00:00:5e:00:01:02", ts=2.0)])
    assert detect_arp_spoof(df, ignore_mac_prefixes=["00:00:5e:00:01"]) == []
    assert len(detect_arp_spoof(df)) == 1


def test_scan_below_threshold_not_flagged():
    from netanalyzer.detectors import detect_port_scan
    df = pcap_to_df("pcaps/synthetic/portscan.pcap")
    assert detect_port_scan(df, window_s=5, min_ports=500) == []


def test_slow_scan_detected_by_long_window():
    from netanalyzer.detectors import detect_port_scan
    import pandas as pd
    rows = [dict(proto="TCP", tcp_flags="S", src_ip="1.1.1.1", dst_ip="2.2.2.2", dport=p, ts=p * 15.0)
            for p in range(1, 31)]                      # 1 cổng / 15 s, kiểu nmap -T1
    df = pd.DataFrame(rows)
    assert detect_port_scan(df, window_s=5, min_ports=20) == []
    assert len(detect_port_scan(df, window_s=300, min_ports=15)) == 1
