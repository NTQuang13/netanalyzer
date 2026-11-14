from netanalyzer.live import replay
from netanalyzer.policy import load_policy

POL = load_policy("policy.yml")


def test_live_replay_detects_all_types():
    types = {a["type"] for a in replay("pcaps/synthetic/mixed.pcap", POL)}
    assert types == {"port_scan", "arp_spoof", "rogue_dhcp", "broadcast_storm", "vlan_violation"}


def test_live_clean_has_no_alert():
    assert replay("pcaps/synthetic/clean.pcap", POL) == []


def test_live_dedup_cooldown():
    al = replay("pcaps/synthetic/arpspoof.pcap", POL, cooldown=1e9)
    keys = [(a["type"], a["ip"]) for a in al]
    assert len(keys) == len(set(keys))
