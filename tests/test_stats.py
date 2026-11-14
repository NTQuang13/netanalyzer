import pytest

from netanalyzer import stats
from netanalyzer.parser import pcap_to_df
from netanalyzer.policy import load_policy
from netanalyzer.synth import HANDSHAKE_RTT_MS

df = pcap_to_df("pcaps/synthetic/clean.pcap")
POL = load_policy("policy.yml")


def test_rtt_matches_ground_truth():
    rtt = stats.tcp_handshake_rtt(df)
    assert len(rtt) == 5
    assert rtt["rtt_ms"].between(HANDSHAKE_RTT_MS - 0.01, HANDSHAKE_RTT_MS + 0.01).all()


def test_retransmission_rate():
    # 5 luồng x 2 gói dữ liệu + 1 gói gửi lại = 11 gói có payload, 1 trùng
    assert stats.retransmission_rate(df) == pytest.approx(1 / 11)


def test_routed_packets_not_counted_as_retrans():
    d = pcap_to_df("pcaps/synthetic/vlan_viol.pcap")
    assert stats.retransmission_rate(d) == 0.0


def test_vlan_eff_falls_back_to_subnet():
    d = stats.add_vlan_eff(df, POL["vlan_subnets"])
    assert set(d["vlan_eff"]) <= {0, 10, 20}
    assert (d.loc[d["src_ip"] == "10.10.10.11", "vlan_eff"] == 10).all()


def test_top_talkers_and_hist():
    assert stats.top_talkers(df).iloc[0]["bytes"] > 0
    assert stats.pkt_size_hist(df).sum() == len(df)
