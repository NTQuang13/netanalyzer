import glob

import numpy as np
import pandas as pd
import pytest

from netanalyzer.parser import pcap_to_df

FILES = sorted(glob.glob("pcaps/synthetic/*.pcap"))


@pytest.mark.parametrize("f", FILES)
def test_fast_equals_scapy(f):
    a, b = pcap_to_df(f, "scapy"), pcap_to_df(f, "fast")
    assert len(a) == len(b)
    assert np.allclose(a["ts"], b["ts"], atol=1e-5, rtol=0)
    cols = [c for c in a.columns if c not in ("ts", "time")]
    pd.testing.assert_frame_equal(a[cols], b[cols], check_dtype=False)


def test_fields_parsed():
    df = pcap_to_df("pcaps/synthetic/clean.pcap")
    assert {"ARP", "ICMP", "TCP", "DHCP", "DNS"} <= set(df["proto"])
    assert df["vlan"].dropna().isin([10, 20]).all()
    assert set(df["dhcp_type"].dropna()) == {"discover", "offer", "request", "ack"}
    assert "example.com." in set(df["dns_qname"].dropna())
