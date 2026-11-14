import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)


@pytest.fixture(scope="session", autouse=True)
def synthetic_pcaps():
    from netanalyzer.synth import generate
    generate(os.path.join(ROOT, "pcaps", "synthetic"))   # xác định => luôn giống nhau
