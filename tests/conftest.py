import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def listener():
    """A real listening socket on 127.0.0.1 (ephemeral port)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    yield s
    s.close()


@pytest.fixture()
def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def synth():
    from netmon.anomaly import detect_all
    from netmon.flows import generate_synthetic
    flows, labels = generate_synthetic(seed=7)
    grid, dets = detect_all(flows, seed=7)
    return flows, labels, grid, dets
