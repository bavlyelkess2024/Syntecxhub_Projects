import threading

import pytest

from secure_transfer import crypto
from secure_transfer.certs import generate_self_signed
from secure_transfer.client import Client
from secure_transfer.server import Storage, TransferServer

TOKEN = "test-token"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Cheaper scrypt so the test-suite stays fast."""
    orig = crypto.derive_keys
    monkeypatch.setattr("secure_transfer.client.derive_keys",
                        lambda pw, salt: orig(pw, salt, n=2 ** 10))


@pytest.fixture
def env(tmp_path):
    cert, key = str(tmp_path / "c.crt"), str(tmp_path / "c.key")
    generate_self_signed(cert, key)
    srv = TransferServer(("127.0.0.1", 0), Storage(str(tmp_path / "data")), TOKEN, cert, key)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def connect(token=TOKEN):
        return Client("127.0.0.1", port, token, cert)

    yield type("Env", (), {"connect": staticmethod(connect), "tmp": tmp_path,
                           "data": tmp_path / "data"})
    srv.shutdown()
    srv.server_close()
