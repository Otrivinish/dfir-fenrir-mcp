"""TLS context: 1.3 floor always; RFC 5280 strict mode kept for the system trust
store, relaxed only under a pinned internal CA (generate-certs.sh CAs lack the
keyUsage extension that Python 3.13+ strict mode demands)."""

import shutil
import ssl
import subprocess

import pytest

from fenrir_mcp import client


def test_system_store_keeps_strict_and_tls13():
    ctx = client.ssl_context()
    assert ctx.verify_flags & ssl.VERIFY_X509_STRICT
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not available")
def test_pinned_ca_relaxes_only_strict_flag(monkeypatch, tmp_path):
    key, crt = tmp_path / "ca.key", tmp_path / "ca.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "1", "-subj", "/CN=Test CA"],
        check=True, capture_output=True,
    )
    monkeypatch.setenv("FENRIR_CA_CERT", str(crt))
    ctx = client.ssl_context()
    assert not (ctx.verify_flags & ssl.VERIFY_X509_STRICT)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED
