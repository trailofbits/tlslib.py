"""
Tests for `tlslib.stdlib`.
"""

from pathlib import Path
from unittest import TestCase

from tlslib import stdlib, tlslib

from ._utils import limbo_server


class TestOpenSSLTrustStore(TestCase):
    def test_init(self):
        path = Path("/tmp/not-real")
        store = stdlib.OpenSSLTrustStore(path)
        self.assertEqual(store._trust_path, path)

        system_store = stdlib.OpenSSLTrustStore()
        self.assertNotEqual(store, system_store)

        system_store_explicit = stdlib.OpenSSLTrustStore(None)
        self.assertNotEqual(store, system_store_explicit)


class TestBackend(TestCase):
    def test_backend_types(self):
        backend = stdlib.STDLIB_BACKEND

        self.assertIs(backend.certificate, stdlib.OpenSSLCertificate)
        self.assertIs(backend.client_context, stdlib.OpenSSLClientContext)
        self.assertIs(backend.private_key, stdlib.OpenSSLPrivateKey)
        self.assertIs(backend.server_context, stdlib.OpenSSLServerContext)
        self.assertIs(backend.trust_store, stdlib.OpenSSLTrustStore)

        # invariant properties
        self.assertIs(backend.client_configuration, tlslib.TLSClientConfiguration)
        self.assertIs(backend.server_configuration, tlslib.TLSServerConfiguration)


class TestBasic(TestBackend):
    def test_trivial_connection(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            client_sock.send(b"message 1")
            client_sock.send(b"message 2")
            client_sock.recv(1024)
            client_sock.recv(1024)
            client_sock.close()

            self.assertEqual(server.server_recv, [b"message 1", b"message 2"])
            self.assertEqual(server.server_sent, [b"echo: message 1", b"echo: message 2"])
