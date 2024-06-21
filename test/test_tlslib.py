"""
Tests for `tlslib.tlslib`.
"""

from unittest import TestCase

from tlslib import tlslib


class TestBackend(TestCase):
    def test_backend_types(self):
        class Certificate:
            pass

        class ClientContext:
            pass

        class PrivateKey:
            pass

        class ServerContext:
            pass

        class TrustStore:
            pass

        backend = tlslib.Backend(
            certificate=Certificate,
            client_context=ClientContext,
            private_key=PrivateKey,
            server_context=ServerContext,
            trust_store=TrustStore,
        )

        self.assertIs(backend.certificate, Certificate)
        self.assertIs(backend.client_context, ClientContext)
        self.assertIs(backend.private_key, PrivateKey)
        self.assertIs(backend.server_context, ServerContext)
        self.assertIs(backend.trust_store, TrustStore)

        # invariant properties
        self.assertIs(backend.client_configuration, tlslib.TLSClientConfiguration)
        self.assertIs(backend.server_configuration, tlslib.TLSServerConfiguration)


class AbstractFunctions(TestBackend):
    def test_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            tlslib.TLSSocket.fileno(tlslib.TLSSocket)

    def test_pure_types(self):
        self.assertIsInstance(tlslib.Certificate.from_buffer(b""), tlslib.Certificate)
        self.assertIsInstance(tlslib.Certificate.from_file(""), tlslib.Certificate)
        self.assertIsInstance(tlslib.Certificate.from_id(b""), tlslib.Certificate)
        self.assertIsInstance(tlslib.PrivateKey.from_buffer(b""), tlslib.PrivateKey)
        self.assertIsInstance(tlslib.PrivateKey.from_file(""), tlslib.PrivateKey)
        self.assertIsInstance(tlslib.PrivateKey.from_id(b""), tlslib.PrivateKey)
        with self.assertRaises(ValueError):
            tlslib.Certificate()
        with self.assertRaises(ValueError):
            tlslib.PrivateKey()

    def test_empty_protocols(self):
        tlslib.TrustStore.from_buffer(b"")
        tlslib.TrustStore.from_file("")
        tlslib.TrustStore.from_id(b"")
        tlslib.TrustStore.from_id(b"")
        tlslib.TrustStore.system()
        tlslib.ClientContext.__init__(tlslib.ClientContext, tlslib.TLSClientConfiguration())
        tlslib.ServerContext.__init__(tlslib.ClientContext, tlslib.TLSServerConfiguration())
