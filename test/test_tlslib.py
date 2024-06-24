"""
Tests for `tlslib.tlslib`.
"""

from unittest import TestCase

from tlslib import tlslib


class TestBackend(TestCase):
    def test_backend_types(self):
        class ClientContext:
            pass

        class ServerContext:
            pass

        def validate_config(
            tls_config: tlslib.TLSClientConfiguration | tlslib.TLSServerConfiguration,
        ) -> None:
            return None

        backend = tlslib.Backend(
            client_context=ClientContext,
            server_context=ServerContext,
            validate_config=validate_config,
        )

        self.assertIs(backend.client_context, ClientContext)
        self.assertIs(backend.server_context, ServerContext)

        self.assertIs(backend.validate_config, validate_config)


class AbstractFunctions(TestBackend):
    def test_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            tlslib.TLSSocket.fileno(tlslib.TLSSocket)

    def test_pure_types(self):
        self.assertIsInstance(tlslib.TrustStore.from_buffer(b""), tlslib.TrustStore)
        self.assertIsInstance(tlslib.TrustStore.from_file(""), tlslib.TrustStore)
        self.assertIsInstance(tlslib.TrustStore.from_id(b""), tlslib.TrustStore)
        self.assertIsInstance(tlslib.TrustStore.from_id(b""), tlslib.TrustStore)
        self.assertIsInstance(tlslib.TrustStore.system(), tlslib.TrustStore)
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
        tlslib.ClientContext.__init__(tlslib.ClientContext, tlslib.TLSClientConfiguration())
        tlslib.ServerContext.__init__(tlslib.ClientContext, tlslib.TLSServerConfiguration())
