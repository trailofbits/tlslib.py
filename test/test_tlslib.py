"""
Tests for `tlslib.tlslib`.
"""

from unittest import TestCase

from tlslib import tlslib


class TestTLSImplementation(TestCase):
    def test_implementation_types(self):
        class ClientContext:
            pass

        class ServerContext:
            pass

        def validate_config(
            tls_config: tlslib.TLSClientConfiguration | tlslib.TLSServerConfiguration,
        ) -> None:
            return None

        implementation = tlslib.TLSImplementation(
            client_context=ClientContext,
            server_context=ServerContext,
            validate_config=validate_config,
        )

        self.assertIs(implementation.client_context, ClientContext)
        self.assertIs(implementation.server_context, ServerContext)

        self.assertIs(implementation.validate_config, validate_config)


class AbstractFunctions(TestTLSImplementation):
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
