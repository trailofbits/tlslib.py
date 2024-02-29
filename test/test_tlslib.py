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
