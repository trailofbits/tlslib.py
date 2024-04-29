"""
Tests for `tlslib.stdlib`.
"""

from unittest import TestCase

from tlslib import insecure, stdlib, tlslib

from ._utils import (
    limbo_server,
    retry_loop,
    tweak_client_config,
    tweak_server_config,
)


class TestInsecureBackend(TestCase):
    def test_insecure_backend_types(self):
        insecure_backend = stdlib.STDLIB_INSECURE_BACKEND

        self.assertIs(insecure_backend.certificate, stdlib.OpenSSLCertificate)
        self.assertIs(insecure_backend.client_context, stdlib.OpenSSLClientContext)
        self.assertIs(insecure_backend.private_key, stdlib.OpenSSLPrivateKey)
        self.assertIs(insecure_backend.server_context, stdlib.OpenSSLServerContext)
        self.assertIs(insecure_backend.insecure_client_context, stdlib.OpenSSLInsecureClientContext)
        self.assertIs(insecure_backend.insecure_server_context, stdlib.OpenSSLInsecureServerContext)

        # invariant properties
        self.assertIs(insecure_backend.client_configuration, tlslib.TLSClientConfiguration)
        self.assertIs(insecure_backend.server_configuration, tlslib.TLSServerConfiguration)


class TestBasic(TestInsecureBackend):
    def test_trivial_connection_insecure(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")
        new_client_config = tweak_client_config(client_config, trust_store=None)
        insecure_config = insecure.InsecureConfiguration(True)

        with server:
            insecure_client_context = stdlib.STDLIB_INSECURE_BACKEND.insecure_client_context(
                new_client_config, insecure_config
            )
            client_sock = insecure_client_context.connect(server.socket.getsockname())
            client_sock.send(b"message 1")
            client_sock.send(b"message 2")

            received = 0
            while received < 2:
                try:
                    client_sock.recv(1024)
                    received += 1
                except tlslib.WantReadError:
                    continue

            self.assertEqual(client_sock.negotiated_tls_version, tlslib.TLSVersion.TLSv1_3)
            self.assertEqual(client_sock.cipher(), tlslib.CipherSuite.TLS_AES_256_GCM_SHA384)
            self.assertEqual(client_sock.negotiated_protocol(), None)
            self.assertEqual(client_sock.getpeername(), server.socket.getsockname())
            self.assertIsInstance(client_sock.getpeercert(), stdlib.OpenSSLCertificate)
            self.assertIsInstance(client_sock.fileno(), int)
            self.assertIsInstance(
                insecure_client_context.insecure_configuration, insecure.InsecureConfiguration
            )
            self.assertEqual(insecure_client_context.insecure_configuration, insecure_config)

            client_sock.close()

            self.assertEqual(client_sock.negotiated_tls_version, None)
            self.assertEqual(client_sock.cipher(), None)

            for attempt in retry_loop(max_attempts=3, wait=0.1):
                with attempt:
                    self.assertEqual(server.server_recv, [b"message 1", b"message 2"])
                    self.assertEqual(server.server_sent, [b"echo: message 1", b"echo: message 2"])
                    self.assertEqual(server.peer_cert, None)

    def test_insecure_server(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        # Enable client auth by setting a TrustStore
        truststore = stdlib.OpenSSLTrustStore(None)

        insecure_config = insecure.InsecureConfiguration(True)
        server = tweak_server_config(
            server, trust_store=truststore, insecure_config=insecure_config
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            client_sock.send(b"message")
            client_sock.close()

            self.assertEqual(server.server_context.insecure_configuration, insecure_config)
