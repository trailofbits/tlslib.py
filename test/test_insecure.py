"""
Tests for `tlslib.stdlib`.
"""

import warnings
from unittest import TestCase

with warnings.catch_warnings():
    warnings.filterwarnings(
        "ignore",
        message="Using an InsecureBackend is insecure. This should not be used in production.",
    )
    from tlslib import insecure, tlslib
    from tlslib.insecure import SecurityWarning, stdlib_insecure

    from ._utils import (
        handshake_buffers,
        limbo_server,
        loop_until_success,
        retry_loop,
        tweak_client_config,
        tweak_server_config,
        write_until_read,
    )


class TestInsecureBackend(TestCase):
    def test_insecure_backend_types(self):
        insecure_backend = stdlib_insecure.STDLIB_INSECURE_BACKEND

        self.assertIs(insecure_backend.certificate, stdlib_insecure.Certificate)
        self.assertIs(insecure_backend.client_context, stdlib_insecure.OpenSSLClientContext)
        self.assertIs(insecure_backend.private_key, stdlib_insecure.PrivateKey)
        self.assertIs(insecure_backend.server_context, stdlib_insecure.OpenSSLServerContext)
        self.assertIs(
            insecure_backend.insecure_client_context, stdlib_insecure.OpenSSLInsecureClientContext
        )
        self.assertIs(
            insecure_backend.insecure_server_context, stdlib_insecure.OpenSSLInsecureServerContext
        )

        # invariant properties
        self.assertIs(insecure_backend.client_configuration, tlslib.TLSClientConfiguration)
        self.assertIs(insecure_backend.server_configuration, tlslib.TLSServerConfiguration)
        self.assertIs(insecure_backend.insecure_configuration, insecure.InsecureConfiguration)


class TestBasic(TestInsecureBackend):
    def test_trivial_connection_insecure(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        # Overwrite client TrustStore to remove needed root certificate
        new_client_config = tweak_client_config(client_config, trust_store=None)
        with self.assertWarns(SecurityWarning):
            insecure_config = stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_configuration(
                True, True
            )

        with server:
            with self.assertWarns(SecurityWarning):
                insecure_client_context = (
                    stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_client_context(
                        new_client_config, insecure_config
                    )
                )

            with self.assertWarns(SecurityWarning):
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
            self.assertIsInstance(client_sock.getpeercert(), bytes)
            self.assertIsInstance(client_sock.fileno(), int)
            self.assertIsInstance(
                insecure_client_context.insecure_configuration, insecure.InsecureConfiguration
            )
            self.assertEqual(insecure_client_context.insecure_configuration, insecure_config)

            while True:
                try:
                    client_sock.close(False)
                    break
                except tlslib.WantReadError:
                    continue

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
        truststore = stdlib_insecure.STDLIB_INSECURE_BACKEND.trust_store.system()

        with self.assertWarns(SecurityWarning):
            insecure_config = stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_configuration(
                True, True
            )

        with self.assertWarns(SecurityWarning):
            server = tweak_server_config(
                server, trust_store=truststore, insecure_config=insecure_config
            )
        with self.assertWarns(SecurityWarning):
            with server:
                client_context = stdlib_insecure.STDLIB_INSECURE_BACKEND.client_context(
                    client_config
                )

                client_sock = client_context.connect(server.socket.getsockname())

                client_sock.send(b"message")
                while True:
                    try:
                        client_sock.close(False)
                        break
                    except tlslib.WantReadError:
                        continue

                self.assertEqual(server.server_context.insecure_configuration, insecure_config)

    def test_invalid_insecure_config(self):
        with self.assertRaises(ValueError):
            with self.assertWarns(SecurityWarning):
                _ = stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_configuration(False, True)


class TestBuffer(TestInsecureBackend):
    def test_trivial_connection_buffer_insecure(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")
        server_config = server.server_context.configuration
        backend = server.backend

        # Overwrite client TrustStore to remove needed root certificate
        new_client_config = tweak_client_config(client_config, trust_store=None)
        with self.assertWarns(SecurityWarning):
            insecure_config = stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_configuration(
                True, True
            )

        hostname = "localhost"

        with self.assertWarns(SecurityWarning):
            client_context = stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_client_context(
                new_client_config, insecure_config
            )
        server_context = backend.server_context(server_config)

        with self.assertWarns(SecurityWarning):
            client_buffer, server_buffer = handshake_buffers(
                client_context, server_context, hostname
            )

        write_until_read(client_buffer, server_buffer, b"message 1")
        write_until_read(server_buffer, client_buffer, b"echo: message 1")
        write_until_read(client_buffer, server_buffer, b"message 2")
        write_until_read(server_buffer, client_buffer, b"echo: message 2")

        self.assertEqual(client_buffer.negotiated_tls_version, tlslib.TLSVersion.TLSv1_3)
        self.assertEqual(client_buffer.cipher(), tlslib.CipherSuite.TLS_AES_256_GCM_SHA384)
        self.assertEqual(client_buffer.negotiated_protocol(), None)
        self.assertIsNotNone(client_buffer.getpeercert())
        # self.assertEqual(client_buffer.getpeername(), server.socket.getsockname())

        self.assertEqual(server_buffer.negotiated_tls_version, tlslib.TLSVersion.TLSv1_3)
        self.assertEqual(server_buffer.cipher(), tlslib.CipherSuite.TLS_AES_256_GCM_SHA384)
        self.assertEqual(server_buffer.negotiated_protocol(), None)
        self.assertIsNone(server_buffer.getpeercert())

        loop_until_success(client_buffer, server_buffer, "shutdown")

    def test_create_client_buffer_insecure(self):
        client_config = stdlib_insecure.STDLIB_INSECURE_BACKEND.client_configuration()

        for dhc, dv in ((True, True), (True, False), (False, False)):
            with self.assertWarns(SecurityWarning):
                insecure_config = stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_configuration(
                    dhc, dv
                )

            with self.assertWarns(SecurityWarning):
                insecure_client_context = (
                    stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_client_context(
                        client_config, insecure_config
                    )
                )

            with self.assertWarns(SecurityWarning):
                _ = insecure_client_context.create_buffer("localhost")

    def test_create_server_buffer_insecure(self):
        server_config = stdlib_insecure.STDLIB_INSECURE_BACKEND.server_configuration()

        for dhc, dv in ((True, True), (True, False), (False, False)):
            with self.assertWarns(SecurityWarning):
                insecure_config = stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_configuration(
                    dhc, dv
                )

            with self.assertWarns(SecurityWarning):
                insecure_server_context = (
                    stdlib_insecure.STDLIB_INSECURE_BACKEND.insecure_server_context(
                        server_config, insecure_config
                    )
                )

            with self.assertWarns(SecurityWarning):
                _ = insecure_server_context.create_buffer()
