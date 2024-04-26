"""
Tests for `tlslib.stdlib`.
"""

import tempfile
from pathlib import Path
from unittest import TestCase

from tlslib import stdlib, tlslib

from ._utils import (
    limbo_server,
    limbo_server_ssl,
    retry_loop,
    tweak_client_config,
    tweak_server_config,
)


class TestOpenSSLTrustStore(TestCase):
    def test_init(self):
        path = Path("/tmp/not-real")
        store = stdlib.OpenSSLTrustStore(path)
        self.assertEqual(store._trust_path, path)

        system_store = stdlib.OpenSSLTrustStore()
        self.assertNotEqual(store, system_store)

        system_store_explicit = stdlib.OpenSSLTrustStore(None)
        self.assertNotEqual(store, system_store_explicit)

        # Separate instantiations of the same store (even the system store)
        # are also not equal.
        self.assertNotEqual(system_store, system_store_explicit)

    def test_system_store_method(self):
        system_store = stdlib.OpenSSLTrustStore.system()
        system_store_init = stdlib.OpenSSLTrustStore()

        # Separate instantiations of the  system store not equal.
        self.assertNotEqual(system_store, system_store_init)


class TestOpenSSLTLSSocket(TestCase):
    def test_socket_init(self):
        with self.assertRaises(TypeError):
            stdlib.OpenSSLTLSSocket()


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

    def test_protocol_negotiation(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(
            client_config, inner_protocols=(tlslib.NextProtocol.H2,)
        )

        server = tweak_server_config(server, inner_protocols=(tlslib.NextProtocol.H2,))

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(client_sock.negotiated_protocol(), tlslib.NextProtocol.H2)
            client_sock.close(True)
            for attempt in retry_loop(max_attempts=3, wait=0.1):
                with attempt:
                    self.assertEqual(server.server_negotiated_protocol, tlslib.NextProtocol.H2)


class TestConfig(TestBackend):
    def test_config_system_trust_store_client(self):
        backend = stdlib.STDLIB_BACKEND

        system_store = None

        client_config = backend.client_configuration(trust_store=system_store)
        client_context = backend.client_context(client_config)
        client_sock = client_context.connect(("www.python.org", 443))
        self.assertEqual(client_sock.context.configuration.trust_store, system_store)
        client_sock.close(True)

    def test_config_file_trust_store_client(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(
                client_sock.context.configuration.trust_store, client_config.trust_store
            )
            client_sock.close(True)

    def test_config_file_truststore_server(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")
        # Add the server's signing certificate to the server's trust store, just so that it's not
        # empty
        truststore = stdlib.OpenSSLTrustStore.from_file(
            server.server_context.configuration.certificate_chain[0].leaf[0]._cert_path
        )
        server = tweak_server_config(server, trust_store=truststore)

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            for attempt in retry_loop(max_attempts=3, wait=0.5):
                with attempt:
                    # Connection should have failed due to client not authenticating
                    with self.assertRaises(tlslib.TLSError):
                        client_sock.send(b"message")
            client_sock.close(True)

    def test_config_explicit_system_trust_store_server(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")
        truststore = stdlib.OpenSSLTrustStore(None)
        server = tweak_server_config(server, trust_store=truststore)

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            for attempt in retry_loop(max_attempts=3, wait=0.5):
                with attempt:
                    # Connection should have failed due to client not authenticating
                    with self.assertRaises(tlslib.TLSError):
                        client_sock.send(b"message")
            client_sock.close(True)

    def test_config_weird_cipher_id(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(
            client_config,
            ciphers=(49245,),
            highest_supported_version=tlslib.TLSVersion.TLSv1_2,
        )

        server = tweak_server_config(
            server,
            ciphers=(49245,),
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(client_sock.cipher(), 49245)
            client_sock.close(True)

    def test_config_weird_protocol(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(client_config, inner_protocols=(b"bla",))

        server = tweak_server_config(server, inner_protocols=(b"bla",))

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(client_sock.negotiated_protocol(), b"bla")
            client_sock.close(True)
            for attempt in retry_loop(max_attempts=3, wait=0.1):
                with attempt:
                    self.assertEqual(server.server_negotiated_protocol, b"bla")

    def test_config_connection_signingchain_empty(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")
        server = tweak_server_config(server, certificate_chain=[])

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_config_signingchain_empty(self):
        cert = stdlib.OpenSSLCertificate.from_buffer(b"")
        key = stdlib.OpenSSLPrivateKey.from_buffer(b"")
        tlslib.SigningChain((cert, key), None)

        with tempfile.NamedTemporaryFile(mode="wb") as empty_file:
            cert = stdlib.OpenSSLCertificate.from_file(Path(empty_file.name))
            key = stdlib.OpenSSLPrivateKey.from_file(Path(empty_file.name))
            tlslib.SigningChain((cert, key), None)


class TestNegative(TestBackend):
    def test_no_client_ciphers(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(
            client_config,
            ciphers=(),
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_ciphers_mismatch(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(
            client_config,
            ciphers=(44,),
            highest_supported_version=tlslib.TLSVersion.TLSv1_2,
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_bad_tls_version_option(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(
            client_config, highest_supported_version=tlslib.TLSVersion.MINIMUM_SUPPORTED
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_protocol_version_mismatch(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        server = tweak_server_config(
            server,
            lowest_supported_version=tlslib.TLSVersion.TLSv1_3,
        )

        new_client_config = tweak_client_config(
            client_config, highest_supported_version=tlslib.TLSVersion.TLSv1_2
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_send_too_much_data(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            with self.assertRaises(tlslib.WantWriteError):
                client_sock.send(b"a" * 10000000)


class TestClientAgainstSSL(TestBackend):
    def test_trivial_connection_ssl(self):
        server, client_config = limbo_server_ssl("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
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

            client_sock.close(True)

            self.assertEqual(client_sock.negotiated_tls_version, None)
            self.assertEqual(client_sock.cipher(), None)

            for attempt in retry_loop(max_attempts=3, wait=0.1):
                with attempt:
                    self.assertEqual(server.server_recv, [b"message 1", b"message 2"])
                    self.assertEqual(server.server_sent, [b"echo: message 1", b"echo: message 2"])
                    self.assertEqual(server.peer_cert, None)

    def test_all_protocol_versions(self):
        server, client_config = limbo_server_ssl("webpki::san::exact-localhost-ip-san")

        with server:
            for tlsversion in tlslib.TLSVersion:
                with self.subTest(tlsversion=tlsversion):
                    if (
                        tlsversion == tlslib.TLSVersion.MINIMUM_SUPPORTED
                        or tlsversion == tlslib.TLSVersion.MAXIMUM_SUPPORTED
                    ):
                        continue

                    new_client_config = tweak_client_config(
                        client_config,
                        highest_supported_version=tlsversion,
                    )

                    client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
                    client_sock = client_context.connect(server.socket.getsockname())
                    self.assertEqual(client_sock.negotiated_tls_version, tlsversion)
                    self.assertEqual(client_sock.negotiated_protocol(), None)
                    self.assertEqual(client_sock.getpeername(), server.socket.getsockname())
                    while True:
                        try:
                            client_sock.close(False)
                            break
                        except tlslib.WantReadError:
                            continue
                    self.assertEqual(client_sock.negotiated_tls_version, None)
                    self.assertEqual(client_sock.cipher(), None)

    def test_all_ciphers(self):
        server, client_config = limbo_server_ssl("webpki::san::exact-localhost-ip-san")
        with server:
            for cipher in tlslib.CipherSuite:
                with self.subTest(cipher=cipher):
                    # We test v1.2 because it is not possible to disable ciphersuites
                    # in the stdlib for TLS v1.3
                    print(cipher)

                    new_client_config = tweak_client_config(
                        client_config,
                        ciphers=(cipher,),
                        highest_supported_version=tlslib.TLSVersion.TLSv1_2,
                    )
                    client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
                    try:
                        client_sock = client_context.connect(server.socket.getsockname())
                    except tlslib.TLSError:
                        continue

                    self.assertEqual(client_sock.negotiated_tls_version, tlslib.TLSVersion.TLSv1_2)
                    self.assertEqual(client_sock.cipher(), cipher)
                    self.assertEqual(client_sock.negotiated_protocol(), None)
                    self.assertEqual(client_sock.getpeername(), server.socket.getsockname())
                    while True:
                        try:
                            client_sock.close(False)
                            break
                        except tlslib.WantReadError:
                            continue
                    self.assertEqual(client_sock.negotiated_tls_version, None)
                    self.assertEqual(client_sock.cipher(), None)

    def test_all_next_protocols(self):
        server, client_config = limbo_server_ssl("webpki::san::exact-localhost-ip-san")

        with server:
            for np in tlslib.NextProtocol:
                with self.subTest(np=np):
                    new_client_config = tweak_client_config(client_config, inner_protocols=(np,))

                    client_context = stdlib.STDLIB_BACKEND.client_context(new_client_config)
                    client_sock = client_context.connect(server.socket.getsockname())
                    self.assertEqual(client_sock.negotiated_protocol(), np)
                    client_sock.close(True)
                    for attempt in retry_loop(max_attempts=3, wait=0.1):
                        with attempt:
                            self.assertEqual(
                                server.server_negotiated_protocol, np.value.decode("ascii")
                            )

    def test_client_auth(self):
        server, client_config = limbo_server_ssl(
            "webpki::san::exact-localhost-ip-san", "rfc5280::nc::nc-permits-email-exact"
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(client_sock.negotiated_tls_version, tlslib.TLSVersion.TLSv1_3)

            for attempt in retry_loop(max_attempts=3, wait=0.1):
                with attempt:
                    self.assertIsNotNone(server.peer_cert)
            client_sock.close(True)


class TestSNI(TestBackend):
    def test_trivial_connection_sni(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")
        server_example_com, _ = limbo_server("webpki::san::exact-dns-san")

        cert_chain_example_com = server_example_com.server_context.configuration.certificate_chain[
            0
        ]
        cert_chain_localhost = server.server_context.configuration.certificate_chain[0]

        server = tweak_server_config(
            server, certificate_chain=[cert_chain_example_com, cert_chain_localhost]
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            # Manually set the socket address to localhost instead of 127.0.0.1, so that the
            # certificate is valid
            client_sock = client_context.connect(("localhost", server.socket.getsockname()[1]))
            client_sock.close(True)

    def test_connection_sni_no_appropriate_certchain(self):
        server_example_com, client_config = limbo_server("webpki::san::exact-dns-san")
        cert_chain_example_com = server_example_com.server_context.configuration.certificate_chain[
            0
        ]

        # Use two certificates (to trigger the SNI logic) but make them both for `example.com`, so
        # that neither are correct for this server (127.0.0.1)
        server = tweak_server_config(
            server_example_com, certificate_chain=[cert_chain_example_com, cert_chain_example_com]
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_connection_sni_cert_no_san(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")
        server_no_san, _ = limbo_server("webpki::san::no-san")

        cert_chain_no_san = server_no_san.server_context.configuration.certificate_chain[0]
        cert_chain_localhost = server.server_context.configuration.certificate_chain[0]

        # The cert with no SAN should be ignored since there is another cert present that is valid
        server = tweak_server_config(
            server, certificate_chain=[cert_chain_no_san, cert_chain_localhost]
        )

        with server:
            client_context = stdlib.STDLIB_BACKEND.client_context(client_config)
            # Manually set the socket address to localhost instead of 127.0.0.1, so that the
            # certificate is valid
            client_sock = client_context.connect(("localhost", server.socket.getsockname()[1]))
            client_sock.close(True)
