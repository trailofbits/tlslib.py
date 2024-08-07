"""
Tests for `tlslib.stdlib`.
"""

import tempfile
from pathlib import Path
from unittest import TestCase

from tlslib import stdlib, tlslib

from ._utils import (
    handshake_buffers,
    limbo_server,
    limbo_server_ssl,
    loop_until_success,
    retry_loop,
    tweak_client_config,
    tweak_server_config,
    write_until_complete,
    write_until_read,
)


class TestTrustStore(TestCase):
    def test_init(self):
        path = Path("/tmp/not-real")
        store = tlslib.TrustStore(path=path)
        self.assertEqual(store._path, path)

        system_store = tlslib.TrustStore()
        self.assertNotEqual(store, system_store)

        system_store_explicit = tlslib.TrustStore(None, None, None)
        self.assertNotEqual(store, system_store_explicit)

        # Separate instantiations of the same store (even the system store)
        # are also not equal.
        self.assertNotEqual(system_store, system_store_explicit)

    def test_system_store_method(self):
        system_store = tlslib.TrustStore.system()
        system_store_init = tlslib.TrustStore()

        # Separate instantiations of the  system store not equal.
        self.assertNotEqual(system_store, system_store_init)


class TestOpenSSLTLSSocket(TestCase):
    def test_socket_init(self):
        with self.assertRaises(TypeError):
            stdlib.OpenSSLTLSSocket()


class TestTLSImplementation(TestCase):
    def test_implementation_types(self):
        implementation = stdlib.STDLIB_IMPLEMENTATION

        self.assertIs(implementation.client_context, stdlib.OpenSSLClientContext)
        self.assertIs(implementation.server_context, stdlib.OpenSSLServerContext)

        self.assertIs(implementation.validate_config, stdlib.validate_config)


class TestBasic(TestTLSImplementation):
    def test_trivial_connection(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
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
            self.assertIsInstance(client_sock.getpeercert(), bytes)
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
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(client_sock.negotiated_protocol(), tlslib.NextProtocol.H2)
            client_sock.close(True)
            for attempt in retry_loop(max_attempts=3, wait=0.1):
                with attempt:
                    self.assertEqual(server.server_negotiated_protocol, tlslib.NextProtocol.H2)

    def test_ssl_zero_return(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            client_sock.send(b"message 1")
            client_sock.send(b"message 2")

            try:
                client_sock.close(False)
            except tlslib.WantReadError:
                pass

            received = 0
            while received < 3:
                try:
                    client_sock.recv(1024)
                    received += 1
                except tlslib.WantReadError:
                    continue


class TestConfig(TestTLSImplementation):
    def test_config_system_trust_store_client(self):
        implementation = stdlib.STDLIB_IMPLEMENTATION

        system_store = None

        client_config = tlslib.TLSClientConfiguration(trust_store=system_store)
        client_context = implementation.client_context(client_config)
        client_sock = client_context.connect(("www.python.org", 443))
        self.assertEqual(client_sock.context.configuration.trust_store, system_store)
        client_sock.close(True)

    def test_config_file_trust_store_client(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(
                client_sock.context.configuration.trust_store, client_config.trust_store
            )
            client_sock.close(True)

    def test_config_file_truststore_server(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")
        # Add the server's signing certificate to the server's trust store, just so that it's not
        # empty

        truststore = tlslib.TrustStore.from_buffer(
            server.server_context.configuration.certificate_chain[0].leaf[0]._buffer
        )
        server = tweak_server_config(server, trust_store=truststore)

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            for attempt in retry_loop(max_attempts=3, wait=0.5):
                with attempt:
                    # Connection should have failed due to client not authenticating
                    with self.assertRaises(tlslib.TLSError):
                        client_sock.send(b"message")
            client_sock.close(True)

    def test_config_explicit_system_trust_store_server(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")
        truststore = tlslib.TrustStore()
        server = tweak_server_config(server, trust_store=truststore)
        stdlib.STDLIB_IMPLEMENTATION.validate_config(server.server_context.configuration)

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
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
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(client_sock.cipher(), 49245)
            client_sock.close(True)

    def test_config_weird_protocol(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(client_config, inner_protocols=(b"bla",))

        server = tweak_server_config(server, inner_protocols=(b"bla",))

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
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
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_config_signingchain_empty(self):
        cert = tlslib.Certificate.from_buffer(b"")
        key = tlslib.PrivateKey.from_buffer(b"")
        tlslib.SigningChain((cert, key), None)

        with tempfile.NamedTemporaryFile(mode="wb") as empty_file:
            cert = tlslib.Certificate.from_file(Path(empty_file.name))
            key = tlslib.PrivateKey.from_file(Path(empty_file.name))
            tlslib.SigningChain((cert, key), None)

    def test_context_signingchain_path(self):
        implementation = stdlib.STDLIB_IMPLEMENTATION
        with tempfile.NamedTemporaryFile(mode="wb") as empty_file:
            cert = tlslib.Certificate.from_file(Path(empty_file.name))
            key = tlslib.PrivateKey.from_file(Path(empty_file.name))
            sign_chain = tlslib.SigningChain((cert, key), (cert,))
            server_config = tlslib.TLSServerConfiguration(certificate_chain=(sign_chain,))
            server_context = implementation.server_context(server_config)
            with self.assertRaises(tlslib.TLSError):
                server_context.create_buffer()


class TestNegative(TestTLSImplementation):
    def test_no_client_ciphers(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(
            client_config,
            ciphers=(),
        )

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
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
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_bad_tls_version_option(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        new_client_config = tweak_client_config(
            client_config, highest_supported_version=tlslib.TLSVersion.MINIMUM_SUPPORTED
        )

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
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
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
            with self.assertRaises(tlslib.TLSError):
                client_sock = client_context.connect(server.socket.getsockname())
                client_sock.close(True)

    def test_send_too_much_data(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            with self.assertRaises(tlslib.WantWriteError):
                client_sock.send(b"a" * 10000000)

    def test_arbitrary_id_not_supported(self):
        implementation = stdlib.STDLIB_IMPLEMENTATION

        # Trust store with arbitrary ID
        trust_store = tlslib.TrustStore.from_id(b"")
        client_config = tlslib.TLSClientConfiguration(trust_store=trust_store)
        with self.assertRaises(tlslib.ConfigurationError):
            implementation.validate_config(client_config)

        with self.assertRaises(tlslib.ConfigurationError):
            client_context = implementation.client_context(client_config)
            client_context.create_buffer("test")

        # Leaf certificate with arbitrary ID
        certificate = tlslib.Certificate.from_id(b"")
        signing_chain = tlslib.SigningChain((certificate, None))
        server_config = tlslib.TLSServerConfiguration(certificate_chain=(signing_chain,))

        with self.assertRaises(tlslib.ConfigurationError):
            implementation.validate_config(server_config)

        with self.assertRaises(tlslib.ConfigurationError):
            server_context = implementation.server_context(server_config)
            server_context.create_buffer()

        # Chain certificate with arbitrary ID
        cert1 = tlslib.Certificate.from_buffer(b"")
        cert2 = tlslib.Certificate.from_id(b"")
        signing_chain = tlslib.SigningChain((cert1, None), (cert2,))
        server_config = tlslib.TLSServerConfiguration(certificate_chain=(signing_chain,))

        with self.assertRaises(tlslib.ConfigurationError):
            implementation.validate_config(server_config)

        with self.assertRaises(tlslib.ConfigurationError):
            server_context = implementation.server_context(server_config)
            server_context.create_buffer()

        # Private Key with arbitrary ID
        privkey = tlslib.PrivateKey.from_id(b"")
        certificate = tlslib.Certificate.from_file(Path("/tmp/not-real"))
        signing_chain = tlslib.SigningChain((certificate, privkey))
        server_config = tlslib.TLSServerConfiguration(certificate_chain=(signing_chain,))

        with self.assertRaises(tlslib.ConfigurationError):
            implementation.validate_config(server_config)

        with self.assertRaises(tlslib.ConfigurationError):
            server_context = implementation.server_context(server_config)
            server_context.create_buffer()

    def test_empty_cert(self):
        implementation = stdlib.STDLIB_IMPLEMENTATION

        # Empty leaf certificate
        certificate = tlslib.Certificate.from_id(b"")
        certificate._id = None
        signing_chain = tlslib.SigningChain((certificate, None))
        server_config = tlslib.TLSServerConfiguration(certificate_chain=(signing_chain,))

        with self.assertRaises(tlslib.ConfigurationError):
            implementation.validate_config(server_config)

        with self.assertRaises(tlslib.ConfigurationError):
            server_context = implementation.server_context(server_config)
            server_context.create_buffer()

        # Empty chain certificate
        cert1 = tlslib.Certificate.from_buffer(b"")
        cert2 = tlslib.Certificate.from_id(b"")
        cert2._id = None
        signing_chain = tlslib.SigningChain((cert1, None), (cert2,))
        server_config = tlslib.TLSServerConfiguration(certificate_chain=(signing_chain,))

        with self.assertRaises(tlslib.ConfigurationError):
            implementation.validate_config(server_config)

        with self.assertRaises(tlslib.ConfigurationError):
            server_context = implementation.server_context(server_config)
            server_context.create_buffer()


class TestClientAgainstSSL(TestTLSImplementation):
    def test_trivial_connection_ssl(self):
        server, client_config = limbo_server_ssl("webpki::san::exact-localhost-ip-san")

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
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
            self.assertIsInstance(client_sock.getpeercert(), bytes)
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

                    client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
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
                    client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
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

                    client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(new_client_config)
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

        stdlib.STDLIB_IMPLEMENTATION.validate_config(client_config)

        with server:
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
            client_sock = client_context.connect(server.socket.getsockname())
            self.assertEqual(client_sock.negotiated_tls_version, tlslib.TLSVersion.TLSv1_3)

            for attempt in retry_loop(max_attempts=3, wait=0.1):
                with attempt:
                    self.assertIsNotNone(server.peer_cert)
            client_sock.close(True)


class TestSNI(TestTLSImplementation):
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
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
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
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
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
            client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
            # Manually set the socket address to localhost instead of 127.0.0.1, so that the
            # certificate is valid
            client_sock = client_context.connect(("localhost", server.socket.getsockname()[1]))
            client_sock.close(True)


### Buffer tests
class TestOpenSSLTLSBuffer(TestCase):
    def test_buffer_init(self):
        with self.assertRaises(TypeError):
            stdlib.OpenSSLTLSBuffer()


class TestBuffer(TestTLSImplementation):
    def test_trivial_connection_buffer(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")
        server_config = server.server_context.configuration
        implementation = server.implementation

        hostname = "localhost"

        client_context = implementation.client_context(client_config)
        server_context = implementation.server_context(server_config)

        client_buffer, server_buffer = handshake_buffers(client_context, server_context, hostname)

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

    def test_read_into_buffer(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")
        server_config = server.server_context.configuration
        implementation = server.implementation

        hostname = "localhost"

        client_context = implementation.client_context(client_config)
        server_context = implementation.server_context(server_config)
        client_buffer, server_buffer = handshake_buffers(client_context, server_context, hostname)

        message = b"message 1"
        write_until_complete(client_buffer, server_buffer, message)
        read_buf = bytearray(1024)
        read_len = server_buffer.read(2 * len(message), read_buf)
        assert read_buf[:read_len] == message

    def test_create_client_buffer(self):
        client_config = tlslib.TLSClientConfiguration()
        client_context = stdlib.STDLIB_IMPLEMENTATION.client_context(client_config)
        client_buffer = client_context.create_buffer(None)

        self.assertEqual(client_buffer.context, client_context)
        self.assertIsNone(client_buffer.cipher())
        self.assertIsNone(client_buffer.negotiated_protocol())
        self.assertIsNone(client_buffer.negotiated_tls_version)
        self.assertEqual(client_buffer.incoming_bytes_buffered(), 0)

    def test_config_weird_cipher_id_buffer(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")

        new_client_config = tweak_client_config(
            client_config,
            ciphers=(49245,),
            highest_supported_version=tlslib.TLSVersion.TLSv1_2,
        )

        server = tweak_server_config(
            server,
            ciphers=(49245,),
        )

        server_config = server.server_context.configuration
        implementation = server.implementation

        hostname = "localhost"

        client_context = implementation.client_context(new_client_config)
        server_context = implementation.server_context(server_config)
        client_buffer, server_buffer = handshake_buffers(client_context, server_context, hostname)

        self.assertEqual(client_buffer.cipher(), 49245)
        self.assertEqual(server_buffer.cipher(), 49245)

    def test_protocol_negotiation_buffer(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")

        new_client_config = tweak_client_config(
            client_config, inner_protocols=(tlslib.NextProtocol.H2,)
        )

        server = tweak_server_config(server, inner_protocols=(tlslib.NextProtocol.H2,))

        server_config = server.server_context.configuration
        implementation = server.implementation

        hostname = "localhost"

        client_context = implementation.client_context(new_client_config)
        server_context = implementation.server_context(server_config)
        client_buffer, server_buffer = handshake_buffers(client_context, server_context, hostname)

        self.assertEqual(client_buffer.negotiated_protocol(), tlslib.NextProtocol.H2)
        self.assertEqual(server_buffer.negotiated_protocol(), tlslib.NextProtocol.H2)

    def test_bytes_protocol_negotiation_buffer(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")

        protocol = b"bla"

        new_client_config = tweak_client_config(client_config, inner_protocols=(protocol,))

        server = tweak_server_config(server, inner_protocols=(protocol,))

        server_config = server.server_context.configuration
        implementation = server.implementation

        hostname = "localhost"

        client_context = implementation.client_context(new_client_config)
        server_context = implementation.server_context(server_config)
        client_buffer, server_buffer = handshake_buffers(client_context, server_context, hostname)

        self.assertEqual(client_buffer.negotiated_protocol(), protocol)
        self.assertEqual(server_buffer.negotiated_protocol(), protocol)

    def test_zero_return(self):
        server, client_config = limbo_server("webpki::san::exact-localhost-dns-san")
        server_config = server.server_context.configuration
        implementation = server.implementation

        hostname = "localhost"

        client_context = implementation.client_context(client_config)
        server_context = implementation.server_context(server_config)

        client_buffer, server_buffer = handshake_buffers(client_context, server_context, hostname)

        client_buffer.write(b"message 1")
        client_buffer.write(b"message 2")

        self.assertRaises(tlslib.WantReadError, client_buffer.shutdown)

        client_bytes = client_buffer.process_outgoing(client_buffer.outgoing_bytes_buffered())
        server_buffer.process_incoming(client_bytes)

        buf = server_buffer.read(1024)
        self.assertEqual(buf, b"message 1")
        buf = server_buffer.read(1024)
        self.assertEqual(buf, b"message 2")

        server_buffer.write(b"echo: message 1")
        server_buffer.write(b"echo: message 2")
        server_buffer.shutdown()

        server_bytes = server_buffer.process_outgoing(server_buffer.outgoing_bytes_buffered())
        client_buffer.process_incoming(server_bytes)

        buf = client_buffer.read(1024)
        self.assertEqual(buf, b"echo: message 1")
        buf = client_buffer.read(1024)
        self.assertEqual(buf, b"echo: message 2")
        buf = client_buffer.read(1024)
        self.assertEqual(buf, b"")
