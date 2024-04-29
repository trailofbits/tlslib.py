from __future__ import annotations

import contextlib
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import weakref
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from tlslib.insecure import InsecureConfiguration
from tlslib.insecure.stdlib_insecure import STDLIB_INSECURE_BACKEND
from tlslib.stdlib import (
    STDLIB_BACKEND,
    OpenSSLCertificate,
    OpenSSLPrivateKey,
    OpenSSLTrustStore,
    TLSVersion,
)
from tlslib.tlslib import (
    DEFAULT_CIPHER_LIST,
    Backend,
    CipherSuite,
    NextProtocol,
    RaggedEOF,
    ServerContext,
    SigningChain,
    TLSClientConfiguration,
    TLSError,
    TLSServerConfiguration,
    TLSSocket,
    WantReadError,
    WantWriteError,
)

_ASSETS = Path(__file__).parent / "assets"
assert _ASSETS.is_dir()

_Socket = TLSSocket | ssl.SSLSocket


def limbo_asset(id: str) -> dict[str, Any]:
    path = _ASSETS / f"{id}.json"
    return json.loads(path.read_text())


# Derived from CPython's `test_ssl.ThreadedEchoServer`,
# with simplifications (no socket wrapping/unwrapping).
class ThreadedEchoServer(threading.Thread):
    class ConnectionHandler(threading.Thread):
        def __init__(self, server: ThreadedEchoServer, sock: _Socket, addr):
            self.server = server
            self.sock = sock
            self.addr = addr

            self.running = False
            self.queue = []
            threading.Thread.__init__(self)
            self.daemon = True
            self.name = "client"

        def send(self, msg: bytes) -> None:
            self.sock.send(msg)
            self.server.server_sent.append(msg)

        def recv(self, amt: int) -> bytes:
            msg = self.sock.recv(amt)
            if msg == b"":
                return None
            self.server.server_recv.append(msg)
            return msg

        def run(self) -> None:
            self.running = True

            while self.running and self.server.active:
                # Normally there'd be some kind of real state machine here,
                # but ours is just a single transition of read->write.
                try:
                    msg = self.recv(1024)

                    if not msg:
                        self.running = False
                    else:
                        self.queue.append(msg)
                except (WantReadError, ssl.SSLWantReadError):
                    try:
                        msg = self.queue.pop(0)
                        self.send(b"echo: " + msg)
                    except IndexError:
                        continue
                except (WantWriteError, ssl.SSLWantWriteError):
                    continue
                except RaggedEOF:
                    self.running = False
                except Exception:
                    raise

    def __init__(
        self,
        backend: Backend | None,
        cert_chain,
        min_tls_version,
        max_tls_version,
        inner_protocols,
        ciphers,
        trust_store,
    ):
        self.server_context: ServerContext | ssl.SSLContext
        if backend is not None:
            self.backend = backend
            server_configuration = backend.server_configuration(
                certificate_chain=cert_chain,
                ciphers=ciphers,
                inner_protocols=inner_protocols,
                lowest_supported_version=min_tls_version,
                highest_supported_version=max_tls_version,
                trust_store=trust_store,
            )
            self.server_context = backend.server_context(server_configuration)
        else:
            self.backend = None
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = min_tls_version
            server_context.maximum_version = max_tls_version
            server_context.options |= ssl.OP_NO_COMPRESSION
            server_context.verify_flags = (
                ssl.VerifyFlags.VERIFY_X509_STRICT | ssl.VerifyFlags.VERIFY_X509_PARTIAL_CHAIN
            )
            assert isinstance(cert_chain, os.PathLike)
            server_context.load_cert_chain(cert_chain)
            server_context.set_ciphers("ALL:COMPLEMENTOFALL")
            if inner_protocols is not None:
                server_context.set_alpn_protocols(inner_protocols)
            if trust_store is not None:
                server_context.load_verify_locations(trust_store)
                server_context.verify_mode = ssl.CERT_REQUIRED
            self.server_context = server_context

        self.active = False
        self.flag: threading.Event | None = None
        threading.Thread.__init__(self)
        self.name = "server"
        self.daemon = True
        self.peer_cert = None

        self.server_sent = []
        self.server_recv = []

        self.server_negotiated_protocol = None

    def __enter__(self):
        self.start(threading.Event())
        self.flag.wait()
        return self

    def __exit__(self, *args):
        self.stop()
        self.join()

    def start(self, flag=None) -> None:
        self.flag = flag
        if self.backend is not None:
            self.socket = self.server_context.connect(("127.0.0.1", 0))
        else:
            sock = socket.create_server(("127.0.0.1", 0))
            self.socket = self.server_context.wrap_socket(sock=sock, server_side=True)
            self.socket.setblocking(False)

        return super().start()

    def run(self) -> None:
        self.socket.listen(1)
        self.active = True
        if self.flag:
            self.flag.set()
        while self.active:
            try:
                newconn, connaddr = self.socket.accept()
                self.peer_cert = newconn.getpeercert()
                prot = None
                if self.backend is not None:
                    prot = newconn.negotiated_protocol()
                else:
                    newconn.setblocking(False)
                    prot = newconn.selected_alpn_protocol()
                    print(self.peer_cert)

                if prot is None:
                    handler = self.ConnectionHandler(self, newconn, connaddr)
                    handler.start()
                    handler.join()
                else:
                    self.server_negotiated_protocol = prot

            except BlockingIOError:
                # Would have blocked on accept; busy loop instead.
                continue
            except (TLSError, ssl.SSLError) as exc:
                print(exc)
                # Something went wrong during the handshake.
                # TODO: Currently treating as busy loop, but we can also choose
                # to gracefully shut down here?
                continue
            except Exception:
                # TODO: Figure out if there are other things we should mask or
                # catch here.
                raise

        if self.socket:
            self.socket.close()
            self.socket = None

    def stop(self):
        self.active = False


def limbo_server(id: str) -> tuple[ThreadedEchoServer, TLSClientConfiguration]:
    """
    Return a `ThreadedServer` and a `TLSClientConfiguration` suitable for connecting to it,
    both instantiated with an `sslib` backend and state from the given Limbo testcase.
    """

    testcase = limbo_asset(id)

    peer_cert = OpenSSLCertificate.from_buffer(testcase["peer_certificate"].encode())
    peer_cert_key = None
    if testcase["peer_certificate_key"] is not None:
        peer_cert_key = OpenSSLPrivateKey.from_buffer(testcase["peer_certificate_key"].encode())
    untrusted_intermediates = []
    for pem in testcase["untrusted_intermediates"]:
        untrusted_intermediates.append(OpenSSLCertificate.from_buffer(pem.encode()))
    signing_chain = SigningChain(leaf=(peer_cert, peer_cert_key), chain=untrusted_intermediates)

    trusted_certs = []
    for pem in testcase["trusted_certs"]:
        trusted_certs.append(pem.encode())

    client_config = STDLIB_BACKEND.client_configuration(
        certificate_chain=None,
        ciphers=DEFAULT_CIPHER_LIST,
        inner_protocols=None,
        lowest_supported_version=TLSVersion.MINIMUM_SUPPORTED,
        highest_supported_version=TLSVersion.MAXIMUM_SUPPORTED,
        trust_store=STDLIB_BACKEND.trust_store.from_buffer(b"\n".join(trusted_certs)),
    )

    server = ThreadedEchoServer(
        STDLIB_BACKEND,
        (signing_chain,),
        TLSVersion.MINIMUM_SUPPORTED,
        TLSVersion.MAXIMUM_SUPPORTED,
        inner_protocols=None,
        ciphers=DEFAULT_CIPHER_LIST,
        trust_store=None,
    )

    return server, client_config


def tweak_client_config(
    old_config: TLSClientConfiguration,
    certificate_chain: SigningChain[OpenSSLCertificate, OpenSSLPrivateKey] | None = None,
    ciphers: Sequence[CipherSuite | int] | None = None,
    inner_protocols: Sequence[NextProtocol | bytes] | None = None,
    lowest_supported_version: TLSVersion | None = None,
    highest_supported_version: TLSVersion | None = None,
    trust_store: OpenSSLTrustStore | None = None,
) -> TLSClientConfiguration:
    if certificate_chain is None:
        certificate_chain = old_config.certificate_chain

    if ciphers is None:
        ciphers = old_config.ciphers

    if inner_protocols is None:
        inner_protocols = old_config.inner_protocols

    if lowest_supported_version is None:
        lowest_supported_version = old_config.lowest_supported_version

    if highest_supported_version is None:
        highest_supported_version = old_config.highest_supported_version

    if trust_store is None:
        trust_store = old_config.trust_store

    return TLSClientConfiguration(
        certificate_chain=certificate_chain,
        ciphers=ciphers,
        inner_protocols=inner_protocols,
        lowest_supported_version=lowest_supported_version,
        highest_supported_version=highest_supported_version,
        trust_store=trust_store,
    )


def tweak_server_config(
    server: ThreadedEchoServer,
    certificate_chain: Sequence[SigningChain[OpenSSLCertificate, OpenSSLPrivateKey]] | None = None,
    ciphers: Sequence[CipherSuite | int] | None = None,
    inner_protocols: Sequence[NextProtocol | bytes] | None = None,
    lowest_supported_version: TLSVersion | None = None,
    highest_supported_version: TLSVersion | None = None,
    trust_store: OpenSSLTrustStore | None = None,
    insecure_config: InsecureConfiguration | None = None,
) -> ThreadedEchoServer:
    old_config = server.server_context.configuration

    if certificate_chain is None:
        certificate_chain = old_config.certificate_chain

    if ciphers is None:
        ciphers = old_config.ciphers

    if inner_protocols is None:
        inner_protocols = old_config.inner_protocols

    if lowest_supported_version is None:
        lowest_supported_version = old_config.lowest_supported_version

    if highest_supported_version is None:
        highest_supported_version = old_config.highest_supported_version

    if trust_store is None:
        trust_store = old_config.trust_store

    new_config = TLSServerConfiguration(
        certificate_chain=certificate_chain,
        ciphers=ciphers,
        inner_protocols=inner_protocols,
        lowest_supported_version=lowest_supported_version,
        highest_supported_version=highest_supported_version,
        trust_store=trust_store,
    )

    if insecure_config is not None:
        server.backend = STDLIB_INSECURE_BACKEND
        server.server_context = server.backend.insecure_server_context(new_config, insecure_config)
    else:
        server.server_context = server.backend.server_context(new_config)

    return server


def limbo_server_ssl(
    id: str, client_id: str | None = None
) -> tuple[ThreadedEchoServer, TLSClientConfiguration]:
    """
    Return a `ThreadedServer` and a `TLSClientConfiguration` suitable for connecting to it,
    both instantiated with an `sslib` backend and state from the given Limbo testcase.
    """

    testcase = limbo_asset(id)

    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as io:
        io.write(testcase["peer_certificate"].encode())
        io.write(b"\n")
        if testcase["peer_certificate_key"] is not None:
            io.write(testcase["peer_certificate_key"].encode())
            io.write(b"\n")
        for pem in testcase["untrusted_intermediates"]:
            io.write(pem.encode())
            io.write(b"\n")

    trusted_certs = []
    for pem in testcase["trusted_certs"]:
        trusted_certs.append(pem.encode())

    sign_chain_client = None
    server_trust_store = None
    if client_id is not None:
        testcase_client = limbo_asset(client_id)
        peer_cert = OpenSSLCertificate.from_buffer(testcase_client["peer_certificate"].encode())
        peer_cert_key = None
        if testcase_client["peer_certificate_key"] is not None:
            peer_cert_key = OpenSSLPrivateKey.from_buffer(
                testcase_client["peer_certificate_key"].encode()
            )
        untrusted_intermediates = []
        for pem in testcase_client["untrusted_intermediates"]:
            untrusted_intermediates.append(OpenSSLCertificate.from_buffer(pem.encode()))
        sign_chain_client = SigningChain(
            leaf=(peer_cert, peer_cert_key), chain=untrusted_intermediates
        )

        trusted_certs_client = []
        for pem in testcase_client["trusted_certs"]:
            trusted_certs_client.append(pem.encode())

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as io_client:
            for pem in testcase_client["trusted_certs"]:
                io_client.write(pem.encode())
                io_client.write(b"\n")
        server_trust_store = Path(io_client.name)

    client_config = STDLIB_BACKEND.client_configuration(
        certificate_chain=sign_chain_client,
        ciphers=DEFAULT_CIPHER_LIST,
        inner_protocols=None,
        lowest_supported_version=TLSVersion.MINIMUM_SUPPORTED,
        highest_supported_version=TLSVersion.MAXIMUM_SUPPORTED,
        trust_store=STDLIB_BACKEND.trust_store.from_buffer(b"\n".join(trusted_certs)),
    )

    protocols = []
    for np in NextProtocol:
        protocols.append(np.value.decode("ascii"))

    server = ThreadedEchoServer(
        None,
        Path(io.name),
        ssl.TLSVersion.MINIMUM_SUPPORTED,
        ssl.TLSVersion.MAXIMUM_SUPPORTED,
        inner_protocols=protocols,
        ciphers=DEFAULT_CIPHER_LIST,
        trust_store=server_trust_store,
    )
    if client_id is not None:
        weakref.finalize(server, os.remove, io_client.name)

    weakref.finalize(server, os.remove, io.name)

    return server, client_config


class RetryContextManager(contextlib.ContextDecorator):
    """
    Context manager used by `retry_loop()` to ignore exceptions
    and retry until a max number of attempts has been reached.
    See `retry_loop()` for more details.
    """

    def __init__(self, is_last_attempt: bool):
        self.exit_success: bool = False
        self.is_last_attempt: bool = is_last_attempt

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        self.exit_success = exc_type is None
        # Supress any exception if this is not the last attempt
        if not self.is_last_attempt:
            return True


def retry_loop(max_attempts: int, wait: float) -> Iterator[RetryContextManager]:
    """
    Generator that yields a context manager to use in code blocks that should be retried
    if an exception occurs. Usage:
    ```
    for attempt in retry_loop(max_attempts=3, wait=0.1):
        with attempt:
            self.assertEqual(server.server_recv, [b"message 1", b"message 2"])
    ```
    """
    for i in range(max_attempts):
        is_last_attempt = i == max_attempts - 1
        current_attempt = RetryContextManager(is_last_attempt)
        yield current_attempt
        if current_attempt.exit_success:
            break
        else:
            time.sleep(wait)
