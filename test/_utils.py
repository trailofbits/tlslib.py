from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

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


def limbo_asset(id: str) -> dict[str, Any]:
    path = _ASSETS / f"{id}.json"
    return json.loads(path.read_text())


# Derived from CPython's `test_ssl.ThreadedEchoServer`,
# with simplifications (no socket wrapping/unwrapping).
class ThreadedEchoServer(threading.Thread):
    class ConnectionHandler(threading.Thread):
        def __init__(self, server: ThreadedEchoServer, sock: TLSSocket, addr):
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

            while self.running:
                # Normally there'd be some kind of real state machine here,
                # but ours is just a single transition of read->write.
                try:
                    msg = self.recv(1024)
                    if not msg:
                        self.running = False
                    else:
                        self.queue.append(msg)
                except WantReadError:
                    try:
                        msg = self.queue.pop(0)
                        self.send(b"echo: " + msg)
                    except IndexError:
                        continue
                except WantWriteError:
                    continue
                except RaggedEOF:
                    self.running = False

    def __init__(
        self,
        backend: Backend,
        cert_chain,
        min_tls_version,
        max_tls_version,
        inner_protocols,
        ciphers,
    ):
        self.backend = backend
        server_configuration = backend.server_configuration(
            certificate_chain=cert_chain,
            ciphers=ciphers,
            inner_protocols=inner_protocols,
            lowest_supported_version=min_tls_version,
            highest_supported_version=max_tls_version,
            trust_store=None,
        )
        self.server_context: ServerContext = backend.server_context(server_configuration)

        self.active = False
        self.flag: threading.Event | None = None
        threading.Thread.__init__(self)
        self.name = "server"
        self.daemon = True

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
        self.socket = self.server_context.connect(("127.0.0.1", 0))
        return super().start()

    def run(self) -> None:
        self.socket.listen(1)
        self.active = True
        if self.flag:
            self.flag.set()
        while self.active:
            try:
                newconn, connaddr = self.socket.accept()

                if newconn.negotiated_protocol() is None:
                    handler = self.ConnectionHandler(self, newconn, connaddr)
                    handler.start()
                    handler.join()
                else:
                    self.server_negotiated_protocol = newconn.negotiated_protocol()
            except BlockingIOError:
                # Would have blocked on accept; busy loop instead.
                continue
            except TLSError:
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
        signing_chain,
        TLSVersion.MINIMUM_SUPPORTED,
        TLSVersion.MAXIMUM_SUPPORTED,
        inner_protocols=None,
        ciphers=DEFAULT_CIPHER_LIST,
    )

    return server, client_config


def tweak_client_config(
    old_config: TLSClientConfiguration,
    certificate_chain: SigningChain[OpenSSLCertificate, OpenSSLPrivateKey] | None = None,
    ciphers: Sequence[CipherSuite] | None = None,
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
    certificate_chain: SigningChain[OpenSSLCertificate, OpenSSLPrivateKey] | None = None,
    ciphers: Sequence[CipherSuite] | None = None,
    inner_protocols: Sequence[NextProtocol | bytes] | None = None,
    lowest_supported_version: TLSVersion | None = None,
    highest_supported_version: TLSVersion | None = None,
    trust_store: OpenSSLTrustStore | None = None,
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

    server.server_context = server.backend.server_context(new_config)

    return server
