import json
import sys
import threading
from pathlib import Path
from typing import Any

from tlslib.stdlib import STDLIB_BACKEND, OpenSSLCertificate, OpenSSLPrivateKey, TLSVersion
from tlslib.tlslib import (
    DEFAULT_CIPHER_LIST,
    Backend,
    ServerContext,
    SigningChain,
    TLSClientConfiguration,
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
class ThreadedServer(threading.Thread):
    class ConnectionHandler(threading.Thread):
        def __init__(self, server, sock: TLSSocket, addr):
            self.server = server
            self.sock = sock
            self.addr = addr

            self.running = False
            threading.Thread.__init__(self)
            self.daemon = True
            self.name = "client"

        def close(self):
            self.sock.close()

        def run(self) -> None:
            self.running = True

            while self.running:
                try:
                    msg = self.sock.recv(1024)
                    print(f"client sez: {msg}")
                except WantWriteError:
                    # print("WantWrite!")
                    self.sock.send(b"hello")
                    continue
                except WantReadError:
                    continue
                    # print("WantRead!")
                except Exception as e:
                    self.running = False
                    print(f"ConnectionHandler {e=}")

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
                sys.stdout.write("accepted!\n")
                handler = self.ConnectionHandler(self, newconn, connaddr)
                handler.start()
                handler.join()
                print("done with handler")
            except BlockingIOError:
                # Would have blocked on accept; busy loop instead.
                continue
            except Exception as e:  # TODO
                sys.stdout.write(f"uh oh: {e=}\n")
                raise

        if self.socket:
            self.socket.close()
            self.socket = None

    def stop(self):
        self.active = False


def limbo_server(id: str) -> tuple[ThreadedServer, TLSClientConfiguration]:
    """
    Return a `ThreadedServer` and a `TLSClientConfiguration` suitable for connecting to it,
    both instantiated with an `sslib` backend and state from the given Limbo testcase.
    """

    testcase = limbo_asset(id)

    peer_cert = OpenSSLCertificate.from_buffer(testcase["peer_certificate"].encode())
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

    server = ThreadedServer(
        STDLIB_BACKEND,
        signing_chain,
        TLSVersion.MINIMUM_SUPPORTED,
        TLSVersion.MAXIMUM_SUPPORTED,
        inner_protocols=None,
        ciphers=DEFAULT_CIPHER_LIST,
    )

    return server, client_config
