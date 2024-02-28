"""Shims the standard library OpenSSL module into the amended PEP 543 API."""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
import tempfile
import typing
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path

import truststore

from .tlslib import (
    Backend,
    CipherSuite,
    NextProtocol,
    SigningChain,
    TLSClientConfiguration,
    TLSError,
    TLSServerConfiguration,
    TLSVersion,
    WantReadError,
    WantWriteError,
)

_SSLContext = ssl.SSLContext | truststore.SSLContext


class OpenSSLTrustStore:
    """A handle to a trust store object, either on disk or the system trust store,
    that can be used to validate the certificates presented by a remote peer.
    """

    def __init__(self, path: os.PathLike | None):
        """
        Creates a TrustStore object from a path or representing the system trust store.

        If no path is given, the default system trust store is used.
        """

        self._trust_path = path

    @classmethod
    def system(cls) -> OpenSSLTrustStore:
        """
        Returns a TrustStore object that represents the system trust
        database.
        """

        return cls(path=None)

    @classmethod
    def from_pem_file(cls, path: os.PathLike) -> OpenSSLTrustStore:
        """
        Initializes a trust store from a single file full of PEMs.
        """

        return cls(path=Path(path))


class OpenSSLCertificate:
    """A handle to a certificate object, either on disk or in a buffer, that can
    be used for either server or client connectivity.
    """

    def __init__(self, path: os.PathLike | None = None):
        """Creates a certificate object, storing a path to the (temp)file."""

        self._cert_path = path

    @classmethod
    def from_buffer(cls, buffer: bytes) -> OpenSSLCertificate:
        """
        Creates a Certificate object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN CERTIFICATE" and another
        series of dashes). In the absence of that preamble, the
        implementation may assume that the certificate is DER-encoded
        instead.
        """

        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(buffer)

        return cls(path=Path(path))

    @classmethod
    def from_file(cls, path: os.PathLike) -> OpenSSLCertificate:
        """
        Creates a Certificate object from a file on disk. This method may
        be a convenience method that wraps ``open`` and ``from_buffer``,
        but some TLS implementations may be able to provide more-secure or
        faster methods of loading certificates that do not involve Python
        code.
        """

        return cls(path=path)


class OpenSSLPrivateKey:
    """A handle to a private key object, either on disk or in a buffer, that can
    be used along with a certificate for either server or client connectivity.
    """

    def __init__(self, path: os.PathLike | None = None, password: bytes | None = None):
        """Creates a private key object, storing a path to the (temp)file."""

        self._key_path = path
        self._password = password

    @classmethod
    def from_buffer(cls, buffer: bytes, password: bytes | None = None) -> OpenSSLPrivateKey:
        """
        Creates a PrivateKey object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN", the key type, and
        another series of dashes). In the absence of that preamble, the
        implementation may assume that the certificate is DER-encoded
        instead.

        The key may additionally be encrypted. If it is, the ``password``
        argument can be used to decrypt the key. The ``password`` argument
        may be a function to call to get the password for decrypting the
        private key. It will only be called if the private key is encrypted
        and a password is necessary. It will be called with no arguments,
        and it should return either bytes or bytearray containing the
        password. Alternatively a bytes, or bytearray value may be supplied
        directly as the password argument. It will be ignored if the
        private key is not encrypted and no password is needed.
        """

        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(buffer)
        return cls(path=Path(path), password=password)

    @classmethod
    def from_file(cls, path: os.PathLike, password: bytes | None = None) -> OpenSSLPrivateKey:
        """
        Creates a PrivateKey object from a file on disk. This method may
        be a convenience method that wraps ``open`` and ``from_buffer``,
        but some TLS implementations may be able to provide more-secure or
        faster methods of loading certificates that do not involve Python
        code.

        The ``password`` parameter behaves exactly as the equivalent
        parameter on ``from_buffer``.
        """

        return cls(path=path, password=password)


_TLSClientConfiguration = TLSClientConfiguration[
    OpenSSLTrustStore, OpenSSLCertificate, OpenSSLPrivateKey
]

_TLSServerConfiguration = TLSServerConfiguration[
    OpenSSLTrustStore, OpenSSLCertificate, OpenSSLPrivateKey
]


# We need all the various TLS options. We hard code this as their integer
# values to deal with the fact that the symbolic constants are only exposed if
# both OpenSSL and Python agree that they should be. That's problematic for
# something that should be generic. This way works better.
_OP_NO_SSLv2 = 0x01000000
_OP_NO_SSLv3 = 0x02000000
_OP_NO_TLSv1 = 0x04000000
_OP_NO_TLSv1_2 = 0x08000000
_OP_NO_TLSv1_1 = 0x10000000
_OP_NO_TLSv1_3 = 0x20000000

_opts_from_min_version = {
    TLSVersion.MINIMUM_SUPPORTED: 0,
    TLSVersion.SSLv2: 0,
    TLSVersion.SSLv3: _OP_NO_SSLv2,
    TLSVersion.TLSv1: _OP_NO_SSLv2 | _OP_NO_SSLv3,
    TLSVersion.TLSv1_1: _OP_NO_SSLv2 | _OP_NO_SSLv3 | _OP_NO_TLSv1,
    TLSVersion.TLSv1_2: _OP_NO_SSLv2 | _OP_NO_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1,
    TLSVersion.TLSv1_3: (
        _OP_NO_SSLv2 | _OP_NO_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1_2
    ),
}
_opts_from_max_version = {
    TLSVersion.SSLv2: (
        _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1 | _OP_NO_SSLv3
    ),
    TLSVersion.SSLv3: _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1,
    TLSVersion.TLSv1: _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_1,
    TLSVersion.TLSv1_1: _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2,
    TLSVersion.TLSv1_2: _OP_NO_TLSv1_3,
    TLSVersion.TLSv1_3: 0,
    TLSVersion.MAXIMUM_SUPPORTED: 0,
}

# We need to populate a dictionary of ciphers that OpenSSL supports, in the
# form of {16-bit number: OpenSSL suite name}.
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.set_ciphers("ALL:COMPLEMENTOFALL")
_cipher_map = {c["id"] & 0xFFFF: c["name"] for c in ctx.get_ciphers()}
del ctx


@contextmanager
def _error_converter(
    ignore_filter: tuple[type[Exception]] | tuple[()] = (),
) -> typing.Generator[None, None, None]:
    """
    Catches errors from the ssl module and wraps them up in TLSError
    exceptions. Ignores certain kinds of exceptions as requested.
    """
    try:
        yield
    except ignore_filter:
        raise
    except ssl.SSLWantReadError:
        raise WantReadError("Must read data") from None
    except ssl.SSLWantWriteError:
        raise WantWriteError("Must write data") from None
    except ssl.SSLError as e:
        raise TLSError(e) from None


def _version_options_from_version_range(min: TLSVersion, max: TLSVersion) -> int:
    """Given a TLS version range, we need to convert that into options that
    exclude TLS versions as appropriate.
    """
    try:
        return _opts_from_min_version[min] | _opts_from_max_version[max]
    except KeyError:
        msg = "Bad maximum/minimum options"
        raise TLSError(msg)


def _create_context_with_trust_store(
    protocol: ssl._SSLMethod, trust_store: OpenSSLTrustStore | None
) -> _SSLContext:
    some_context: _SSLContext

    if not trust_store or not trust_store._trust_path:
        some_context = truststore.SSLContext(protocol)
    else:
        some_context = ssl.SSLContext(protocol)
        some_context.load_verify_locations(trust_store._trust_path)

    some_context.options |= ssl.OP_NO_COMPRESSION

    return some_context


def _configure_context_for_certs(
    context: _SSLContext,
    cert_chain: SigningChain | None = None,
) -> _SSLContext:
    """Given a PEP 543 cert chain, configure the SSLContext to send that cert
    chain in the handshake.

    Returns the context.
    """

    if cert_chain is not None:
        # FIXME: support multiple certificates at different filesystem
        # locations. This requires being prepared to create temporary
        # files.

        cert = cert_chain.leaf[0]
        assert isinstance(cert, OpenSSLCertificate)
        cert_path = cert._cert_path
        key_path = None
        password = None
        if cert_chain.leaf[1] is not None:
            privkey = cert_chain.leaf[1]
            assert isinstance(privkey, OpenSSLPrivateKey)
            key_path = privkey._key_path
            password = privkey._password

        if cert_path is not None:
            context.load_cert_chain(cert_path, key_path, password)

    return context


def _configure_context_for_ciphers(
    context: _SSLContext, ciphers: Sequence[CipherSuite] | None = None
) -> _SSLContext:
    """Given a PEP 543 cipher suite list, configure the SSLContext to use those
    cipher suites.

    Returns the context.
    """
    if ciphers is not None:
        ossl_names = [_cipher_map[cipher] for cipher in ciphers if cipher in _cipher_map]
    if not ossl_names:
        msg = "Unable to find any supported ciphers!"
        raise TLSError(msg)
    context.set_ciphers(":".join(ossl_names))
    return context


def _configure_context_for_negotiation(
    context: _SSLContext,
    inner_protocols: Sequence[NextProtocol | bytes] | None = None,
) -> _SSLContext:
    """Given a PEP 543 list of protocols to negotiate, configures the SSLContext
    to negotiate those protocols.
    """
    if inner_protocols:
        protocols = []
        for np in inner_protocols:
            proto_string = np if isinstance(np, bytes) else np.value
            # The protocol string needs to be of type str for the standard
            # library.
            protocols.append(proto_string.decode("ascii"))

        # If ALPN/NPN aren't supported, that's no problem.
        with contextlib.suppress(NotImplementedError):
            context.set_alpn_protocols(protocols)

        with contextlib.suppress(NotImplementedError):
            context.set_npn_protocols(protocols)

    return context


def _init_context_common(
    some_context: _SSLContext,
    config: TLSClientConfiguration | TLSServerConfiguration,
) -> _SSLContext:
    some_context = _configure_context_for_certs(some_context, config.certificate_chain)

    some_context = _configure_context_for_ciphers(
        some_context,
        config.ciphers,
    )
    some_context = _configure_context_for_negotiation(
        some_context,
        config.inner_protocols,
    )
    some_context.options |= _version_options_from_version_range(
        config.lowest_supported_version,
        config.highest_supported_version,
    )

    return some_context


def _init_context_client(config: _TLSClientConfiguration) -> _SSLContext:
    """Initialize an SSL context object with a given client configuration."""
    some_context = _create_context_with_trust_store(ssl.PROTOCOL_TLS_CLIENT, config.trust_store)

    return _init_context_common(some_context, config)


def _init_context_server(config: _TLSServerConfiguration) -> _SSLContext:
    """Initialize an SSL context object with a given server configuration."""
    some_context = _create_context_with_trust_store(ssl.PROTOCOL_TLS_SERVER, config.trust_store)

    return _init_context_common(some_context, config)


class OpenSSLTLSSocket:
    """A TLSSocket implementation based on OpenSSL."""

    __slots__ = (
        "_parent_context",
        "_socket",
        "_ssl_context",
    )

    _parent_context: OpenSSLClientContext | OpenSSLServerContext
    _socket: ssl.SSLSocket
    _ssl_context: _SSLContext

    def __init__(self, *args: tuple, **kwargs: tuple) -> None:
        """OpenTLSSockets should not be constructed by the user.
        Instead, the ClientContext.connect() and
        ServerContext.connect() use the _create() method."""
        msg = (
            f"{self.__class__.__name__} does not have a public constructor. "
            "Instances are returned by ClientContext.connect() or ServerContext.connect()."
        )
        raise TypeError(
            msg,
        )

    @classmethod
    def _create(
        cls,
        address: tuple[str | None, int],
        parent_context: OpenSSLClientContext | OpenSSLServerContext,
        server_side: bool,
        ssl_context: _SSLContext,
    ) -> OpenSSLTLSSocket:
        self = cls.__new__(cls)
        self._parent_context = parent_context
        self._ssl_context = ssl_context

        if server_side is True:
            sock = socket.create_server(address)
            self._socket = ssl_context.wrap_socket(
                sock, server_side=server_side, server_hostname=None
            )
        else:
            hostname, _ = address
            sock = socket.create_connection(address)
            self._socket = ssl_context.wrap_socket(
                sock, server_side=server_side, server_hostname=hostname
            )

        self._socket.setblocking(False)

        return self

    def recv(self, bufsize: int) -> bytes:
        """Receive data from the socket. The return value is a bytes object
        representing the data received. Should not work before the handshake
        is completed."""
        try:
            with _error_converter(ignore_filter=(ssl.SSLZeroReturnError,)):
                return self._socket.recv(bufsize)
        except ssl.SSLZeroReturnError:
            return b""

    def send(self, bytes: bytes) -> int:
        """Send data to the socket. The socket must be connected to a remote socket."""
        with _error_converter():
            return self._socket.send(bytes)

    def close(self) -> None:
        """Unwraps the TLS connection, shuts down both halves of the connection and
        mark the socket closed."""
        with _error_converter():
            sock = self._socket.unwrap()

        sock.shutdown(socket.SHUT_RDWR)
        return sock.close()

    def listen(self, backlog: int) -> None:
        """Enable a server to accept connections. If backlog is specified, it
        specifies the number of unaccepted connections that the system will allow
        before refusing new connections."""
        with _error_converter():
            return self._socket.listen(backlog)

    def accept(self) -> tuple[OpenSSLTLSSocket, socket._RetAddress]:
        """Accept a connection. The socket must be bound to an address and listening
        for connections. The return value is a pair (conn, address) where conn is a
        new TLSSocket object usable to send and receive data on the connection, and
        address is the address bound to the socket on the other end of the connection."""

        (sock, address) = self._socket.accept()
        tls_socket = OpenSSLTLSSocket.__new__(OpenSSLTLSSocket)
        tls_socket._parent_context = self._parent_context
        tls_socket._ssl_context = self._ssl_context
        tls_socket._socket = sock
        with _error_converter():
            tls_socket._socket.setblocking(False)
        return (tls_socket, address)

    def getpeername(self) -> socket._RetAddress:
        """Return the remote address to which the socket is connected."""

        with _error_converter():
            return self._socket.getpeername()

    def fileno(self) -> int:
        """Return the socket’s file descriptor (a small integer), or -1 on failure."""

        with _error_converter():
            return self._socket.fileno()

    @property
    def context(self) -> OpenSSLClientContext | OpenSSLServerContext:
        """The ``Context`` object this socket is tied to."""

        return self._parent_context

    def cipher(self) -> CipherSuite | int | None:
        """
        Returns the CipherSuite entry for the cipher that has been negotiated on the connection.

        If no connection has been negotiated, returns ``None``. If the cipher negotiated is not
        defined in CipherSuite, returns the 16-bit integer representing that cipher directly.
        """

        # This is the OpenSSL cipher name. We want the ID, which we can get by
        # looking for this entry in the context's list of supported ciphers.
        # FIXME: This works only on 3.6. To get this to work elsewhere, we may
        # need to vendor tlsdb.
        ret = self._socket.cipher()

        if ret is None:
            return None
        else:
            ossl_cipher, _, _ = ret

        for cipher in self._ssl_context.get_ciphers():
            if cipher["name"] == ossl_cipher:
                break
        else:
            msg = "Unable to identify cipher suite"
            raise TLSError(msg)

        cipher_id = cipher["id"] & 0xFFFF
        try:
            return CipherSuite(cipher_id)
        except ValueError:
            return cipher_id

    def negotiated_protocol(self) -> NextProtocol | bytes | None:
        """
        Returns the protocol that was selected during the TLS handshake.

        This selection may have been made using ALPN, NPN, or some future
        negotiation mechanism.

        If the negotiated protocol is one of the protocols defined in the
        ``NextProtocol`` enum, the value from that enum will be returned.
        Otherwise, the raw bytestring of the negotiated protocol will be
        returned.

        If ``Context.set_inner_protocols()`` was not called, if the other
        party does not support protocol negotiation, if this socket does
        not support any of the peer's proposed protocols, or if the
        handshake has not happened yet, ``None`` is returned.
        """

        proto = self._socket.selected_alpn_protocol()

        # The standard library returns this as a str, we want bytes.
        if proto is None:
            return None

        protoBytes = proto.encode("ascii")

        try:
            return NextProtocol(protoBytes)
        except ValueError:
            return protoBytes

    @property
    def negotiated_tls_version(self) -> TLSVersion | None:
        """The version of TLS that has been negotiated on this connection."""

        ossl_version = self._socket.version()
        if ossl_version is None:
            return None
        else:
            return TLSVersion(ossl_version)


class OpenSSLClientContext:
    """This class controls and creates wrapped sockets and buffers for using the
    standard library bindings to OpenSSL to perform TLS connections on the
    client side of a network connection.
    """

    def __init__(self, configuration: _TLSClientConfiguration) -> None:
        """Create a new context object from a given TLS configuration."""

        self._configuration = configuration

    @property
    def configuration(self) -> _TLSClientConfiguration:
        """Returns the TLS configuration that was used to create the context."""

        return self._configuration

    def connect(self, address: tuple[str | None, int]) -> OpenSSLTLSSocket:
        """Create a buffered I/O object that can be used to do TLS."""
        ossl_context = _init_context_client(self._configuration)

        return OpenSSLTLSSocket._create(
            parent_context=self,
            server_side=False,
            ssl_context=ossl_context,
            address=address,
        )


class OpenSSLServerContext:
    """This class controls and creates wrapped sockets and buffers for using the
    standard library bindings to OpenSSL to perform TLS connections on the
    server side of a network connection.
    """

    def __init__(self, configuration: _TLSServerConfiguration) -> None:
        """Create a new context object from a given TLS configuration."""

        self._configuration = configuration

    @property
    def configuration(self) -> _TLSServerConfiguration:
        """Returns the TLS configuration that was used to create the context."""

        return self._configuration

    def connect(self, address: tuple[str | None, int]) -> OpenSSLTLSSocket:
        """Create a buffered I/O object that can be used to do TLS."""
        ossl_context = _init_context_server(self._configuration)

        return OpenSSLTLSSocket._create(
            parent_context=self,
            server_side=True,
            ssl_context=ossl_context,
            address=address,
        )


#: The stdlib ``Backend`` object.
STDLIB_BACKEND = Backend(
    certificate=OpenSSLCertificate,
    client_context=OpenSSLClientContext,
    private_key=OpenSSLPrivateKey,
    server_context=OpenSSLServerContext,
    trust_store=OpenSSLTrustStore,
)

# The current main is just test-code. We should probably remove it from here and add it to /test
if __name__ == "__main__":
    client_config = _TLSClientConfiguration(trust_store=OpenSSLTrustStore.system())
    client_ctx = STDLIB_BACKEND.client_context(client_config)
    tls_socket = client_ctx.connect(("www.python.org", 443))
    print(tls_socket.negotiated_tls_version)
    print(tls_socket.cipher)
    print(tls_socket.negotiated_protocol)

    tls_socket.send(
        b"GET / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close"
        b"\r\nAccept-Encoding: identity\r\n\r\n",
    )
    print(tls_socket.recv(4096))
