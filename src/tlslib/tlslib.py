"""Abstract interface to TLS for Python."""

from __future__ import annotations

import os
from abc import abstractmethod
from collections.abc import Buffer, Callable, Sequence
from enum import Enum, IntEnum
from typing import Generic, Protocol, TypeVar

__all__ = [
    "TLSBuffer",
    "TLSServerConfiguration",
    "TLSClientConfiguration",
    "ClientContext",
    "ServerContext",
    "CipherSuite",
    "NextProtocol",
    "TLSVersion",
    "TLSError",
    "WantWriteError",
    "WantReadError",
    "RaggedEOF",
    "Certificate",
    "PrivateKey",
    "Backend",
]


class TrustStore:
    """
    The trust store that is used to verify certificate validity.
    """

    __slots__ = (
        "_buffer",
        "_path",
        "_id",
    )

    def __init__(
        self, buffer: bytes | None = None, path: os.PathLike | None = None, id: bytes | None = None
    ):
        """
        Creates a TrustStore object from a path, buffer, or ID.

        If none of these is given, the default system trust store is used.
        """

        self._buffer = buffer
        self._path = path
        self._id = id

    @classmethod
    def system(cls) -> TrustStore:
        """
        Returns a TrustStore object that represents the system trust
        database.
        """
        return cls()

    @classmethod
    def from_buffer(cls, buffer: bytes) -> TrustStore:
        """
        Initializes a trust store from a buffer of PEM-encoded certificates.
        """
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path: os.PathLike) -> TrustStore:
        """
        Initializes a trust store from a single file containing PEMs.
        """
        return cls(path=path)

    @classmethod
    def from_id(cls, id: bytes) -> TrustStore:
        """
        Initializes a trust store from an arbitrary identifier.
        """
        return cls(id=id)


class Certificate:
    """Object representing a certificate used in TLS."""

    __slots__ = (
        "_buffer",
        "_path",
        "_id",
    )

    def __init__(
        self, buffer: bytes | None = None, path: os.PathLike | None = None, id: bytes | None = None
    ):
        """
        Creates a Certificate object from a path, buffer, or ID.

        If none of these is given, an exception is raised.
        """

        if buffer is None and path is None and id is None:
            raise ValueError("Certificate cannot be empty.")

        self._buffer = buffer
        self._path = path
        self._id = id

    @classmethod
    def from_buffer(cls, buffer: bytes) -> Certificate:
        """
        Creates a Certificate object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN CERTIFICATE" and another
        series of dashes). In the absence of that preamble, the
        implementation may assume that the certificate is DER-encoded
        instead.
        """
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path: os.PathLike) -> Certificate:
        """
        Creates a Certificate object from a file on disk. The file on disk
        should contain a series of bytes corresponding to a certificate that
        may be either PEM-encoded or DER-encoded. If the bytes are PEM encoded
        it *must* begin with the standard PEM preamble (a series of dashes
        followed by the ASCII bytes "BEGIN CERTIFICATE" and another series of
        dashes). In the absence of that preamble, the implementation may
        assume that the certificate is DER-encoded instead.
        """
        return cls(path=path)

    @classmethod
    def from_id(cls, id: bytes) -> Certificate:
        """
        Creates a Certificate object from an arbitrary identifier. This may
        be useful for backends that rely on system certificate stores.
        """
        return cls(id=id)


class PrivateKey:
    """Object representing a private key corresponding to a public key
    for a certificate used in TLS."""

    __slots__ = (
        "_buffer",
        "_path",
        "_id",
    )

    def __init__(
        self, buffer: bytes | None = None, path: os.PathLike | None = None, id: bytes | None = None
    ):
        """
        Creates a PrivateKey object from a path, buffer, or ID.

        If none of these is given, an exception is raised.
        """

        if buffer is None and path is None and id is None:
            raise ValueError("PrivateKey cannot be empty.")

        self._buffer = buffer
        self._path = path
        self._id = id

    @classmethod
    def from_buffer(cls, buffer: bytes) -> PrivateKey:
        """
        Creates a PrivateKey object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN", the key type, and
        another series of dashes). In the absence of that preamble, the
        implementation may assume that the private key is DER-encoded
        instead.
        """
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path: os.PathLike) -> PrivateKey:
        """
        Creates a PrivateKey object from a file on disk. The file on disk
        should contain a series of bytes corresponding to a certificate that
        may be either PEM-encoded or DER-encoded. If the bytes are PEM encoded
        it *must* begin with the standard PEM preamble (a series of dashes
        followed by the ASCII bytes "BEGIN", the key type, and another series
        of dashes). In the absence of that preamble, the implementation may
        assume that the certificate is DER-encoded instead.
        """
        return cls(path=path)

    @classmethod
    def from_id(cls, id: bytes) -> PrivateKey:
        """
        Creates a PrivateKey object from an arbitrary identifier. This may
        be useful for backends that rely on system private key stores.
        """
        return cls(id=id)


class TLSClientConfiguration:
    """
    An immutable TLS Configuration object for a "client" socket, i.e. a socket
    making a connection to a server. This object has the following
    properties:

    :param certificate_chain SigningChain: A single signing chain,
        comprising a leaf certificate including its corresponding private key
        and optionally a list of intermediate certificates. These certificates
        will be offered to the server during the handshake if required.

    :param ciphers Sequence[CipherSuite | int] | None:
        The available ciphers for TLS connections created with this
        configuration, in priority order. If None is provided, the backend
        will choose a suitable default value (such as system recommended settings).

    :param inner_protocols Sequence[NextProtocol | bytes]:
        Protocols that connections created with this configuration should
        advertise as supported during the TLS handshake. These may be
        advertised using ALPN. This list of protocols should be ordered
        by preference.

    :param lowest_supported_version TLSVersion | None:
        The minimum version of TLS that should be allowed on TLS
        connections using this configuration.

    :param highest_supported_version TLSVersion | None:
        The maximum version of TLS that should be allowed on TLS
        connections using this configuration.

    :param trust_store TrustStore:
        The trust store that connections using this configuration will use
        to validate certificates. None means that the system store is used.
    """

    __slots__ = (
        "_certificate_chain",
        "_ciphers",
        "_inner_protocols",
        "_lowest_supported_version",
        "_highest_supported_version",
        "_trust_store",
    )

    def __init__(
        self,
        certificate_chain: SigningChain | None = None,
        ciphers: Sequence[CipherSuite] | None = None,
        inner_protocols: Sequence[NextProtocol | bytes] | None = None,
        lowest_supported_version: TLSVersion | None = None,
        highest_supported_version: TLSVersion | None = None,
        trust_store: TrustStore | None = None,
    ) -> None:
        """Initialize TLS client configuration."""

        if inner_protocols is None:
            inner_protocols = []

        self._certificate_chain = certificate_chain
        self._ciphers = ciphers
        self._inner_protocols = inner_protocols
        self._lowest_supported_version = lowest_supported_version
        self._highest_supported_version = highest_supported_version
        self._trust_store = trust_store

    @property
    def certificate_chain(self) -> SigningChain | None:
        """
        The leaf certificate and corresponding private key, with optionally a list of
        intermediate certificates. These certificates will be offered to the server
        during the handshake if required.

        """
        return self._certificate_chain

    @property
    def ciphers(self) -> Sequence[CipherSuite | int] | None:
        """
        The list of available ciphers for TLS connections, in priority order.
        None indicates that system recommended settings will be used.
        """
        return self._ciphers

    @property
    def inner_protocols(self) -> Sequence[NextProtocol | bytes]:
        """Protocols that connections should advertise as supported during the TLS handshake.

        These may be advertised using ALPN. This list of protocols is ordered by preference.
        """
        return self._inner_protocols

    @property
    def lowest_supported_version(self) -> TLSVersion | None:
        """
        The minimum version of TLS that is allowed on TLS connections.
        None indicates that system recommended settings will be used.
        """
        return self._lowest_supported_version

    @property
    def highest_supported_version(self) -> TLSVersion | None:
        """
        The maximum version of TLS that will be allowed on TLS connections.
        None indicates that system recommended settings will be used.
        """
        return self._highest_supported_version

    @property
    def trust_store(self) -> TrustStore | None:
        """
        The trust store that connections using this configuration will use
        to validate certificates. None means that the system store is used.
        """
        return self._trust_store


class TLSServerConfiguration:
    """
    An immutable TLS Configuration object for a "server" socket, i.e. a socket
    making one or more connections to clients. This object has the following
    properties:

    :param certificate_chain Sequence[SigningChain]: A sequence of signing chains,
        where each signing chain comprises a leaf certificate including
        its corresponding private key and optionally a list of intermediate
        certificates. These certificates will be offered to the client during
        the handshake if required.

    :param ciphers Sequence[CipherSuite | int] | None:
        The available ciphers for TLS connections created with this
        configuration, in priority order. If None is provided, the backend
        will choose a suitable default value (such as system recommended settings).

    :param inner_protocols Sequence[NextProtocol | bytes]:
        Protocols that connections created with this configuration should
        advertise as supported during the TLS handshake. These may be
        advertised using ALPN. This list of protocols should be ordered
        by preference.

    :param lowest_supported_version TLSVersion | None:
        The minimum version of TLS that should be allowed on TLS
        connections using this configuration.

    :param highest_supported_version TLSVersion | None:
        The maximum version of TLS that should be allowed on TLS
        connections using this configuration.

    :param trust_store TrustStore:
        The trust store that connections using this configuration will use
        to validate certificates. None means that client authentication is disabled,
        whereas any other option enable client authentication.
    """

    __slots__ = (
        "_certificate_chain",
        "_ciphers",
        "_inner_protocols",
        "_lowest_supported_version",
        "_highest_supported_version",
        "_trust_store",
    )

    def __init__(
        self,
        certificate_chain: Sequence[SigningChain] | None = None,
        ciphers: Sequence[CipherSuite | int] | None = None,
        inner_protocols: Sequence[NextProtocol | bytes] | None = None,
        lowest_supported_version: TLSVersion | None = None,
        highest_supported_version: TLSVersion | None = None,
        trust_store: TrustStore | None = None,
    ) -> None:
        """Initialize TLS server configuration."""

        if inner_protocols is None:
            inner_protocols = []

        self._certificate_chain = certificate_chain
        self._ciphers = ciphers
        self._inner_protocols = inner_protocols
        self._lowest_supported_version = lowest_supported_version
        self._highest_supported_version = highest_supported_version
        self._trust_store = trust_store

    @property
    def certificate_chain(self) -> Sequence[SigningChain] | None:
        """
        The set of signing chains, where each signing chain comprises a
        leaf certificate and its corresponding private key, with optionally
        a list of intermediate certificates. The certificates corresponding to
        the signing chain that includes the correct certificate for the hostname
        requested by the client will beoffered to the client during the handshake
        if required.
        """
        return self._certificate_chain

    @property
    def ciphers(self) -> Sequence[CipherSuite | int] | None:
        """
        The list of available ciphers for TLS connections, in priority order.
        None indicates that system recommended settings will be used.
        """
        return self._ciphers

    @property
    def inner_protocols(self) -> Sequence[NextProtocol | bytes]:
        """Protocols that connections should advertise as supported during the TLS handshake.

        These may be advertised using ALPN. This list of protocols is ordered by preference.
        """
        return self._inner_protocols

    @property
    def lowest_supported_version(self) -> TLSVersion | None:
        """
        The minimum version of TLS that is allowed on TLS connections.
        None indicates that system recommended settings will be used.
        """
        return self._lowest_supported_version

    @property
    def highest_supported_version(self) -> TLSVersion | None:
        """
        The maximum version of TLS that will be allowed on TLS connections.
        None indicates that system recommended settings will be used.
        """
        return self._highest_supported_version

    @property
    def trust_store(self) -> TrustStore | None:
        """
        The trust store that connections using this configuration will use
        to validate certificates. None means that the system store is used.
        """
        return self._trust_store


class ClientContext(Protocol):
    """Context for setting up TLS connections for a client."""

    @abstractmethod
    def __init__(self, configuration: TLSClientConfiguration) -> None:
        """Create a new client context object from a given TLS client configuration."""
        ...

    @property
    @abstractmethod
    def configuration(self) -> TLSClientConfiguration:
        """Returns the TLS client configuration that was used to create the client context."""

    @abstractmethod
    def connect(self, address: tuple[str | None, int]) -> TLSSocket:
        """Creates a TLSSocket that behaves like a socket.socket, and
        contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.).
        """

    @abstractmethod
    def create_buffer(self, server_hostname: str) -> TLSBuffer:
        """Creates a TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""


_ClientContext = TypeVar("_ClientContext", bound=ClientContext)


class ServerContext(Protocol):
    """Context for setting up TLS connections for a server."""

    @abstractmethod
    def __init__(self, configuration: TLSServerConfiguration) -> None:
        """Create a new server context object from a given TLS server configuration."""
        ...

    @property
    @abstractmethod
    def configuration(self) -> TLSServerConfiguration:
        """Returns the TLS server configuration that was used to create the server context."""

    @abstractmethod
    def connect(self, address: tuple[str | None, int]) -> TLSSocket:
        """Creates a TLSSocket that behaves like a socket.socket, and
        contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.).
        """

    @abstractmethod
    def create_buffer(self) -> TLSBuffer:
        """Creates a TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""


_ServerContext = TypeVar("_ServerContext", bound=ServerContext)


class TLSSocket(Protocol):
    """This class implements a socket.socket-like object that creates an OS
    socket, wraps it in an SSL context, and provides read and write methods
    over that channel."""

    @abstractmethod
    def __init__(self, *args: tuple, **kwargs: tuple) -> None:
        """TLSSockets should not be constructed by the user.
        The backend should implement a method to construct a TLSSocket
        object and call it in ClientContext.connect() and
        ServerContext.connect()."""

    @abstractmethod
    def recv(self, bufsize: int) -> bytes:
        """Receive data from the socket. The return value is a bytes object
        representing the data received. Should not work before the handshake
        is completed."""

    @abstractmethod
    def send(self, bytes: bytes) -> int:
        """Send data to the socket. The socket must be connected to a remote socket."""

    @abstractmethod
    def close(self, force: bool = False) -> None:
        """Shuts down the connection and mark the socket closed.
        If force is True, this method should send the close_notify alert and shut down
        the socket without waiting for the other side.
        If force is False, this method should send the close_notify alert and raise
        the WantReadError exception until a corresponding close_notify alert has been
        received from the other side.
        In either case, this method should return WantWriteError if sending the
        close_notify alert currently fails."""

    @abstractmethod
    def listen(self, backlog: int) -> None:
        """Enable a server to accept connections. If backlog is specified, it
        specifies the number of unaccepted connections that the system will allow
        before refusing new connections."""

    @abstractmethod
    def accept(self) -> tuple[TLSSocket, tuple[str | None, int]]:
        """Accept a connection. The socket must be bound to an address and listening
        for connections. The return value is a pair (conn, address) where conn is a
        new TLSSocket object usable to send and receive data on the connection, and
        address is the address bound to the socket on the other end of the connection."""

    @abstractmethod
    def getsockname(self) -> tuple[str | None, int]:
        """Return the local address to which the socket is connected."""

    @abstractmethod
    def getpeercert(self) -> bytes | None:
        """
        Return the raw DER bytes of the certificate provided by the peer
        during the handshake, if applicable.
        """

    @abstractmethod
    def getpeername(self) -> tuple[str | None, int]:
        """Return the remote address to which the socket is connected."""

    @property
    @abstractmethod
    def context(self) -> ClientContext | ServerContext:
        """The ``Context`` object this socket is tied to."""

    @abstractmethod
    def cipher(self) -> CipherSuite | int | None:
        """
        Returns the CipherSuite entry for the cipher that has been negotiated on the connection.

        If no connection has been negotiated, returns ``None``. If the cipher negotiated is not
        defined in CipherSuite, returns the 16-bit integer representing that cipher directly.
        """

    @abstractmethod
    def negotiated_protocol(self) -> NextProtocol | bytes | None:
        """
        Returns the protocol that was selected during the TLS handshake.

        This selection may have been made using ALPN or some future
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

    @property
    @abstractmethod
    def negotiated_tls_version(self) -> TLSVersion | None:
        """The version of TLS that has been negotiated on this connection."""


class TLSBuffer(Protocol):
    """This class implements an in memory-channel that creates two buffers,
    wraps them in an SSL context, and provides read and write methods over
    that channel."""

    @abstractmethod
    def read(self, amt: int, buffer: Buffer | None) -> bytes | int:
        """
        Read up to ``amt`` bytes of data from the input buffer and return
        the result as a ``bytes`` instance. If an optional buffer is
        provided, the result is written into the buffer and the number of
        bytes is returned instead.

        Once EOF is reached, all further calls to this method return the
        empty byte string ``b''``.

        May read "short": that is, fewer bytes may be returned than were
        requested.

        Raise ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read.

        May raise ``RaggedEOF`` if the connection has been closed without a
        graceful TLS shutdown. Whether this is an exception that should be
        ignored or not is up to the specific application.

        As at any time a re-negotiation is possible, a call to ``read()``
        can also cause write operations.
        """

    @abstractmethod
    def write(self, buf: Buffer) -> int:
        """
        Write ``buf`` in encrypted form to the output buffer and return the
        number of bytes written. The ``buf`` argument must be an object
        supporting the buffer interface.

        Raise ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read. In either
        case, users should endeavour to resolve that situation and then
        re-call this method. When re-calling this method users *should*
        re-use the exact same ``buf`` object, as some backends require that
        the exact same buffer be used.

        This operation may write "short": that is, fewer bytes may be
        written than were in the buffer.

        As at any time a re-negotiation is possible, a call to ``write()``
        can also cause read operations.
        """

    @abstractmethod
    def do_handshake(self) -> None:
        """
        Performs the TLS handshake. Also performs certificate validation
        and hostname verification.
        """

    @abstractmethod
    def cipher(self) -> CipherSuite | int | None:
        """
        Returns the CipherSuite entry for the cipher that has been
        negotiated on the connection. If no connection has been negotiated,
        returns ``None``. If the cipher negotiated is not defined in
        CipherSuite, returns the 16-bit integer representing that cipher
        directly.
        """

    @abstractmethod
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

    @property
    @abstractmethod
    def context(self) -> ClientContext | ServerContext:
        """
        The ``Context`` object this buffer is tied to.
        """

    @property
    @abstractmethod
    def negotiated_tls_version(self) -> TLSVersion | None:
        """
        The version of TLS that has been negotiated on this connection.
        """

    @abstractmethod
    def shutdown(self) -> None:
        """
        Performs a clean TLS shut down. This should generally be used
        whenever possible to signal to the remote peer that the content is
        finished.
        """

    @abstractmethod
    def process_incoming(self, data_from_network: bytes) -> None:
        """
        Receives some TLS data from the network and stores it in an
        internal buffer.

        If the internal buffer is overfull, this method will raise
        ``WantReadError`` and store no data. At this point, the user must
        call ``read`` to remove some data from the internal buffer
        before repeating this call.
        """

    @abstractmethod
    def incoming_bytes_buffered(self) -> int:
        """
        Returns how many bytes are in the incoming buffer waiting to be processed.
        """

    @abstractmethod
    def process_outgoing(self, amount_bytes_for_network: int) -> bytes:
        """
        Returns the next ``amt`` bytes of data that should be written to
        the network from the outgoing data buffer, removing it from the
         internal buffer.
        """

    @abstractmethod
    def outgoing_bytes_buffered(self) -> int:
        """
        Returns how many bytes are in the outgoing buffer waiting to be sent.
        """

    @abstractmethod
    def getpeercert(self) -> bytes | None:
        """
        Return the raw DER bytes of the certificate provided by the peer
        during the handshake, if applicable.
        """


class CipherSuite(IntEnum):
    """
    Known cipher suites.

    See: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>
    """

    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9


"""
This default cipher list for TLS v1.2 is based on the CloudFlare recommendations,
see: <https://developers.cloudflare.com/ssl/reference/cipher-suites/recommendations/>

The default cipher list for TLS v1.3 should comprise the five fixed cipher suites
from the TLS v1.3 specification.
"""
DEFAULT_CIPHER_LIST = [
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
]


class NextProtocol(Enum):
    """The underlying negotiated ("next") protocol."""

    H2 = b"h2"
    H2C = b"h2c"
    HTTP1 = b"http/1.1"
    WEBRTC = b"webrtc"
    C_WEBRTC = b"c-webrtc"
    FTP = b"ftp"
    STUN = b"stun.nat-discovery"
    TURN = b"stun.turn"


class TLSVersion(Enum):
    """
    TLS versions.

    The `MINIMUM_SUPPORTED` and `MAXIMUM_SUPPORTED` variants are "open ended",
    and refer to the "lowest mutually supported" and "highest mutually supported"
    TLS versions, respectively.
    """

    MINIMUM_SUPPORTED = "MINIMUM_SUPPORTED"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"
    MAXIMUM_SUPPORTED = "MAXIMUM_SUPPORTED"


class TLSError(Exception):
    """
    The base exception for all TLS related errors from any backend.

    Catching this error should be sufficient to catch *all* TLS errors,
    regardless of what backend is used.
    """


class WantWriteError(TLSError):
    """
    A special signaling exception used only when non-blocking or buffer-only I/O is used.

    This error signals that the requested
    operation cannot complete until more data is written to the network,
    or until the output buffer is drained.

    This error is should only be raised when it is completely impossible
    to write any data. If a partial write is achievable then this should
    not be raised.
    """


class WantReadError(TLSError):
    """
    A special signaling exception used only when non-blocking or buffer-only I/O is used.

    This error signals that the requested
    operation cannot complete until more data is read from the network, or
    until more data is available in the input buffer.

    This error should only be raised when it is completely impossible to
    write any data. If a partial write is achievable then this should not
    be raised.
    """


class RaggedEOF(TLSError):
    """A special signaling exception used when a TLS connection has been
    closed gracelessly: that is, when a TLS CloseNotify was not received
    from the peer before the underlying TCP socket reached EOF. This is a
    so-called "ragged EOF".

    This exception is not guaranteed to be raised in the face of a ragged
    EOF: some implementations may not be able to detect or report the
    ragged EOF.

    This exception is not always a problem. Ragged EOFs are a concern only
    when protocols are vulnerable to length truncation attacks. Any
    protocol that can detect length truncation attacks at the application
    layer (e.g. HTTP/1.1 and HTTP/2) is not vulnerable to this kind of
    attack and so can ignore this exception.
    """


class ConfigurationError(TLSError):
    """An special exception that backends can use when the provided
    configuration uses features not supported by that backend."""


class SigningChain:
    """Object representing a certificate chain used in TLS."""

    leaf: tuple[Certificate, PrivateKey | None]
    chain: list[Certificate]

    def __init__(
        self,
        leaf: tuple[Certificate, PrivateKey | None],
        chain: Sequence[Certificate] | None = None,
    ):
        """Initializes a SigningChain object."""
        self.leaf = leaf
        if chain is None:
            chain = []
        self.chain = list(chain)


class Backend(Generic[_ClientContext, _ServerContext]):
    """An object representing the collection of classes that implement the
    PEP 543 abstract TLS API for a specific TLS implementation.
    """

    __slots__ = (
        "_client_context",
        "_server_context",
        "_validate_config",
    )

    def __init__(
        self,
        client_context: type[_ClientContext],
        server_context: type[_ServerContext],
        validate_config: Callable[[TLSClientConfiguration | TLSServerConfiguration], None],
    ) -> None:
        """Initializes all attributes of the backend."""

        self._client_context = client_context
        self._server_context = server_context
        self._validate_config = validate_config

    @property
    def client_context(self) -> type[_ClientContext]:
        """The concrete implementation of the PEP 543 Client Context object,
        if this TLS backend supports being the client on a TLS connection.
        """
        return self._client_context

    @property
    def server_context(self) -> type[_ServerContext]:
        """The concrete implementation of the PEP 543 Server Context object,
        if this TLS backend supports being a server on a TLS connection.
        """
        return self._server_context

    @property
    def validate_config(self) -> Callable[[TLSClientConfiguration | TLSServerConfiguration], None]:
        """A function that reveals whether this TLS backend supports a
        particular TLS configuration.
        """
        return self._validate_config
