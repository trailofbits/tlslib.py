"""Abstract interface to TLS for Python."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from enum import Enum, IntEnum

__all__ = [
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
    "Backend",
]


class _TLSBaseConfiguration:
    """
    "Base" configuration for a TLS connection, whether server or client initiated.

    This class is not constructed or used directly.
    """

    __slots__ = (
        "_ciphers",
        "_inner_protocols",
        "_lowest_supported_version",
        "_highest_supported_version",
    )

    def __init__(
        self,
        ciphers: list[CipherSuite] | None = None,
        inner_protocols: list[NextProtocol | bytes] | None = None,
        lowest_supported_version: TLSVersion | None = None,
        highest_supported_version: TLSVersion | None = None,
    ) -> None:
        if ciphers is None:
            ciphers = DEFAULT_CIPHER_LIST

        if inner_protocols is None:
            inner_protocols = []

        if lowest_supported_version is None:
            lowest_supported_version = TLSVersion.TLSv1

        if highest_supported_version is None:
            highest_supported_version = TLSVersion.MAXIMUM_SUPPORTED

        self._ciphers = ciphers
        self._inner_protocols = inner_protocols
        self._lowest_supported_version = lowest_supported_version
        self._highest_supported_version = highest_supported_version

    @property
    def ciphers(self) -> list[CipherSuite]:
        """The list of available ciphers for TLS connections, in priority order."""
        return self._ciphers

    @property
    def inner_protocols(self) -> list[NextProtocol | bytes]:
        """Protocols that connections should advertise as supported during the TLS handshake.

        These may be advertised using either or both of ALPN or NPN. This list of
        protocols is ordered by preference.
        """
        return self._inner_protocols

    @property
    def lowest_supported_version(self) -> TLSVersion:
        """The minimum version of TLS that is allowed on TLS connections."""
        return self._lowest_supported_version

    @property
    def highest_supported_version(self) -> TLSVersion:
        """The maximum version of TLS that will be allowed on TLS connections."""
        return self._highest_supported_version


class TLSServerConfiguration(_TLSBaseConfiguration):
    """TLS configuration for a "server" socket, i.e. a socket accepting connections from clients."""

    __slots__ = ("_certificate_chain",)

    def __init__(
        self,
        ciphers: list[CipherSuite] | None = None,
        inner_protocols: list[NextProtocol | bytes] | None = None,
        lowest_supported_version: TLSVersion | None = None,
        highest_supported_version: TLSVersion | None = None,
        certificate_chain=None,
    ) -> None:
        super().__init__(
            ciphers,
            inner_protocols,
            lowest_supported_version,
            highest_supported_version,
        )
        self._certificate_chain = certificate_chain

    @property
    def certificate_chain(self):
        """
        The certificate, intermediate certificates, and the corresponding
        private key for the leaf certificate. These certificates will be
        offered to the remote peer during the handshake if required.

        The first Certificate in the list is the leaf certificate. All
        subsequent certificates will be offered as intermediate additional
        certificates.
        """
        return self._certificate_chain


class TLSClientConfiguration(_TLSBaseConfiguration):
    """TLS configuration for a "client" socket, i.e. a socket making a connection to a server."""

    def __init__(
        self,
        ciphers: list[CipherSuite] | None = None,
        inner_protocols: list[NextProtocol | CipherSuite] | None = None,
        lowest_supported_version: TLSVersion | None = None,
        highest_supported_version: TLSVersion | None = None,
    ) -> None:
        super().__init__(
            ciphers,
            inner_protocols,
            lowest_supported_version,
            highest_supported_version,
        )


class _BaseContext:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, configuration) -> None:
        """Create a new context object from a given TLS configuration."""

    @property
    @abstractmethod
    def configuration(self):
        """Returns the TLS configuration that was used to create the context."""


class ClientContext(_BaseContext):
    @abstractmethod
    def connect(self, address):
        """Creates a TLSSocket that behaves like a socket.socket, and
        contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.).
        """


class ServerContext(_BaseContext):
    @abstractmethod
    def connect(self, address):
        """Creates a TLSSocket that behaves like a socket.socket, and
        contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.).
        """


class TLSSocket:
    __metaclass__ = ABCMeta
    """This class implements a subtype of socket.socket that wraps
    the underlying OS socket in an SSL context when necessary, and
    provides read and write methods over that channel. """

    def __init__(self, *args, **kwargs) -> None:
        msg = f"{self.__class__.__name__} does not have a public constructor. Instances are returned by ClientContext.connect() or ServerContext.connect()."
        raise TypeError(
            msg,
        )

    @classmethod
    @abstractmethod
    def _create(address):
        """
        Creates a TLSSocket.

        Only to be used by ClientContext.connect() and ServerContext.connect().
        """

    @property
    @abstractmethod
    def context(self):
        """The ``Context`` object this buffer is tied to."""

    @property
    @abstractmethod
    def socket(self):
        """The socket-like object to be used by the user."""

    @abstractmethod
    def cipher(self) -> CipherSuite | int:
        """
        Returns the CipherSuite entry for the cipher that has been negotiated on the connection.

        If no connection has been negotiated, returns ``None``. If the cipher negotiated is not
        defined in CipherSuite, returns the 16-bit integer representing that cipher directly.
        """

    @abstractmethod
    def negotiated_protocol(self) -> NextProtocol | bytes:
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
    def negotiated_tls_version(self) -> TLSVersion:
        """The version of TLS that has been negotiated on this connection."""


class CipherSuite(IntEnum):
    """
    Known cipher suites.

    See: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>
    """

    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
    TLS_RSA_WITH_SEED_CBC_SHA = 0x0096
    TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009A
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00A0
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00A1
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BA
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BC
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BE
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C0
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C2
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C4
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xC002
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xC00C
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC074
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC075
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC076
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC077
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC078
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC079
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07A
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07B
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07C
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07D
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07E
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07F
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC088
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC089
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08A
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08B
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08C
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08D
    TLS_RSA_WITH_AES_128_CCM = 0xC09C
    TLS_RSA_WITH_AES_256_CCM = 0xC09D
    TLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E
    TLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F
    TLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0
    TLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xC0A2
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xC0A3
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA


DEFAULT_CIPHER_LIST = [
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
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
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1 = "TLSv1"
    TLSv1_1 = "TLSv1.1"
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


class Backend:
    """An object representing the collection of classes that implement the
    PEP 543 abstract TLS API for a specific TLS implementation.
    """

    __slots__ = (
        "_client_context",
        "_server_context",
        "_tls_socket",
    )

    def __init__(self, client_context, server_context, tls_socket) -> None:
        self._client_context = client_context
        self._server_context = server_context
        self._tls_socket = tls_socket

    @property
    def client_context(self):
        """The concrete implementation of the PEP 543 Client Context object,
        if this TLS backend supports being the client on a TLS connection.
        """
        return self._client_context

    @property
    def server_context(self):
        """The concrete implementation of the PEP 543 Server Context object,
        if this TLS backend supports being a server on a TLS connection.
        """
        return self._server_context

    @property
    def tls_socket(self):
        """The concrete implementation of the PEP 543 TLSSocket object used
        by this TLS backend.
        """
        return self._tls_socket
