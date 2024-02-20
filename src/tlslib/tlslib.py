"""Abstract interface to TLS for Python."""

from abc import ABCMeta, abstractmethod
from enum import Enum, IntEnum

__all__ = [
    "TLSServerConfiguration", "TLSClientConfiguration", "ClientContext", "ServerContext",
    "CipherSuite", "NextProtocol", "TLSVersion",
    "TLSError", "WantWriteError", "WantReadError", "RaggedEOF", "Backend",
]

class _TLSBaseConfiguration:
    __slots__ = (
        "_ciphers", "_inner_protocols", "_lowest_supported_version",
        "_highest_supported_version",
    )

    def __init__(self,
                 ciphers=None,
                 inner_protocols=None,
                 lowest_supported_version=None,
                 highest_supported_version=None) -> None:

        if ciphers is None:
            ciphers = DEFAULT_CIPHER_LIST

        if inner_protocols is None:
            inner_protocols = ()

        if lowest_supported_version is None:
            lowest_supported_version = TLSVersion.TLSv1

        if highest_supported_version is None:
            highest_supported_version = TLSVersion.MAXIMUM_SUPPORTED

        self._ciphers = ciphers
        self._inner_protocols = inner_protocols
        self._lowest_supported_version = lowest_supported_version
        self._highest_supported_version = highest_supported_version

    @property
    def ciphers(self):
        """The available ciphers for TLS connections created with this
        configuration, in priority order.
        """
        return self._ciphers

    @property
    def inner_protocols(self):
        """Protocols that connections created with this configuration should
        advertise as supported during the TLS handshake. These may be
        advertised using either or both of ALPN or NPN. This list of
        protocols is ordered by preference.
        """
        return self._inner_protocols

    @property
    def lowest_supported_version(self):
        """The minimum version of TLS that is allowed on TLS connections using
        this configuration.
        """
        return self._lowest_supported_version

    @property
    def highest_supported_version(self):
        """The maximum version of TLS that will be allowed on TLS connections
        using this configuration.
        """
        return self._highest_supported_version

class TLSServerConfiguration(_TLSBaseConfiguration):
    __slots__ = (
        "_certificate_chain"
    )
    def __init__(self,
                 ciphers=None,
                 inner_protocols=None,
                 lowest_supported_version=None,
                 highest_supported_version=None,
                 certificate_chain = None) -> None:

        super().__init__(ciphers,
                         inner_protocols,
                         lowest_supported_version,
                         highest_supported_version)
        self._certificate_chain = certificate_chain

    @property
    def certificate_chain(self):
        """The certificate, intermediate certificates, and the corresponding
        private key for the leaf certificate. These certificates will be
        offered to the remote peer during the handshake if required.

        The first Certificate in the list is the leaf certificate. All
        subsequent certificates will be offered as intermediate additional
        certificates.
        """
        return self._certificate_chain

class TLSClientConfiguration(_TLSBaseConfiguration):
    def __init__(self,
                 ciphers=None,
                 inner_protocols=None,
                 lowest_supported_version=None,
                 highest_supported_version=None) -> None:

        super().__init__(ciphers,
                         inner_protocols,
                         lowest_supported_version,
                         highest_supported_version)

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
        """Creates a TLSSocket. Only to be used by
        ClientContext.connect() and ServerContext.connect().
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
    def cipher(self):
        """Returns the CipherSuite entry for the cipher that has been
        negotiated on the connection. If no connection has been negotiated,
        returns ``None``. If the cipher negotiated is not defined in
        CipherSuite, returns the 16-bit integer representing that cipher
        directly.
        """

    @abstractmethod
    def negotiated_protocol(self):
        """Returns the protocol that was selected during the TLS handshake.
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
    def negotiated_tls_version(self):
        """The version of TLS that has been negotiated on this connection."""

class CipherSuite(IntEnum):
    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003f
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
    TLS_RSA_WITH_SEED_CBC_SHA = 0x0096
    TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009a
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00a0
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00a1
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00ba
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00bc
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00be
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c0
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c2
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c4
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xc002
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc003
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xc004
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xc005
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xc007
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc008
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xc00c
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xc00d
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xc00e
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xc011
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc025
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc026
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xc029
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xc02a
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02d
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02e
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xc031
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xc032
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc072
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc073
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc074
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc075
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc076
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc077
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc078
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc079
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07a
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07b
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07c
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07d
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07e
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07f
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc086
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc087
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc088
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc089
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08a
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08b
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08c
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08d
    TLS_RSA_WITH_AES_128_CCM = 0xc09c
    TLS_RSA_WITH_AES_256_CCM = 0xc09d
    TLS_DHE_RSA_WITH_AES_128_CCM = 0xc09e
    TLS_DHE_RSA_WITH_AES_256_CCM = 0xc09f
    TLS_RSA_WITH_AES_128_CCM_8 = 0xc0a0
    TLS_RSA_WITH_AES_256_CCM_8 = 0xc0a1
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xc0a2
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xc0a3
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xc0ac
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xc0ad
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xc0ae
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xc0af
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa


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
    H2 = b"h2"
    H2C = b"h2c"
    HTTP1 = b"http/1.1"
    WEBRTC = b"webrtc"
    C_WEBRTC = b"c-webrtc"
    FTP = b"ftp"
    STUN = b"stun.nat-discovery"
    TURN = b"stun.turn"


class TLSVersion(Enum):
    MINIMUM_SUPPORTED = "MINIMUM_SUPPORTED"
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1 = "TLSv1"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"
    MAXIMUM_SUPPORTED = "MAXIMUM_SUPPORTED"

class TLSError(Exception):
    """The base exception for all TLS related errors from any backend.
    Catching this error should be sufficient to catch *all* TLS errors,
    regardless of what backend is used.
    """


class WantWriteError(TLSError):
    """A special signaling exception used only when non-blocking or
    buffer-only I/O is used. This error signals that the requested
    operation cannot complete until more data is written to the network,
    or until the output buffer is drained.

    This error is should only be raised when it is completely impossible
    to write any data. If a partial write is achievable then this should
    not be raised.
    """


class WantReadError(TLSError):
    """A special signaling exception used only when non-blocking or
    buffer-only I/O is used. This error signals that the requested
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
        "_client_context", "_server_context", "_tls_socket",
    )

    def __init__(self,
                 client_context,
                 server_context,
                 tls_socket) -> None:
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

