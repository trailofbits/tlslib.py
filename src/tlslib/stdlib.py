"""Shims the standard library OpenSSL module into the amended PEP 543 API."""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
import tempfile

import truststore

from .tlslib import (
    Backend,
    Certificate,
    CipherSuite,
    ClientContext,
    NextProtocol,
    PrivateKey,
    ServerContext,
    TLSClientConfiguration,
    TLSError,
    TLSServerConfiguration,
    TLSSocket,
    TLSVersion,
    TrustStore,
)

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


def _version_options_from_version_range(min, max):
    """Given a TLS version range, we need to convert that into options that
    exclude TLS versions as appropriate.
    """
    try:
        return _opts_from_min_version[min] | _opts_from_max_version[max]
    except KeyError:
        msg = "Bad maximum/minimum options"
        raise TLSError(msg)


def _create_context_with_trust_store(protocol, trust_store):
    if trust_store is _SYSTEMTRUSTSTORE:
        some_context = truststore.SSLContext(protocol)
    else:
        some_context = ssl.SSLContext(protocol)
        if trust_store is not None:
            some_context.load_verify_locations(trust_store._trust_path)

    some_context.options |= ssl.OP_NO_COMPRESSION

    return some_context


def _configure_context_for_certs(context, cert_chain):
    """Given a PEP 543 cert chain, configure the SSLContext to send that cert
    chain in the handshake.

    Returns the context.
    """
    if cert_chain:
        # FIXME: support multiple certificates at different filesystem
        # locations. This requires being prepared to create temporary
        # files.
        assert len(cert_chain[0]) == 1
        cert_path = cert_chain[0][0]._cert_path
        key_path = None
        password = None
        if cert_chain[1]:
            key_path = cert_chain[1]._key_path
            password = cert_chain[1]._password

        context.load_cert_chain(cert_path, key_path, password)

    return context


def _configure_context_for_ciphers(context, ciphers):
    """Given a PEP 543 cipher suite list, configure the SSLContext to use those
    cipher suites.

    Returns the context.
    """
    ossl_names = [_cipher_map[cipher] for cipher in ciphers if cipher in _cipher_map]
    if not ossl_names:
        msg = "Unable to find any supported ciphers!"
        raise TLSError(msg)
    context.set_ciphers(":".join(ossl_names))
    return context


def _configure_context_for_negotiation(context, inner_protocols):
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


def _init_context_common(some_context, config):
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


def _init_context_client(config):
    """Initialize an ssl.SSLContext object with a given client configuration."""
    some_context = _create_context_with_trust_store(ssl.PROTOCOL_TLS_CLIENT, config.trust_store)

    return _init_context_common(some_context, config)


def _init_context_server(config):
    """Initialize an ssl.SSLContext object with a given server configuration."""
    some_context = _create_context_with_trust_store(ssl.PROTOCOL_TLS_SERVER, config.trust_store)

    some_context = _configure_context_for_certs(some_context, config.certificate_chain)

    return _init_context_common(some_context, config)


class OpenSSLTLSSocket(TLSSocket):
    """A TLSSocket implementation based on OpenSSL."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init(args, kwargs)

    @classmethod
    def _create(cls, parent_context, ssl_context, address):
        self = cls.__new__(cls)
        self._parent_context = parent_context
        self._ssl_context = ssl_context

        hostname, _ = address
        sock = socket.create_connection(address)
        self._socket = ssl_context.wrap_socket(sock, server_hostname=hostname)

        return self

    @property
    def context(self):
        return self._parent_context

    @property
    def socket(self):
        return self._socket

    @property
    def cipher(self) -> CipherSuite | int:
        # This is the OpenSSL cipher name. We want the ID, which we can get by
        # looking for this entry in the context's list of supported ciphers.
        # FIXME: This works only on 3.6. To get this to work elsewhere, we may
        # need to vendor tlsdb.
        ossl_cipher, _, _ = self._socket.cipher()

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

    @property
    def negotiated_protocol(self) -> NextProtocol | bytes | None:
        proto = self._socket.selected_alpn_protocol()

        # The standard library returns this as a str, we want bytes.
        if proto is not None:
            proto = proto.encode("ascii")

        try:
            return NextProtocol(proto)
        except ValueError:
            return proto

    @property
    def negotiated_tls_version(self):
        ossl_version = self._socket.version()
        if ossl_version is None:
            return None
        else:
            return TLSVersion(ossl_version)


class OpenSSLClientContext(ClientContext):
    """This class controls and creates wrapped sockets and buffers for using the
    standard library bindings to OpenSSL to perform TLS connections on the
    client side of a network connection.
    """

    def __init__(self, configuration: TLSClientConfiguration) -> None:
        self._configuration = configuration

    @property
    def configuration(self) -> TLSClientConfiguration:
        return self._configuration

    def connect(self, address):
        """Create a buffered I/O object that can be used to do TLS."""
        ossl_context = _init_context_client(self._configuration)

        return OpenSSLTLSSocket._create(
            parent_context=self,
            ssl_context=ossl_context,
            address=address,
        )


class OpenSSLServerContext(ServerContext):
    """This class controls and creates wrapped sockets and buffers for using the
    standard library bindings to OpenSSL to perform TLS connections on the
    server side of a network connection.
    """

    def __init__(self, configuration: TLSServerConfiguration) -> None:
        self._configuration = configuration

    @property
    def configuration(self) -> TLSServerConfiguration:
        return self._configuration

    def connect(self, address) -> OpenSSLTLSSocket:
        """Create a buffered I/O object that can be used to do TLS."""
        ossl_context = _init_context_server(self._configuration)

        return OpenSSLTLSSocket._create(
            parent_context=self,
            ssl_context=ossl_context,
            address=address,
        )


class OpenSSLCertificate(Certificate):
    """A handle to a certificate object, either on disk or in a buffer, that can
    be used for either server or client connectivity.
    """

    def __init__(self, path: os.PathLike | None = None):
        self._cert_path = path

    @classmethod
    def from_buffer(cls, buffer: bytes) -> OpenSSLCertificate:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(buffer)
        return cls(path=path)

    @classmethod
    def from_file(cls, path: os.PathLike) -> OpenSSLCertificate:
        return cls(path=path)


class OpenSSLPrivateKey(PrivateKey):
    """A handle to a private key object, either on disk or in a buffer, that can
    be used along with a certificate for either server or client connectivity.
    """

    def __init__(self, path: os.PathLike | None = None, password: bytes | None = None):
        self._key_path = path
        self._password = password

    @classmethod
    def from_buffer(cls, buffer: bytes, password: bytes | None = None):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(buffer)
        return cls(path=path, password=password)

    @classmethod
    def from_file(cls, path: os.PathLike, password: bytes | None = None):
        return cls(path=path, password=password)


class OpenSSLTrustStore(TrustStore):
    """A handle to a trust store object, either on disk or the system trust store,
    that can be used to validate the certificates presented by a remote peer.
    """

    def __init__(self, path: os.PathLike):
        self._trust_path = path

    @classmethod
    def system(cls) -> OpenSSLTrustStore:
        return _SYSTEMTRUSTSTORE

    @classmethod
    def from_pem_file(cls, path) -> OpenSSLTrustStore:
        return cls(path=path)


# We use a sentinel object for the system trust store that is guaranteed not
# to compare equal to any other object.
_SYSTEMTRUSTSTORE = OpenSSLTrustStore(object())

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
    client_config = TLSClientConfiguration(trust_store=OpenSSLTrustStore.system())
    client_ctx = STDLIB_BACKEND.client_context(client_config)
    tls_socket = client_ctx.connect(("www.python.org", 443))
    print(tls_socket.negotiated_tls_version)
    print(tls_socket.cipher)
    print(tls_socket.negotiated_protocol)

    tls_socket.socket.write(
        b"GET / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close"
        b"\r\nAccept-Encoding: identity\r\n\r\n",
    )
    print(tls_socket.socket.read(4096))
