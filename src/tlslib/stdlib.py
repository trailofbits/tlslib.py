"""Shims the standard library OpenSSL module into the amended PEP 543 API."""

import contextlib
import socket
import ssl

import truststore

from .tlslib import (
    Backend,
    CipherSuite,
    ClientContext,
    NextProtocol,
    ServerContext,
    TLSClientConfiguration,
    TLSError,
    TLSSocket,
    TLSVersion,
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

# @contextmanager
# def _error_converter(ignore_filter=()):
#     """
#     Catches errors from the ssl module and wraps them up in TLSError
#     exceptions. Ignores certain kinds of exceptions as requested.
#     """
#         yield
#         raise


def _version_options_from_version_range(min, max):
    """Given a TLS version range, we need to convert that into options that
    exclude TLS versions as appropriate.
    """
    try:
        return _opts_from_min_version[min] | _opts_from_max_version[max]
    except KeyError:
        msg = "Bad maximum/minimum options"
        raise TLSError(msg)


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
    """Initialize an ssl.SSLContext object with a given configuration."""
    some_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    some_context.options |= ssl.OP_NO_COMPRESSION

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

    def socket(self):
        return self._socket

    def cipher(self):
        # This is the OpenSSL cipher name. We want the ID, which we can get by
        # looking for this entry in the context's list of supported ciphers.
        # FIXME: This works only on 3.6. To get this to work elsewhere, we may
        # need to vendor tlsdb.
        ossl_cipher, _, _ = self._socket.cipher()
        print("a")
        for cipher in self._ssl_context.get_ciphers():
            if cipher["name"] == ossl_cipher:
                break
        else:
            msg = "Unable to identify cipher suite"
            raise TLSError(msg)

        print("b")
        cipher_id = cipher["id"] & 0xFFFF
        try:
            return CipherSuite(cipher_id)
        except ValueError:
            print("c")
            return cipher_id

    def negotiated_protocol(self):
        proto = self._socket.selected_alpn_protocol()

        # The standard library returns this as a str, we want bytes.
        if proto is not None:
            proto = proto.encode("ascii")

        try:
            return NextProtocol(proto)
        except ValueError:
            return proto

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

    def __init__(self, configuration) -> None:
        self._configuration = configuration

    @property
    def configuration(self):
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

    def __init__(self, configuration) -> None:
        self._configuration = configuration

    @property
    def configuration(self):
        return self._configuration

    def connect(self, address):
        """Create a buffered I/O object that can be used to do TLS."""
        raise NotImplementedError


if __name__ == "__main__":
    #: The stdlib ``Backend`` object.
    STDLIB_BACKEND = Backend(
        client_context=OpenSSLClientContext,
        server_context=OpenSSLServerContext,
        tls_socket=OpenSSLTLSSocket,
    )

    client_config = TLSClientConfiguration()
    client_ctx = STDLIB_BACKEND.client_context(client_config)
    tls_socket = client_ctx.connect(("www.python.org", 443))
    print(tls_socket.negotiated_tls_version())
    print(tls_socket.cipher())
    print(tls_socket.negotiated_protocol())

    tls_socket.socket().write(
        b"GET / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
    )
    print(tls_socket.socket().read(4096))
