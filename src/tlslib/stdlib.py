"""Shims the standard library OpenSSL module into the amended PEP 543 API."""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
import typing
import weakref
from collections.abc import Buffer, Sequence
from contextlib import contextmanager
from pathlib import Path

import truststore

from .tlslib import (
    DEFAULT_CIPHER_LIST,
    Backend,
    Certificate,
    CipherSuite,
    ConfigurationError,
    NextProtocol,
    PrivateKey,
    RaggedEOF,
    SigningChain,
    TLSClientConfiguration,
    TLSError,
    TLSServerConfiguration,
    TLSVersion,
    TrustStore,
    WantReadError,
    WantWriteError,
)

_SSLContext = ssl.SSLContext | truststore.SSLContext

_TLSMinVersionOpts = {
    TLSVersion.MINIMUM_SUPPORTED: ssl.TLSVersion.MINIMUM_SUPPORTED,
    TLSVersion.TLSv1_2: ssl.TLSVersion.TLSv1_2,
    TLSVersion.TLSv1_3: ssl.TLSVersion.TLSv1_3,
}

_TLSMaxVersionOpts = {
    TLSVersion.TLSv1_2: ssl.TLSVersion.TLSv1_2,
    TLSVersion.TLSv1_3: ssl.TLSVersion.TLSv1_3,
    TLSVersion.MAXIMUM_SUPPORTED: ssl.TLSVersion.MAXIMUM_SUPPORTED,
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
        pass
    except ssl.SSLWantReadError:
        raise WantReadError("Must read data") from None
    except ssl.SSLWantWriteError:
        raise WantWriteError("Must write data") from None
    except ssl.SSLEOFError:
        raise RaggedEOF("Ragged EOF") from None
    except ssl.SSLError as e:
        raise TLSError(e) from None


def _remove_path(ts_cert_priv: TrustStore | Certificate | PrivateKey) -> None:
    ts_cert_priv._path = None


def _is_system_trust_store(trust_store: TrustStore | None) -> bool:
    return trust_store is None or (
        trust_store._path is None and trust_store._buffer is None and trust_store._id is None
    )


def _get_path_from_trust_store(
    context: _SSLContext, trust_store: TrustStore | None
) -> os.PathLike | None:
    assert trust_store is not None
    if trust_store._path is not None:
        return trust_store._path
    elif trust_store._buffer is not None:
        tmp_path = tempfile.NamedTemporaryFile(mode="w+b", delete=False, delete_on_close=False)
        tmp_path.write(trust_store._buffer)
        tmp_path.close()
        # Store this path to prevent creation of multiple files for each trust store
        trust_store._path = Path(tmp_path.name)
        weakref.finalize(context, os.remove, tmp_path.name)
        # Remove the path in case the trust store outlives the context
        weakref.finalize(context, _remove_path, trust_store)
        return trust_store._path
    elif trust_store._id is not None:
        raise ConfigurationError("This backend does not support id-based trust stores.")
    else:
        return None


def _create_client_context_with_trust_store(trust_store: TrustStore | None) -> _SSLContext:
    some_context: _SSLContext

    if _is_system_trust_store(trust_store):
        some_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    else:
        some_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trust_store_path = _get_path_from_trust_store(some_context, trust_store)
        some_context.load_verify_locations(trust_store_path)

    # TLS Compression is a security risk and is removed in TLS v1.3
    some_context.options |= ssl.OP_NO_COMPRESSION

    some_context.verify_flags = (
        ssl.VerifyFlags.VERIFY_X509_STRICT | ssl.VerifyFlags.VERIFY_X509_PARTIAL_CHAIN
    )

    return some_context


def _create_server_context_with_trust_store(
    trust_store: TrustStore | None,
) -> ssl.SSLContext:
    some_context: ssl.SSLContext

    # truststore does not support server side
    some_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    if trust_store is not None:
        some_context.verify_mode = ssl.CERT_REQUIRED
        trust_store_path = _get_path_from_trust_store(some_context, trust_store)

        if trust_store_path is not None:
            some_context.load_verify_locations(trust_store_path)
        else:
            some_context.load_default_certs(ssl.Purpose.CLIENT_AUTH)

    # TLS Compression is a security risk and is removed in TLS v1.3
    some_context.options |= ssl.OP_NO_COMPRESSION

    return some_context


def _sni_callback_builder(
    _name_to_chain_map: weakref.WeakValueDictionary[str, SigningChain],
    original_config: TLSServerConfiguration,
) -> typing.Callable[[ssl.SSLSocket, str, ssl.SSLContext], ssl.AlertDescription | None]:
    def pep543_callback(
        ssl_socket: ssl.SSLSocket,
        server_name: str,
        stdlib_context: ssl.SSLContext,
    ) -> ssl.AlertDescription | None:
        try:
            sign_chain = _name_to_chain_map[server_name]
        except KeyError:
            return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR

        new_config: TLSServerConfiguration = TLSServerConfiguration(
            certificate_chain=(sign_chain,),
            ciphers=original_config.ciphers,
            inner_protocols=original_config.inner_protocols,
            lowest_supported_version=original_config.lowest_supported_version,
            highest_supported_version=original_config.highest_supported_version,
            trust_store=original_config.trust_store,
        )
        ssl_socket.context = _init_context_server(new_config)

        # Returning None, perversely, is how one signals success from this
        # function. Will wonders never cease?
        return None

    return pep543_callback


def _configure_server_context_for_certs(
    context: ssl.SSLContext,
    cert_chain: Sequence[SigningChain] | None = None,
    sni_config: TLSServerConfiguration | None = None,
) -> ssl.SSLContext:
    if cert_chain is not None:
        if len(cert_chain) == 1:
            # Only one SigningChain, no need to configure SNI
            return _configure_context_for_single_signing_chain(context, cert_chain[0])

        elif len(cert_chain) > 1:
            # We have multiple SigningChains, need to configure SNI
            assert sni_config is not None
            return _configure_context_for_sni(context, cert_chain, sni_config)

    return context


def _get_path_from_cert_or_priv(
    context: _SSLContext, cert_or_priv: Certificate | PrivateKey
) -> os.PathLike:
    if cert_or_priv._path is not None:
        return cert_or_priv._path
    elif cert_or_priv._buffer is not None:
        tmp_path = tempfile.NamedTemporaryFile(mode="w+b", delete=False, delete_on_close=False)
        tmp_path.write(cert_or_priv._buffer)
        tmp_path.close()
        weakref.finalize(context, os.remove, tmp_path.name)
        # Store the path for future usage, preventing creation of multiple files
        cert_or_priv._path = Path(tmp_path.name)
        # Remove the path in case the cert or priv outlives the context
        weakref.finalize(context, _remove_path, cert_or_priv)
        return cert_or_priv._path
    elif cert_or_priv._id is not None:
        raise ConfigurationError(
            "This backend does not support id-based certificates \
                                  or private keys."
        )
    else:
        raise ConfigurationError("Certificate or PrivateKey cannot be empty.")


def _get_bytes_from_cert(cert: Certificate) -> bytes:
    if cert._buffer is not None:
        return cert._buffer
    elif cert._path is not None:
        # Do not save cert in memory
        return Path(cert._path).read_bytes()
    elif cert._id is not None:
        raise ConfigurationError("This backend does not support id-based certificates.")
    else:
        raise ConfigurationError("Certificate cannot be empty.")


def _configure_context_for_single_signing_chain(
    context: _SSLContext,
    cert_chain: SigningChain | None = None,
) -> _SSLContext:
    """Given a PEP 543 cert chain, configure the SSLContext to send that cert
    chain in the handshake.

    Returns the context.
    """

    if cert_chain is not None:
        cert = cert_chain.leaf[0]

        if len(cert_chain.chain) == 0:
            cert_path = _get_path_from_cert_or_priv(context, cert)

        else:
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as io:
                # Write first cert
                io.write(_get_bytes_from_cert(cert))

                for cert in cert_chain.chain:
                    io.write(b"\n")
                    io.write(_get_bytes_from_cert(cert))

            weakref.finalize(context, os.remove, io.name)
            cert_path = Path(io.name)

        key_path = None
        if cert_chain.leaf[1] is not None:
            privkey = cert_chain.leaf[1]

            key_path = _get_path_from_cert_or_priv(context, privkey)

        assert cert_path is not None
        with _error_converter():
            context.load_cert_chain(cert_path, key_path, None)

    return context


def _configure_context_for_sni(
    context: ssl.SSLContext,
    cert_chain: Sequence[SigningChain],
    sni_config: TLSServerConfiguration,
) -> ssl.SSLContext:
    # This is a mapping of concrete server names to the corresponding SigningChain
    _name_to_chain_map: weakref.WeakValueDictionary[str, SigningChain] = (
        weakref.WeakValueDictionary()
    )

    for sign_chain in cert_chain:
        # Parse leaf certificates to find server names
        cert = sign_chain.leaf[0]
        cert_path = _get_path_from_cert_or_priv(context, cert)
        dec_cert = ssl._ssl._test_decode_cert(cert_path)  # type: ignore[attr-defined]

        try:
            alt_names = dec_cert["subjectAltName"]
        except KeyError:
            continue

        server_name = None
        for name in alt_names:
            assert len(name) == 2
            if name[0] == "DNS":
                server_name = name[1]
                break

        if server_name is not None:
            _name_to_chain_map[server_name] = sign_chain

    context.sni_callback = _sni_callback_builder(_name_to_chain_map, sni_config)  # type: ignore[assignment]

    return context


def _configure_context_for_ciphers(
    context: _SSLContext, ciphers: Sequence[CipherSuite | int] | None = None
) -> _SSLContext:
    """Given a PEP 543 cipher suite list, configure the SSLContext to use those
    cipher suites.

    Returns the context.
    """
    if ciphers is None:
        # OpenSSL does not necessarily have system recommended settings
        # The default cipher list is used here instead
        ciphers = DEFAULT_CIPHER_LIST

    ossl_names = [_cipher_map[cipher] for cipher in ciphers if cipher in _cipher_map]
    if not ossl_names:
        msg = "None of the provided ciphers are supported by the OpenSSL backend!"
        raise TLSError(msg)
    with _error_converter():
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

        context.set_alpn_protocols(protocols)

    return context


def _init_context_common(
    some_context: _SSLContext,
    config: TLSClientConfiguration | TLSServerConfiguration,
) -> _SSLContext:
    some_context = _configure_context_for_ciphers(
        some_context,
        config.ciphers,
    )
    some_context = _configure_context_for_negotiation(
        some_context,
        config.inner_protocols,
    )

    # In lieu of system recommended settings, we default to TLS v1.3
    lowest_supported_version = config.lowest_supported_version
    if lowest_supported_version is None:
        lowest_supported_version = TLSVersion.TLSv1_3

    highest_supported_version = config.highest_supported_version
    if highest_supported_version is None:
        highest_supported_version = TLSVersion.MAXIMUM_SUPPORTED

    try:
        some_context.minimum_version = _TLSMinVersionOpts[lowest_supported_version]
        some_context.maximum_version = _TLSMaxVersionOpts[highest_supported_version]
    except KeyError:
        raise TLSError("Bad maximum/minimum options")

    return some_context


def _init_context_client(config: TLSClientConfiguration) -> _SSLContext:
    """Initialize an SSL context object with a given client configuration."""
    some_context = _create_client_context_with_trust_store(config.trust_store)

    some_context = _configure_context_for_single_signing_chain(
        some_context, config.certificate_chain
    )

    return _init_context_common(some_context, config)


def _init_context_server(config: TLSServerConfiguration) -> _SSLContext:
    """Initialize an SSL context object with a given server configuration."""
    some_context = _create_server_context_with_trust_store(config.trust_store)

    some_context = _configure_server_context_for_certs(
        some_context, config.certificate_chain, config
    )

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
            with _error_converter():
                self._socket = ssl_context.wrap_socket(
                    sock, server_side=server_side, server_hostname=None
                )
        else:
            hostname, _ = address
            sock = socket.create_connection(address)
            with _error_converter():
                self._socket = ssl_context.wrap_socket(
                    sock, server_side=server_side, server_hostname=hostname
                )

        self._socket.setblocking(False)

        return self

    def recv(self, bufsize: int) -> bytes:
        """Receive data from the socket. The return value is a bytes object
        representing the data received. Should not work before the handshake
        is completed."""
        with _error_converter():
            try:
                return self._socket.recv(bufsize)
            except ssl.SSLZeroReturnError:
                return b""

    def send(self, bytes: bytes) -> int:
        """Send data to the socket. The socket must be connected to a remote socket."""
        with _error_converter():
            return self._socket.send(bytes)

    def close(self, force: bool = False) -> None:
        """Unwraps the TLS connection, shuts down both halves of the connection and
        mark the socket closed. If force is True, will only shutdown own half and
        not wait for the other side. If force is False, this will raise WantReadError
        until the other side sends a close_notify alert."""

        try:
            with _error_converter():
                sock = self._socket.unwrap()
        except (ValueError, BrokenPipeError, OSError):
            # If these exceptions are raised, we close the socket without re-trying to unwrap it.
            # - ValueError: The socket was actually not wrapped
            # - BrokenPipeError: There is some issue with the socket
            # - OSError: The other side already shut down
            sock = self._socket
        except WantReadError:
            if force:
                sock = self._socket
            else:
                raise

        # NOTE: OSError indicates that the other side has already hung up.
        with _error_converter(ignore_filter=(OSError,)):
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

        with _error_converter():
            (sock, address) = self._socket.accept()
        tls_socket = OpenSSLTLSSocket.__new__(OpenSSLTLSSocket)
        tls_socket._parent_context = self._parent_context
        tls_socket._ssl_context = self._ssl_context
        tls_socket._socket = sock
        with _error_converter():
            tls_socket._socket.setblocking(False)
        return (tls_socket, address)

    def getsockname(self) -> socket._RetAddress:
        """Return the local address to which the socket is connected."""
        with _error_converter():
            return self._socket.getsockname()

    def getpeercert(self) -> bytes | None:
        """
        Return the raw DER bytes of the certificate provided by the peer
        during the handshake, if applicable.
        """
        # In order to return an OpenSSLCertificate, we must obtain the certificate in binary format
        # Obtaining the certificate as a dict is very specific to the ssl module and may be
        # difficult to implement for other backends, so this is not supported

        with _error_converter():
            cert = self._socket.getpeercert(True)

        return cert

    def getpeername(self) -> socket._RetAddress:
        """Return the remote address to which the socket is connected."""

        with _error_converter():
            return self._socket.getpeername()

    def fileno(self) -> int:
        """Return the socket's file descriptor (a small integer), or -1 on failure."""

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
        ret = self._socket.cipher()

        if ret is None:
            return None
        else:
            ossl_cipher, _, _ = ret

        for cipher in self._ssl_context.get_ciphers():
            if cipher["name"] == ossl_cipher:
                break
        # Since the cipher was negotiated using the OpenSSL context,
        # it must exist in the list of the OpenSSL supported ciphers.
        assert cipher["name"] == ossl_cipher

        cipher_id = cipher["id"] & 0xFFFF
        try:
            return CipherSuite(cipher_id)
        except ValueError:
            return cipher_id

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


class OpenSSLTLSBuffer:
    """A TLSBuffer implementation based on OpenSSL"""

    __slots__ = (
        "_ciphertext_buffer",
        "_in_bio",
        "_object",
        "_out_bio",
        "_parent_context",
        "_ssl_context",
    )

    _ciphertext_buffer: bytearray
    _in_bio: ssl.MemoryBIO
    _object: ssl.SSLObject
    _out_bio: ssl.MemoryBIO
    _parent_context: OpenSSLClientContext | OpenSSLServerContext
    _ssl_context: _SSLContext

    def __init__(self, *args: tuple, **kwargs: tuple) -> None:
        """OpenTLSBuffers should not be constructed by the user.
        Instead, the ClientContext.create_buffer() and
        ServerContext.create_buffer() use the _create() method."""
        msg = (
            f"{self.__class__.__name__} does not have a public constructor. "
            "Instances are returned by ClientContext.create_buffer() \
                or ServerContext.create_buffer()."
        )
        raise TypeError(
            msg,
        )

    @classmethod
    def _create(
        cls,
        server_hostname: str | None,
        parent_context: OpenSSLClientContext | OpenSSLServerContext,
        server_side: bool,
        ssl_context: _SSLContext,
    ) -> OpenSSLTLSBuffer:
        self = cls.__new__(cls)
        self._parent_context = parent_context
        self._ssl_context = ssl_context

        # We need this extra buffer to implement the peek/consume API, which
        # the MemoryBIO object does not allow.
        self._ciphertext_buffer = bytearray()

        # Set up the SSLObject we're going to back this with.
        self._in_bio = ssl.MemoryBIO()
        self._out_bio = ssl.MemoryBIO()

        if server_side is True:
            with _error_converter():
                self._object = ssl_context.wrap_bio(
                    self._in_bio, self._out_bio, server_side=True, server_hostname=None
                )
        else:
            with _error_converter():
                self._object = ssl_context.wrap_bio(
                    self._in_bio, self._out_bio, server_side=False, server_hostname=server_hostname
                )

        return self

    def read(self, amt: int, buffer: Buffer | None = None) -> bytes | int:
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

        with _error_converter():
            try:
                # MyPy insists that buffer must be a bytearray
                return self._object.read(amt, buffer)  # type: ignore[arg-type]
            except ssl.SSLZeroReturnError:
                return b""

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

        with _error_converter():
            return self._object.write(buf)

    # Get rid and do handshake ourselves?
    def do_handshake(self) -> None:
        """
        Performs the TLS handshake. Also performs certificate validation
        and hostname verification.
        """

        with _error_converter():
            self._object.do_handshake()

    def shutdown(self) -> None:
        """
        Performs a clean TLS shut down. This should generally be used
        whenever possible to signal to the remote peer that the content is
        finished.
        """

        with _error_converter():
            self._object.unwrap()

    def process_incoming(self, data_from_network: bytes) -> None:
        """
        Receives some TLS data from the network and stores it in an
        internal buffer.

        If the internal buffer is overfull, this method will raise
        ``WantReadError`` and store no data. At this point, the user must
        call ``read`` to remove some data from the internal buffer
        before repeating this call.
        """

        with _error_converter():
            written_len = self._in_bio.write(data_from_network)

        assert written_len == len(data_from_network)

    def incoming_bytes_buffered(self) -> int:
        """
        Returns how many bytes are in the incoming buffer waiting to be processed.
        """

        return self._in_bio.pending

    def process_outgoing(self, amount_bytes_for_network: int) -> bytes:
        """
        Returns the next ``amt`` bytes of data that should be written to
        the network from the outgoing data buffer, removing it from the
        internal buffer.
        """

        return self._out_bio.read(amount_bytes_for_network)

    def outgoing_bytes_buffered(self) -> int:
        """
        Returns how many bytes are in the outgoing buffer waiting to be sent.
        """

        return self._out_bio.pending

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

        ret = self._object.cipher()

        if ret is None:
            return None
        else:
            ossl_cipher, _, _ = ret

        for cipher in self._ssl_context.get_ciphers():
            if cipher["name"] == ossl_cipher:
                break
        # Since the cipher was negotiated using the OpenSSL context,
        # it must exist in the list of the OpenSSL supported ciphers.
        assert cipher["name"] == ossl_cipher

        cipher_id = cipher["id"] & 0xFFFF
        try:
            return CipherSuite(cipher_id)
        except ValueError:
            return cipher_id

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

        proto = self._object.selected_alpn_protocol()

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

        ossl_version = self._object.version()
        if ossl_version is None:
            return None
        else:
            return TLSVersion(ossl_version)

    def getpeercert(self) -> bytes | None:
        """
        Return the raw DER bytes of the certificate provided by the peer
        during the handshake, if applicable.
        """
        # In order to return an OpenSSLCertificate, we must obtain the certificate in binary format
        # Obtaining the certificate as a dict is very specific to the ssl module and may be
        # difficult to implement for other backends, so this is not supported
        with _error_converter():
            cert = self._object.getpeercert(True)

        return cert


class OpenSSLClientContext:
    """This class controls and creates a socket that is wrapped using the
    standard library bindings to OpenSSL to perform TLS connections on the
    client side of a network connection.
    """

    def __init__(self, configuration: TLSClientConfiguration) -> None:
        """Create a new context object from a given TLS configuration."""

        self._configuration = configuration

    @property
    def configuration(self) -> TLSClientConfiguration:
        """Returns the TLS configuration that was used to create the context."""

        return self._configuration

    def connect(self, address: tuple[str | None, int]) -> OpenSSLTLSSocket:
        """Create a socket-like object that can be used to do TLS."""
        ossl_context = _init_context_client(self._configuration)

        return OpenSSLTLSSocket._create(
            parent_context=self,
            server_side=False,
            ssl_context=ossl_context,
            address=address,
        )

    def create_buffer(self, server_hostname: str) -> OpenSSLTLSBuffer:
        """Creates a TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""

        ossl_context = _init_context_client(self._configuration)

        return OpenSSLTLSBuffer._create(
            server_hostname=server_hostname,
            parent_context=self,
            server_side=False,
            ssl_context=ossl_context,
        )


class OpenSSLServerContext:
    """This class controls and creates and creates a socket that is wrapped using the
    standard library bindings to OpenSSL to perform TLS connections on the
    server side of a network connection.
    """

    def __init__(self, configuration: TLSServerConfiguration) -> None:
        """Create a new context object from a given TLS configuration."""

        self._configuration = configuration

    @property
    def configuration(self) -> TLSServerConfiguration:
        """Returns the TLS configuration that was used to create the context."""

        return self._configuration

    def connect(self, address: tuple[str | None, int]) -> OpenSSLTLSSocket:
        """Create a socket-like object that can be used to do TLS."""
        ossl_context = _init_context_server(self._configuration)

        return OpenSSLTLSSocket._create(
            parent_context=self,
            server_side=True,
            ssl_context=ossl_context,
            address=address,
        )

    def create_buffer(self) -> OpenSSLTLSBuffer:
        """Creates a TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""

        ossl_context = _init_context_server(self._configuration)

        return OpenSSLTLSBuffer._create(
            server_hostname=None,
            parent_context=self,
            server_side=True,
            ssl_context=ossl_context,
        )


def _check_cert_or_priv(cert_or_priv: Certificate | PrivateKey) -> None:
    if cert_or_priv._path is not None or cert_or_priv._buffer is not None:
        return None
    elif cert_or_priv._id is not None:
        raise ConfigurationError(
            "This backend does not support id-based certificates \
                                  or private keys."
        )
    else:
        raise ConfigurationError("Certificate or PrivateKey cannot be empty.")


def _check_trust_store(trust_store: TrustStore | None) -> None:
    if trust_store is not None and trust_store._id is not None:
        raise ConfigurationError("This backend does not support id-based trust stores.")


def _check_sign_chain(sign_chain: SigningChain) -> None:
    leaf = sign_chain.leaf
    _check_cert_or_priv(leaf[0])
    priv_key = leaf[1]
    if priv_key is not None:
        _check_cert_or_priv(priv_key)
    for cert in sign_chain.chain:
        _check_cert_or_priv(cert)


def validate_config(tls_config: TLSClientConfiguration | TLSServerConfiguration) -> None:
    """Validates whether the OpenSSL backend supports this TLS configuration."""
    _check_trust_store(tls_config.trust_store)

    if isinstance(tls_config, TLSClientConfiguration):
        sign_chain = tls_config.certificate_chain
        if sign_chain is not None:
            _check_sign_chain(sign_chain)

    else:
        assert isinstance(tls_config, TLSServerConfiguration)
        cert_chain = tls_config.certificate_chain
        if cert_chain is not None:
            for sign_chain in cert_chain:
                _check_sign_chain(sign_chain)


#: The stdlib ``Backend`` object.
STDLIB_BACKEND = Backend(
    client_context=OpenSSLClientContext,
    server_context=OpenSSLServerContext,
    validate_config=validate_config,
)
