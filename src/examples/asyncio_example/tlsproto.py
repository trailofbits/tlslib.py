"""Using TLSLib in asyncio"""
# TODO: license?
# Based on asyncio/sslproto.py
# Contains code from https://github.com/MagicStack/uvloop/tree/v0.16.0
# SPDX-License-Identifier: PSF-2.0 AND (MIT OR Apache-2.0)
# SPDX-FileCopyrightText: Copyright (c) 2015-2021 MagicStack Inc.  http://magic.io

import collections

# import enum
import warnings

try:
    import tlslib.tlslib as tls
    from tlslib.stdlib import STDLIB_BACKEND as backend
except ImportError:  # pragma: no cover
    tls = None
    backend = None

from asyncio import constants, exceptions, protocols, transports
from asyncio.log import logger
from asyncio.sslproto import (
    AppProtocolState,
)
from asyncio.sslproto import (
    SSLProtocolState as TLSProtocolState,
)

if tls is not None:
    TLSAgainErrors = (tls.WantReadError,)  # TODO: How to catch ssl.SSLSyscallError?

# class SSLProtocolState(enum.Enum):
#     UNWRAPPED = "UNWRAPPED"
#     DO_HANDSHAKE = "DO_HANDSHAKE"
#     WRAPPED = "WRAPPED"
#     FLUSHING = "FLUSHING"
#     SHUTDOWN = "SHUTDOWN"


# class AppProtocolState(enum.Enum):
#     # This tracks the state of app protocol (https://git.io/fj59P):
#     #
#     #     INIT -cm-> CON_MADE [-dr*->] [-er-> EOF?] -cl-> CON_LOST
#     #
#     # * cm: connection_made()
#     # * dr: data_received()
#     # * er: eof_received()
#     # * cl: connection_lost()

#     STATE_INIT = "STATE_INIT"
#     STATE_CON_MADE = "STATE_CON_MADE"
#     STATE_EOF = "STATE_EOF"
#     STATE_CON_LOST = "STATE_CON_LOST"


def _create_transport_context(server_side):
    if server_side:
        raise ValueError("Server side TLS needs a valid TLSServerContext")

    # Client side may pass tls=True to use a default
    # context; in that case the tlscontext passed is None.
    # The default is secure for client connections.

    tlscontext = backend.client_context(tls.TLSClientConfiguration())

    return tlscontext


def add_flowcontrol_defaults(high, low, kb):
    """Add flowcontrol defaults"""
    if high is None:
        if low is None:
            hi = kb * 1024
        else:
            lo = low
            hi = 4 * lo
    else:
        hi = high
    if low is None:
        lo = hi // 4
    else:
        lo = low

    if not hi >= lo >= 0:
        raise ValueError(f"high ({hi!r}) must be >= low ({lo!r}) must be >= 0")

    return hi, lo


class _TLSProtocolTransport(transports._FlowControlMixin, transports.Transport):
    _start_tls_compatible = True
    _sendfile_compatible = constants._SendfileMode.FALLBACK

    def __init__(self, loop, tls_protocol):
        self._loop = loop
        self._tls_protocol = tls_protocol
        self._closed = False

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        return self._tls_protocol._get_extra_info(name, default)

    def set_protocol(self, protocol):
        self._tls_protocol._set_app_protocol(protocol)

    def get_protocol(self):
        return self._tls_protocol._app_protocol

    def is_closing(self):
        return self._closed

    def close(self):
        """Close the transport.

        Buffered data will be flushed asynchronously.  No more data
        will be received.  After all buffered data is flushed, the
        protocol's connection_lost() method will (eventually) called
        with None as its argument.
        """
        if not self._closed:
            self._closed = True
            self._tls_protocol._start_shutdown()
        else:
            self._tls_protocol = None

    def __del__(self, _warnings=warnings):
        if not self._closed:
            self._closed = True
            _warnings.warn(
                "unclosed transport <asyncio._TLSProtocolTransport " "object>", ResourceWarning
            )

    def is_reading(self):
        """Is the reading currently paused"""
        return not self._tls_protocol._app_reading_paused

    def pause_reading(self):
        """Pause the receiving end.

        No data will be passed to the protocol's data_received()
        method until resume_reading() is called.
        """
        self._tls_protocol._pause_reading()

    def resume_reading(self):
        """Resume the receiving end.

        Data received will once again be passed to the protocol's
        data_received() method.
        """
        self._tls_protocol._resume_reading()

    def set_write_buffer_limits(self, high=None, low=None):
        """Set the high- and low-water limits for write flow control.

        These two values control when to call the protocol's
        pause_writing() and resume_writing() methods.  If specified,
        the low-water limit must be less than or equal to the
        high-water limit.  Neither value can be negative.

        The defaults are implementation-specific.  If only the
        high-water limit is given, the low-water limit defaults to an
        implementation-specific value less than or equal to the
        high-water limit.  Setting high to zero forces low to zero as
        well, and causes pause_writing() to be called whenever the
        buffer becomes non-empty.  Setting low to zero causes
        resume_writing() to be called only once the buffer is empty.
        Use of zero for either limit is generally sub-optimal as it
        reduces opportunities for doing I/O and computation
        concurrently.
        """
        self._tls_protocol._set_write_buffer_limits(high, low)
        self._tls_protocol._control_app_writing()

    def get_write_buffer_limits(self):
        """Return the current limits of the write buffers."""
        return (self._tls_protocol._outgoing_low_water, self._tls_protocol._outgoing_high_water)

    def get_write_buffer_size(self):
        """Return the current size of the write buffers."""
        return self._tls_protocol._get_write_buffer_size()

    def set_read_buffer_limits(self, high=None, low=None):
        """Set the high- and low-water limits for read flow control.

        These two values control when to call the upstream transport's
        pause_reading() and resume_reading() methods.  If specified,
        the low-water limit must be less than or equal to the
        high-water limit.  Neither value can be negative.

        The defaults are implementation-specific.  If only the
        high-water limit is given, the low-water limit defaults to an
        implementation-specific value less than or equal to the
        high-water limit.  Setting high to zero forces low to zero as
        well, and causes pause_reading() to be called whenever the
        buffer becomes non-empty.  Setting low to zero causes
        resume_reading() to be called only once the buffer is empty.
        Use of zero for either limit is generally sub-optimal as it
        reduces opportunities for doing I/O and computation
        concurrently.
        """
        self._tls_protocol._set_read_buffer_limits(high, low)
        self._tls_protocol._control_tls_reading()

    def get_read_buffer_limits(self):
        return (self._tls_protocol._incoming_low_water, self._tls_protocol._incoming_high_water)

    def get_read_buffer_size(self):
        """Return the current size of the read buffer."""
        return self._tls_protocol._get_read_buffer_size()

    @property
    def _protocol_paused(self):
        # Required for sendfile fallback pause_writing/resume_writing logic
        return self._tls_protocol._app_writing_paused

    def write(self, data):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it
        to be sent out asynchronously.
        """
        if not isinstance(data, bytes | bytearray | memoryview):
            raise TypeError(f"data: expecting a bytes-like instance, " f"got {type(data).__name__}")
        if not data:
            return
        self._tls_protocol._write_appdata((data,))

    def writelines(self, list_of_data):
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and
        calls write() on the result.
        """
        self._tls_protocol._write_appdata(list_of_data)

    def write_eof(self):
        """Close the write end after flushing buffered data.

        This raises :exc:`NotImplementedError` right now.
        """
        raise NotImplementedError

    def can_write_eof(self):
        """Return True if this transport supports write_eof(), False if not."""
        return False

    def abort(self):
        """Close the transport immediately.

        Buffered data will be lost.  No more data will be received.
        The protocol's connection_lost() method will (eventually) be
        called with None as its argument.
        """
        self._force_close(None)

    def _force_close(self, exc):
        self._closed = True
        if self._tls_protocol is not None:
            self._tls_protocol._abort(exc)

    def _test__append_write_backlog(self, data):
        # for test only
        self._tls_protocol._write_backlog.append(data)
        self._tls_protocol._write_buffer_size += len(data)


class TLSProtocol(protocols.BufferedProtocol):
    """TLSProtocol class"""

    max_size = 256 * 1024  # Buffer size passed to read()

    _handshake_start_time = None
    _handshake_timeout_handle = None
    _shutdown_timeout_handle = None

    def __init__(
        self,
        loop,
        app_protocol,
        tlscontext,
        waiter,
        server_side=False,
        server_hostname=None,
        call_connection_made=True,
        tls_handshake_timeout=None,
        tls_shutdown_timeout=None,
    ):
        """Initialize TLSProtocol"""
        if tls is None:
            raise RuntimeError("tlslib module not available")

        self._tls_buffer = bytearray(self.max_size)
        self._tls_buffer_view = memoryview(self._tls_buffer)

        if tls_handshake_timeout is None:
            tls_handshake_timeout = constants.SSL_HANDSHAKE_TIMEOUT
        elif tls_handshake_timeout <= 0:
            raise ValueError(
                f"tls_handshake_timeout should be a positive number, "
                f"got {tls_handshake_timeout}"
            )
        if tls_shutdown_timeout is None:
            tls_shutdown_timeout = constants.SSL_SHUTDOWN_TIMEOUT
        elif tls_shutdown_timeout <= 0:
            raise ValueError(
                f"tls_shutdown_timeout should be a positive number, " f"got {tls_shutdown_timeout}"
            )

        if not tlscontext:
            tlscontext = _create_transport_context(server_side)

        self._server_side = server_side
        if server_hostname and not server_side:
            self._server_hostname = server_hostname
        else:
            self._server_hostname = None
        self._tlscontext = tlscontext
        # TLS-specific extra info. More info are set when the handshake
        # completes.
        self._extra = dict(tlscontext=tlscontext)

        # App data write buffering
        self._write_backlog = collections.deque()
        self._write_buffer_size = 0

        self._waiter = waiter
        self._loop = loop
        self._set_app_protocol(app_protocol)
        self._app_transport = None
        self._app_transport_created = False
        # transport, ex: SelectorSocketTransport
        self._transport = None
        self._tls_handshake_timeout = tls_handshake_timeout
        self._tls_shutdown_timeout = tls_shutdown_timeout
        # TLS and state machine

        self._state = TLSProtocolState.UNWRAPPED
        self._conn_lost = 0  # Set when connection_lost called
        if call_connection_made:
            self._app_state = AppProtocolState.STATE_INIT
        else:
            self._app_state = AppProtocolState.STATE_CON_MADE

        if server_side:
            self._tlsobj = self._tlscontext.create_buffer()
        else:
            self._tlsobj = self._tlscontext.create_buffer(server_hostname=self._server_hostname)

        # Flow Control
        self._tls_writing_paused = False

        self._app_reading_paused = False

        self._tls_reading_paused = False
        self._incoming_high_water = 0
        self._incoming_low_water = 0
        self._set_read_buffer_limits()
        self._eof_received = False

        self._app_writing_paused = False
        self._outgoing_high_water = 0
        self._outgoing_low_water = 0
        self._set_write_buffer_limits()
        self._get_app_transport()

    def _set_app_protocol(self, app_protocol):
        self._app_protocol = app_protocol
        # Make fast hasattr check first
        if hasattr(app_protocol, "get_buffer") and isinstance(
            app_protocol, protocols.BufferedProtocol
        ):
            self._app_protocol_get_buffer = app_protocol.get_buffer
            self._app_protocol_buffer_updated = app_protocol.buffer_updated
            self._app_protocol_is_buffer = True
        else:
            self._app_protocol_is_buffer = False

    def _wakeup_waiter(self, exc=None):
        if self._waiter is None:
            return
        if not self._waiter.cancelled():
            if exc is not None:
                self._waiter.set_exception(exc)
            else:
                self._waiter.set_result(None)
        self._waiter = None

    def _get_app_transport(self):
        if self._app_transport is None:
            if self._app_transport_created:
                raise RuntimeError("Creating _TLSProtocolTransport twice")
            self._app_transport = _TLSProtocolTransport(self._loop, self)
            self._app_transport_created = True
        return self._app_transport

    def connection_made(self, transport):
        """Called when the low-level connection is made.

        Start the TLS handshake.
        """
        self._transport = transport
        self._start_handshake()

    def connection_lost(self, exc):
        """Called when the low-level connection is lost or closed.

        The argument is an exception object or None (the latter
        meaning a regular EOF is received or the connection was
        aborted or closed).
        """
        self._write_backlog.clear()
        self._tlsobj.process_outgoing(-1)
        self._conn_lost += 1

        # Just mark the app transport as closed so that its __dealloc__
        # doesn't complain.
        if self._app_transport is not None:
            self._app_transport._closed = True

        if self._state != TLSProtocolState.DO_HANDSHAKE:
            if (
                self._app_state == AppProtocolState.STATE_CON_MADE
                or self._app_state == AppProtocolState.STATE_EOF
            ):
                self._app_state = AppProtocolState.STATE_CON_LOST
                self._loop.call_soon(self._app_protocol.connection_lost, exc)
        self._set_state(TLSProtocolState.UNWRAPPED)
        self._transport = None
        self._app_transport = None
        self._app_protocol = None
        self._wakeup_waiter(exc)

        if self._shutdown_timeout_handle:
            self._shutdown_timeout_handle.cancel()
            self._shutdown_timeout_handle = None
        if self._handshake_timeout_handle:
            self._handshake_timeout_handle.cancel()
            self._handshake_timeout_handle = None

    def get_buffer(self, n):
        """Get buffer."""
        want = n
        if want <= 0 or want > self.max_size:
            want = self.max_size
        if len(self._tls_buffer) < want:
            self._tls_buffer = bytearray(want)
            self._tls_buffer_view = memoryview(self._tls_buffer)
        return self._tls_buffer_view

    def buffer_updated(self, nbytes):
        """Buffer updated"""
        self._tlsobj.process_incoming(self._tls_buffer_view[:nbytes])

        if self._state == TLSProtocolState.DO_HANDSHAKE:
            self._do_handshake()

        elif self._state == TLSProtocolState.WRAPPED:
            self._do_read()

        elif self._state == TLSProtocolState.FLUSHING:
            self._do_flush()

        elif self._state == TLSProtocolState.SHUTDOWN:
            self._do_shutdown()

    def eof_received(self):
        """Called when the other end of the low-level stream
        is half-closed.

        If this returns a false value (including None), the transport
        will close itself.  If it returns a true value, closing the
        transport is up to the protocol.
        """
        self._eof_received = True
        try:
            if self._loop.get_debug():
                logger.debug("%r received EOF", self)

            if self._state == TLSProtocolState.DO_HANDSHAKE:
                self._on_handshake_complete(ConnectionResetError)

            elif self._state == TLSProtocolState.WRAPPED:
                self._set_state(TLSProtocolState.FLUSHING)
                if self._app_reading_paused:
                    return True
                else:
                    self._do_flush()

            elif self._state == TLSProtocolState.FLUSHING:
                self._do_write()
                self._set_state(TLSProtocolState.SHUTDOWN)
                self._do_shutdown()

            elif self._state == TLSProtocolState.SHUTDOWN:
                self._do_shutdown()

        except Exception:
            self._transport.close()
            raise

    def _get_extra_info(self, name, default=None):
        if name in self._extra:
            return self._extra[name]
        elif self._transport is not None:
            return self._transport.get_extra_info(name, default)
        else:
            return default

    def _set_state(self, new_state):
        allowed = False

        if new_state == TLSProtocolState.UNWRAPPED:
            allowed = True

        elif (
            self._state == TLSProtocolState.UNWRAPPED and new_state == TLSProtocolState.DO_HANDSHAKE
        ):
            allowed = True

        elif self._state == TLSProtocolState.DO_HANDSHAKE and new_state == TLSProtocolState.WRAPPED:
            allowed = True

        elif self._state == TLSProtocolState.WRAPPED and new_state == TLSProtocolState.FLUSHING:
            allowed = True

        elif self._state == TLSProtocolState.FLUSHING and new_state == TLSProtocolState.SHUTDOWN:
            allowed = True

        if allowed:
            self._state = new_state

        else:
            raise RuntimeError(f"cannot switch state from {self._state} to {new_state}")

    # Handshake flow

    def _start_handshake(self):
        if self._loop.get_debug():
            logger.debug("%r starts TLS handshake", self)
            self._handshake_start_time = self._loop.time()
        else:
            self._handshake_start_time = None

        self._set_state(TLSProtocolState.DO_HANDSHAKE)

        # start handshake timeout count down
        self._handshake_timeout_handle = self._loop.call_later(
            self._tls_handshake_timeout, lambda: self._check_handshake_timeout()
        )

        self._do_handshake()

    def _check_handshake_timeout(self):
        if self._state == TLSProtocolState.DO_HANDSHAKE:
            msg = (
                f"TLS handshake is taking longer than "
                f"{self._tls_handshake_timeout} seconds: "
                f"aborting the connection"
            )
            self._fatal_error(ConnectionAbortedError(msg))

    def _do_handshake(self):
        try:
            self._tlsobj.do_handshake()
        except TLSAgainErrors:
            self._process_outgoing()
        except tls.TLSError as exc:
            self._on_handshake_complete(exc)
        else:
            self._on_handshake_complete(None)

    def _on_handshake_complete(self, handshake_exc):
        if self._handshake_timeout_handle is not None:
            self._handshake_timeout_handle.cancel()
            self._handshake_timeout_handle = None

        tlsobj = self._tlsobj
        try:
            if handshake_exc is None:
                self._set_state(TLSProtocolState.WRAPPED)
            else:
                raise handshake_exc

            # peercert = tlsobj.getpeercert() # TODO: Figure out what to do with peercert here

        except Exception as exc:
            handshake_exc = None
            self._set_state(TLSProtocolState.UNWRAPPED)
            # if isinstance(exc, ssl.CertificateError): #TODO: how to catch certificateerror?
            #     msg = 'TLS handshake failed on verifying the certificate'
            # else:
            msg = "TLS handshake failed"
            self._fatal_error(exc, msg)
            self._wakeup_waiter(exc)
            return

        if self._loop.get_debug():
            dt = self._loop.time() - self._handshake_start_time
            logger.debug("%r: TLS handshake took %.1f ms", self, dt * 1e3)

        # Add extra info that becomes available after handshake.
        self._extra.update(  # peercert=peercert,
            cipher=tlsobj.cipher(),
            # compression=tlsobj.compression(), #TODO: compression?
            tls_object=tlsobj,
        )
        if self._app_state == AppProtocolState.STATE_INIT:
            self._app_state = AppProtocolState.STATE_CON_MADE
            self._app_protocol.connection_made(self._get_app_transport())
        self._wakeup_waiter()
        self._do_read()

    # Shutdown flow

    def _start_shutdown(self):
        if self._state in (
            TLSProtocolState.FLUSHING,
            TLSProtocolState.SHUTDOWN,
            TLSProtocolState.UNWRAPPED,
        ):
            return
        if self._app_transport is not None:
            self._app_transport._closed = True
        if self._state == TLSProtocolState.DO_HANDSHAKE:
            self._abort(None)
        else:
            self._set_state(TLSProtocolState.FLUSHING)
            self._shutdown_timeout_handle = self._loop.call_later(
                self._tls_shutdown_timeout, lambda: self._check_shutdown_timeout()
            )
            self._do_flush()

    def _check_shutdown_timeout(self):
        if self._state in (TLSProtocolState.FLUSHING, TLSProtocolState.SHUTDOWN):
            self._transport._force_close(exceptions.TimeoutError("TLS shutdown timed out"))

    def _do_flush(self):
        self._do_read()
        self._set_state(TLSProtocolState.SHUTDOWN)
        self._do_shutdown()

    def _do_shutdown(self):
        try:
            if not self._eof_received:
                self._tlsobj.shutdown()
        except TLSAgainErrors:
            self._process_outgoing()
        except tls.TLSError as exc:
            self._on_shutdown_complete(exc)
        else:
            self._process_outgoing()
            self._call_eof_received()
            self._on_shutdown_complete(None)

    def _on_shutdown_complete(self, shutdown_exc):
        if self._shutdown_timeout_handle is not None:
            self._shutdown_timeout_handle.cancel()
            self._shutdown_timeout_handle = None

        if shutdown_exc:
            self._fatal_error(shutdown_exc)
        else:
            self._loop.call_soon(self._transport.close)

    def _abort(self, exc):
        self._set_state(TLSProtocolState.UNWRAPPED)
        if self._transport is not None:
            self._transport._force_close(exc)

    # Outgoing flow

    def _write_appdata(self, list_of_data):
        if self._state in (
            TLSProtocolState.FLUSHING,
            TLSProtocolState.SHUTDOWN,
            TLSProtocolState.UNWRAPPED,
        ):
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                logger.warning("TLS connection is closed")
            self._conn_lost += 1
            return

        for data in list_of_data:
            self._write_backlog.append(data)
            self._write_buffer_size += len(data)

        try:
            if self._state == TLSProtocolState.WRAPPED:
                self._do_write()

        except Exception as ex:
            self._fatal_error(ex, "Fatal error on TLS protocol")

    def _do_write(self):
        try:
            while self._write_backlog:
                data = self._write_backlog[0]
                count = self._tlsobj.write(data)
                data_len = len(data)
                if count < data_len:
                    self._write_backlog[0] = data[count:]
                    self._write_buffer_size -= count
                else:
                    del self._write_backlog[0]
                    self._write_buffer_size -= data_len
        except TLSAgainErrors:
            pass
        self._process_outgoing()

    def _process_outgoing(self):
        if not self._tls_writing_paused:
            data = self._tlsobj.process_outgoing(self._tlsobj.outgoing_bytes_buffered())
            if len(data):
                self._transport.write(data)
        self._control_app_writing()

    # Incoming flow

    def _do_read(self):
        if self._state not in (
            TLSProtocolState.WRAPPED,
            TLSProtocolState.FLUSHING,
        ):
            return
        try:
            if not self._app_reading_paused:
                if self._app_protocol_is_buffer:
                    self._do_read__buffered()
                else:
                    self._do_read__copied()
                if self._write_backlog:
                    self._do_write()
                else:
                    self._process_outgoing()
            self._control_tls_reading()
        except Exception as ex:
            self._fatal_error(ex, "Fatal error on TLS protocol")

    def _do_read__buffered(self):
        offset = 0
        count = 1

        buf = self._app_protocol_get_buffer(self._get_read_buffer_size())
        wants = len(buf)

        try:
            count = self._tlsobj.read(wants, buf)

            if count > 0:
                offset = count
                while offset < wants:
                    count = self._tlsobj.read(wants - offset, buf[offset:])
                    if count > 0:
                        offset += count
                    else:
                        break
                else:
                    self._loop.call_soon(lambda: self._do_read())
        except TLSAgainErrors:
            pass
        if offset > 0:
            self._app_protocol_buffer_updated(offset)
        if not count:
            # close_notify
            self._call_eof_received()
            self._start_shutdown()

    def _do_read__copied(self):
        chunk = b"1"
        zero = True
        one = False

        try:
            while True:
                chunk = self._tlsobj.read(self.max_size)
                if not chunk:
                    break
                if zero:
                    zero = False
                    one = True
                    first = chunk
                elif one:
                    one = False
                    data = [first, chunk]
                else:
                    data.append(chunk)
        except TLSAgainErrors:
            pass
        if one:
            self._app_protocol.data_received(first)
        elif not zero:
            self._app_protocol.data_received(b"".join(data))
        if not chunk:
            # close_notify
            self._call_eof_received()
            self._start_shutdown()

    def _call_eof_received(self):
        try:
            if self._app_state == AppProtocolState.STATE_CON_MADE:
                self._app_state = AppProtocolState.STATE_EOF
                keep_open = self._app_protocol.eof_received()
                if keep_open:
                    logger.warning(
                        "returning true from eof_received() " "has no effect when using TLS"
                    )
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as ex:
            self._fatal_error(ex, "Error calling eof_received()")

    # Flow control for writes from APP socket

    def _control_app_writing(self):
        size = self._get_write_buffer_size()
        if size >= self._outgoing_high_water and not self._app_writing_paused:
            self._app_writing_paused = True
            try:
                self._app_protocol.pause_writing()
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:
                self._loop.call_exception_handler(
                    {
                        "message": "protocol.pause_writing() failed",
                        "exception": exc,
                        "transport": self._app_transport,
                        "protocol": self,
                    }
                )
        elif size <= self._outgoing_low_water and self._app_writing_paused:
            self._app_writing_paused = False
            try:
                self._app_protocol.resume_writing()
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:
                self._loop.call_exception_handler(
                    {
                        "message": "protocol.resume_writing() failed",
                        "exception": exc,
                        "transport": self._app_transport,
                        "protocol": self,
                    }
                )

    def _get_write_buffer_size(self):
        return self._tlsobj.outgoing_bytes_buffered() + self._write_buffer_size

    def _set_write_buffer_limits(self, high=None, low=None):
        high, low = add_flowcontrol_defaults(high, low, constants.FLOW_CONTROL_HIGH_WATER_SSL_WRITE)
        self._outgoing_high_water = high
        self._outgoing_low_water = low

    # Flow control for reads to APP socket

    def _pause_reading(self):
        self._app_reading_paused = True

    def _resume_reading(self):
        if self._app_reading_paused:
            self._app_reading_paused = False

            def resume():
                if self._state == TLSProtocolState.WRAPPED:
                    self._do_read()
                elif self._state == TLSProtocolState.FLUSHING:
                    self._do_flush()
                elif self._state == TLSProtocolState.SHUTDOWN:
                    self._do_shutdown()

            self._loop.call_soon(resume)

    # Flow control for reads from TLS socket

    def _control_tls_reading(self):
        size = self._get_read_buffer_size()
        if size >= self._incoming_high_water and not self._tls_reading_paused:
            self._tls_reading_paused = True
            self._transport.pause_reading()
        elif size <= self._incoming_low_water and self._tls_reading_paused:
            self._tls_reading_paused = False
            self._transport.resume_reading()

    def _set_read_buffer_limits(self, high=None, low=None):
        high, low = add_flowcontrol_defaults(high, low, constants.FLOW_CONTROL_HIGH_WATER_SSL_READ)
        self._incoming_high_water = high
        self._incoming_low_water = low

    def _get_read_buffer_size(self):
        return self._tlsobj.incoming_bytes_buffered()

    # Flow control for writes to TLS socket

    def pause_writing(self):
        """Called when the low-level transport's buffer goes over
        the high-water mark.
        """
        assert not self._tls_writing_paused
        self._tls_writing_paused = True

    def resume_writing(self):
        """Called when the low-level transport's buffer drains below
        the low-water mark.
        """
        assert self._tls_writing_paused
        self._tls_writing_paused = False
        self._process_outgoing()

    def _fatal_error(self, exc, message="Fatal error on transport"):
        if self._transport:
            self._transport._force_close(exc)

        if isinstance(exc, OSError):
            if self._loop.get_debug():
                logger.debug("%r: %s", self, message, exc_info=True)
        elif not isinstance(exc, exceptions.CancelledError):
            self._loop.call_exception_handler(
                {
                    "message": message,
                    "exception": exc,
                    "transport": self._transport,
                    "protocol": self,
                }
            )
