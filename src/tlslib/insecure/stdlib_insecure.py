"""Shims the standard library OpenSSL module into the amended PEP 543 API."""

from __future__ import annotations

import ssl
import warnings

from ..stdlib import (
    OpenSSLClientContext,
    OpenSSLServerContext,
    OpenSSLTLSBuffer,
    OpenSSLTLSSocket,
    _init_context_client,
    _init_context_server,
    _SSLContext,
    validate_config,
)
from ..tlslib import (
    TLSClientConfiguration,
    TLSServerConfiguration,
)
from . import (
    InsecureBackend,
    InsecureConfiguration,
    SecurityWarning,
)


def _apply_insecure_config(
    context: _SSLContext, insecure_config: InsecureConfiguration
) -> _SSLContext:
    ossl_context = context
    if insecure_config.disable_hostname_check:
        ossl_context.check_hostname = False
        if insecure_config.disable_verification:
            ossl_context.verify_mode = ssl.CERT_NONE

    return ossl_context


class OpenSSLInsecureClientContext(OpenSSLClientContext):
    """
    Class allowing users to make insecure choices using the stdlib OpenSSL-based backend.
    """

    def __init__(
        self,
        tls_configuration: TLSClientConfiguration,
        insecure_configuration: InsecureConfiguration,
    ) -> None:
        """
        Create a new insecure context object from a given TLS configuration and
        insecure configuration."""
        warnings.warn(
            "Using an insecure Client Context is insecure and should not be used in production.",
            SecurityWarning,
        )

        self._insecure_config = insecure_configuration
        super().__init__(tls_configuration)

    def connect(self, address: tuple[str | None, int]) -> OpenSSLTLSSocket:
        """Create an insecure socket-like object that can be used to do TLS."""
        warnings.warn(
            "You are connecting using an insecure Client Context. \
             This is insecure and should not be used in production.",
            SecurityWarning,
        )

        ossl_context = _init_context_client(self._configuration)

        ossl_context = _apply_insecure_config(ossl_context, self._insecure_config)

        return OpenSSLTLSSocket._create(
            parent_context=self,
            server_side=False,
            ssl_context=ossl_context,
            address=address,
        )

    def create_buffer(self, server_hostname: str) -> OpenSSLTLSBuffer:
        """Creates an insecure TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""

        warnings.warn(
            "You are creating a TLSBuffer using an insecure Server Context. \
             This is insecure and should not be used in production.",
            SecurityWarning,
        )

        ossl_context = _init_context_client(self._configuration)

        ossl_context = _apply_insecure_config(ossl_context, self._insecure_config)

        return OpenSSLTLSBuffer._create(
            server_hostname=server_hostname,
            parent_context=self,
            server_side=False,
            ssl_context=ossl_context,
        )

    @property
    def insecure_configuration(self) -> InsecureConfiguration:
        """The insecure configuration options that will make this context insecure."""
        return self._insecure_config


class OpenSSLInsecureServerContext(OpenSSLServerContext):
    """
    Class allowing users to make insecure choices using the stdlib OpenSSL-based backend.
    """

    def __init__(
        self,
        tls_configuration: TLSServerConfiguration,
        insecure_configuration: InsecureConfiguration,
    ) -> None:
        """
        Create a new insecure context object from a given TLS configuration and
        insecure configuration."""
        warnings.warn(
            "Using an insecure Server Context is insecure and should not be used in production.",
            SecurityWarning,
        )

        self._insecure_config = insecure_configuration
        super().__init__(tls_configuration)

    def connect(self, address: tuple[str | None, int]) -> OpenSSLTLSSocket:
        """Create a socket-like object that can be used to do TLS."""
        warnings.warn(
            "You are connecting using an insecure Server Context. \
             This is insecure and should not be used in production.",
            SecurityWarning,
        )

        ossl_context = _init_context_server(self._configuration)

        ossl_context = _apply_insecure_config(ossl_context, self._insecure_config)

        return OpenSSLTLSSocket._create(
            parent_context=self,
            server_side=True,
            ssl_context=ossl_context,
            address=address,
        )

    def create_buffer(self) -> OpenSSLTLSBuffer:
        """Creates an insecure TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""
        warnings.warn(
            "You are creating a TLSBuffer using an insecure Server Context. \
             This is insecure and should not be used in production.",
            SecurityWarning,
        )

        ossl_context = _init_context_server(self._configuration)

        ossl_context = _apply_insecure_config(ossl_context, self._insecure_config)

        return OpenSSLTLSBuffer._create(
            server_hostname=None,
            parent_context=self,
            server_side=True,
            ssl_context=ossl_context,
        )

    @property
    def insecure_configuration(self) -> InsecureConfiguration:
        """The insecure configuration options that will make this context insecure."""
        return self._insecure_config


#: The stdlib ``InsecureBackend`` object.
STDLIB_INSECURE_BACKEND = InsecureBackend(
    client_context=OpenSSLClientContext,
    server_context=OpenSSLServerContext,
    validate_config=validate_config,
    insecure_client_context=OpenSSLInsecureClientContext,
    insecure_server_context=OpenSSLInsecureServerContext,
)
