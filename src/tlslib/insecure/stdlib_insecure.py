"""Shims the standard library OpenSSL module into the amended PEP 543 API."""

from __future__ import annotations

import ssl
import warnings

from ..stdlib import (
    OpenSSLCertificate,
    OpenSSLClientContext,
    OpenSSLPrivateKey,
    OpenSSLServerContext,
    OpenSSLTLSSocket,
    OpenSSLTrustStore,
    _init_context_client,
    _init_context_server,
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
        """Create a socket-like object that can be used to do TLS."""
        warnings.warn(
            "You are connecting using an insecure Client Context. \
             This is insecure and should not be used in production.",
            SecurityWarning,
        )

        ossl_context = _init_context_client(self._configuration)

        if self._insecure_config.disable_verification:
            ossl_context.check_hostname = False
            ossl_context.verify_mode = ssl.CERT_NONE

        return OpenSSLTLSSocket._create(
            parent_context=self,
            server_side=False,
            ssl_context=ossl_context,
            address=address,
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

        if self._insecure_config.disable_verification:
            ossl_context.check_hostname = False
            ossl_context.verify_mode = ssl.CERT_NONE

        return OpenSSLTLSSocket._create(
            parent_context=self,
            server_side=True,
            ssl_context=ossl_context,
            address=address,
        )

    @property
    def insecure_configuration(self) -> InsecureConfiguration:
        """The insecure configuration options that will make this context insecure."""
        return self._insecure_config


#: The stdlib ``InsecureBackend`` object.
STDLIB_INSECURE_BACKEND = InsecureBackend(
    certificate=OpenSSLCertificate,
    client_context=OpenSSLClientContext,
    private_key=OpenSSLPrivateKey,
    server_context=OpenSSLServerContext,
    trust_store=OpenSSLTrustStore,
    insecure_client_context=OpenSSLInsecureClientContext,
    insecure_server_context=OpenSSLInsecureServerContext,
)
