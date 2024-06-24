"""Insecure options for the abstract interface to TLS for Python."""

import warnings
from abc import abstractmethod
from collections.abc import Callable
from typing import Generic, Protocol, TypeVar

from ..tlslib import (
    Backend,
    ClientContext,
    ServerContext,
    TLSClientConfiguration,
    TLSServerConfiguration,
)


class SecurityWarning(Warning):
    """Warning regarding the insecurity caused by the use of this module"""


class InsecureConfiguration:
    """
    Class allowing users to define insecure configuration parameters for testing purposes.
    It should be noted that making use of any of the options in this class will lead to an
    insecure deployment of TLS.

    :param _disable_hostname_check bool:
        Disables hostname_check of the server certificate. This allows anyone positioned
        in the network to intercept connections between legitimate clients and servers without
        detection and is insecure. A better option would be to obtain the server's (self-signed)
        certificate and place it in a newly-created TrustStore object.

    :param disable_verification bool:
        Disables client verification of the server certificate. This allows anyone positioned
        in the network to intercept connections between legitimate clients and servers without
        detection and is insecure. A better option would be to obtain the server's (self-signed)
        certificate and place it in a newly-created TrustStore object.
    """

    __slots__ = (
        "_disable_verification",
        "_disable_hostname_check",
    )

    def __init__(
        self,
        disable_hostname_check: bool = False,
        disable_verification: bool = False,
    ) -> None:
        """Initializes the InsecureConfiguration."""
        warnings.warn(
            "Using InsecureConfiguration is insecure and should not be used in production.",
            SecurityWarning,
        )

        if not disable_hostname_check and disable_verification:
            raise ValueError("Cannot disable verification without disabling hostname check")

        self._disable_hostname_check = disable_hostname_check
        self._disable_verification = disable_verification

    @property
    def disable_hostname_check(self) -> bool:
        """Whether client verification of the server hostname should be disabled."""
        return self._disable_hostname_check

    @property
    def disable_verification(self) -> bool:
        """Whether client verification of the server certificate should be disabled."""
        return self._disable_verification


class InsecureClientContext(ClientContext, Protocol):
    """
    Class allowing users to make insecure choices for testing purposes.

    :param tls_configuration TLSClientConfiguration
        The underlying TLS configuration to be used to instantiate the insecure context.

    :param insecure_configuration InsecureConfiguration:
        The insecure configuration options that will make this context insecure.
    """

    @abstractmethod
    def __init__(
        self,
        tls_configuration: TLSClientConfiguration,
        insecure_configuration: InsecureConfiguration,
    ) -> None:
        """
        Create a new insecure context object from a given TLS configuration and
        insecure configuration."""

    @property
    @abstractmethod
    def insecure_configuration(self) -> InsecureConfiguration:
        """The insecure configuration options that will make this context insecure."""


class InsecureServerContext(ServerContext, Protocol):
    """
    Class allowing users to make insecure choices for testing purposes.

    :param tls_configuration TLSClientConfiguration | TLSServerConfiguration:
        The underlying TLS configuration to be used to instantiate the insecure context.

    :param insecure_configuration InsecureConfiguration:
        The insecure configuration options that will make this context insecure.
    """

    @abstractmethod
    def __init__(
        self,
        tls_configuration: TLSServerConfiguration,
        insecure_configuration: InsecureConfiguration,
    ) -> None:
        """
        Create a new insecure context object from a given TLS configuration and
        insecure configuration."""

    @property
    @abstractmethod
    def insecure_configuration(self) -> InsecureConfiguration:
        """The insecure configuration options that will make this context insecure."""


_ClientContext = TypeVar("_ClientContext", bound=ClientContext)
_ServerContext = TypeVar("_ServerContext", bound=ServerContext)
_InsecureClientContext = TypeVar("_InsecureClientContext", bound=InsecureClientContext)
_InsecureServerContext = TypeVar("_InsecureServerContext", bound=InsecureServerContext)


class InsecureBackend(Backend, Generic[_InsecureClientContext, _InsecureServerContext]):
    """
    An insecure version of a TLS API Backend that allows an implementation to make insecure
    choices for testing purposes.
    """

    __slots__ = (
        "_insecure_client_context",
        "_insecure_server_context",
    )

    def __init__(
        self,
        client_context: type[_ClientContext],
        server_context: type[_ServerContext],
        validate_config: Callable[[TLSClientConfiguration | TLSServerConfiguration], None],
        insecure_client_context: type[_InsecureClientContext],
        insecure_server_context: type[_InsecureServerContext],
    ) -> None:
        """Initializes all attributes of the backend."""

        warnings.warn(
            "Using an InsecureBackend is insecure. This should not be used in production.",
            SecurityWarning,
        )

        self._insecure_client_context = insecure_client_context
        self._insecure_server_context = insecure_server_context

        super().__init__(
            client_context=client_context,
            server_context=server_context,
            validate_config=validate_config,
        )

    @property
    def insecure_client_context(self) -> type[_InsecureClientContext]:
        """The concrete implementation of the PEP 543 Insecure Client Context object used
        by this TLS backend.
        """
        return self._insecure_client_context

    @property
    def insecure_server_context(self) -> type[_InsecureServerContext]:
        """The concrete implementation of the PEP 543 Insecure Server Context object used
        by this TLS backend.
        """
        return self._insecure_server_context
