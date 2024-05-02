"""Insecure options for the abstract interface to TLS for Python."""

import warnings
from abc import abstractmethod
from typing import Generic, Protocol, TypeVar

from ..tlslib import (
    Backend,
    Certificate,
    ClientContext,
    PrivateKey,
    ServerContext,
    TLSClientConfiguration,
    TLSServerConfiguration,
    TrustStore,
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


_TrustStore = TypeVar("_TrustStore", bound=TrustStore)
_Certificate = TypeVar("_Certificate", bound=Certificate)
_PrivateKey = TypeVar("_PrivateKey", bound=PrivateKey)
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

    @property
    def insecure_configuration(
        self,
    ) -> type[InsecureConfiguration]:
        """
        Returns a type object for `InsecureConfiguration`.

        This is identical to using `InsecureConfiguration` directly, and
        is just here for consistency with the Generic-based TLSClientConfiguration
        and TLSServerConfiguration in the regular Backend.
        """
        return InsecureConfiguration

    def __init__(
        self,
        certificate: type[_Certificate],
        client_context: type[_ClientContext],
        private_key: type[_PrivateKey],
        server_context: type[_ServerContext],
        trust_store: type[_TrustStore],
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
            certificate=certificate,
            client_context=client_context,
            private_key=private_key,
            server_context=server_context,
            trust_store=trust_store,
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
