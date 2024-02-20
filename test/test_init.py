"""Initial testing module."""
import tlslib


def test_version() -> None:
    version = getattr(tlslib, "__version__", None)
    assert version is not None
    assert isinstance(version, str)
