"""
Tests for `tlslib/__init__.py`.
"""

from unittest import TestCase

import tlslib


class TestVersion(TestCase):
    def test_version(self) -> None:
        version = getattr(tlslib, "__version__", None)
        self.assertTrue(version is not None)
        self.assertIsInstance(version, str)
