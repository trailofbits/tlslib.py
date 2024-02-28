"""
Tests for `tlslib.stdlib`.
"""

from pathlib import Path
from unittest import TestCase

from tlslib import stdlib


class TestOpenSSLTrustStore(TestCase):
    def test_init(self):
        path = Path("/tmp/not-real")
        store = stdlib.OpenSSLTrustStore(path)
        self.assertEqual(store._trust_path, path)
