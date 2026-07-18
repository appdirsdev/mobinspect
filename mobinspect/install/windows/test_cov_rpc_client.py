"""Real-execution regression tests for mobinspect.install.windows.rpc_client.

Exercises the pure input-validation logic in binskim()/binscope() with a
real RSA challenge/response handshake (no mocks) -- the only part of this
module reachable without an actual Windows host + BinSkim/BinScope
binaries installed. The subprocess-execution tail of both functions needs
those Windows tools and is intentionally out of scope here (ceiling-gap,
same convention as StaticAnalyzer/views/windows/test_cov_windows.py).
"""
import base64
import unittest

import rsa

from mobinspect.install.windows import rpc_client


class _Sig:
    """Minimal stand-in for the xmlrpc.client.Binary the real client sends.

    Only the `.data` attribute `_check_challenge` reads is needed.
    """

    def __init__(self, data):
        self.data = data


class RpcClientValidationTests(unittest.TestCase):
    """binskim()/binscope() must reject any `sample` that isn't a bare md5.

    `sample` is attacker-influenceable (it becomes part of a file path and
    a subprocess argv), so both functions are supposed to refuse anything
    that isn't exactly a 32-char lower-case hex md5.
    """

    @classmethod
    def setUpClass(cls):
        cls.pub_key, cls.priv_key = rsa.newkeys(1024)

    def setUp(self):
        rpc_client.pub_key = self.pub_key
        rpc_client.config = None

    def _signed(self):
        """Issue a fresh one-shot challenge/signature, like production."""
        rpc_client.challenge = 'X' * 256
        raw_sig = rsa.sign(
            rpc_client.challenge.encode('utf-8'), self.priv_key, 'SHA-512')
        return _Sig(base64.b64encode(raw_sig))

    def test_binskim_rejects_md5_embedded_in_traversal_string(self):
        # Before the fix, re.findall(...) only checked that a 32-hex-char
        # run occurred *somewhere* in `sample`, so a path-traversal payload
        # with a bare md5 stitched into it slipped past validation.
        malicious = 'a' * 32 + '/../../../etc/passwd'
        self.assertEqual(
            rpc_client.binskim(malicious, self._signed()), 'Wrong Input!')

    def test_binskim_accepts_bare_md5(self):
        # A real md5 hex (as produced by upload_file()) must still pass
        # validation and reach the (here-unconfigured) tool config -- the
        # TypeError proves it got past the check, not rejected by it.
        sample = 'a' * 32
        with self.assertRaises(TypeError):
            rpc_client.binskim(sample, self._signed())

    def test_binscope_rejects_md5_embedded_in_traversal_string(self):
        # binscope() previously had *no* validation of `sample` at all.
        malicious = 'b' * 32 + '/../../../windows/system32'
        self.assertEqual(
            rpc_client.binscope(malicious, self._signed()), 'Wrong Input!')

    def test_binscope_accepts_bare_md5(self):
        sample = 'b' * 32
        with self.assertRaises(TypeError):
            rpc_client.binscope(sample, self._signed())


if __name__ == '__main__':
    unittest.main()
