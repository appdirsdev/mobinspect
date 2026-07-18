# -*- coding: utf_8 -*-
"""Real-execution regression test for Environment.install_mobinspect_ca().

DynamicAnalyzer/views/android/* is device-locked (omitted from the owned-code
coverage requirement -- see .coveragerc) and cannot be driven end-to-end on
this host: there is no Android device/emulator to push the root CA to.

The bug fixed here, however, lives entirely in *pure* Python string/crypto
logic that runs before any adb call is made: the on-device cacert filename
hash computed from a real X.509 certificate's subject. That part IS
reachable and verifiable without a device, so it is real-execution tested:

  * A real self-signed X.509 certificate (generated once with pyOpenSSL,
    embedded below as a fixed PEM fixture) is parsed with the exact same
    ``OpenSSL.crypto`` + ``hashlib.md5`` calls the production code uses.
  * ``Environment.adb_command`` -- the one piece that genuinely requires a
    device -- is wrapped with a thin recording spy that still calls straight
    through to the real implementation (so the real, expected-to-fail
    subprocess call still happens and is still swallowed internally exactly
    like it is in production/other tests in this suite); we only observe the
    arguments it was called with, we never fake its return value.

Bug: ``ca_file_hash = hex(ret).lstrip('0x')`` in environment.py used to (a)
not zero-pad ``hex(ret)`` to 8 digits and (b) strip *any* leading '0'/'x'
character (not just the literal "0x" prefix) via ``str.lstrip``, silently
truncating the Android c_rehash-style subject hash whenever its leading
hex digit(s) are zero. The fixture certificate below reproduces this
concretely: its subject hash is ``0x4f7f1e`` -> buggy output ``'4f7f1e'``
(6 chars) vs. the correct, zero-padded ``'004f7f1e'`` (8 chars) that Android
actually looks up under ``/system/etc/security/cacerts/<hash>.0``. A
truncated filename is never found by the on-device trust store, so the
pushed MobInspect root CA is silently never trusted -- HTTPS interception
for dynamic analysis breaks with no visible error.
"""
from hashlib import md5

from OpenSSL import crypto

from mobinspect.DynamicAnalyzer.views.android import environment as env_mod
from mobinspect.DynamicAnalyzer.views.android.environment import Environment

# A real, fixed self-signed X.509 certificate (subject CN
# "mobinspect-test-10") whose MD5 subject-hash is 0x4f7f1e -- i.e. its
# hex digest naturally has fewer than 8 digits AND a leading zero nibble,
# the exact condition the buggy `hex(ret).lstrip('0x')` mishandles.
# Generated once with pyOpenSSL; embedded as a fixture for a deterministic,
# no-network, no-device regression test.
_FIXTURE_CERT_PEM = b"""-----BEGIN CERTIFICATE-----
MIIBIzCBzgIBCzANBgkqhkiG9w0BAQQFADAdMRswGQYDVQQDDBJtb2JpbnNwZWN0
LXRlc3QtMTAwHhcNMjYwNzE4MTMwNjE1WhcNMjYwNzE4MTQwNjE1WjAdMRswGQYD
VQQDDBJtb2JpbnNwZWN0LXRlc3QtMTAwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA
v8RiClqa6ESwkJ/5vw4JHT1Srx/HKcOLCScX1CIKlKMNLR9SROx0Fws+0UikmaE3
yCmGT/QpBb98cFyDkyDU/wIDAQABMA0GCSqGSIb3DQEBBAUAA0EAgxqm7lbPEzgq
oHxWxOUF4ykGtMsGkClL8VCvRZL10eOybeSKMEqaT0+Hb/E5SWIP+/3fEBYG3qGM
TkkuITmmIA==
-----END CERTIFICATE-----
"""


def _expected_ca_hash():
    """Recompute the correct (zero-padded, 8 lowercase hex digit) subject
    hash independently, using the same fields/algorithm as production."""
    ca_obj = crypto.load_certificate(crypto.FILETYPE_PEM, _FIXTURE_CERT_PEM)
    digest = md5(ca_obj.get_subject().der()).digest()
    ret = (digest[0] | (digest[1] << 8)
           | (digest[2] << 16) | (digest[3] << 24))
    return format(ret, '08x')


def test_fixture_cert_reproduces_the_truncation_bug():
    """Sanity check on the fixture itself (documents *why* it was chosen).

    Guards against the fixture silently stopping to exercise the bug (e.g.
    if pyOpenSSL's DER encoding ever changed) -- if this assertion starts
    failing, the fixture needs replacing with a new certificate that still
    triggers the divergence.
    """
    ca_obj = crypto.load_certificate(crypto.FILETYPE_PEM, _FIXTURE_CERT_PEM)
    digest = md5(ca_obj.get_subject().der()).digest()
    ret = (digest[0] | (digest[1] << 8)
           | (digest[2] << 16) | (digest[3] << 24))
    buggy = hex(ret).lstrip('0x')
    correct = format(ret, '08x')
    assert ret == 0x4f7f1e
    assert buggy == '4f7f1e'
    assert correct == '004f7f1e'
    assert buggy != correct


def test_install_mobinspect_ca_pushes_correctly_padded_hash(tmp_path, monkeypatch):
    """Regression test for the cacert-hash truncation bug.

    Before the fix: the ``push`` destination computed by
    ``install_mobinspect_ca('install')`` was ``.../4f7f1e.0`` (6 hex
    digits) for this fixture certificate. After the fix it must be the
    correct, Android-recognizable ``.../004f7f1e.0`` (8 hex digits).
    """
    ca_path = tmp_path / 'mobinspect-test-ca.pem'
    ca_path.write_bytes(_FIXTURE_CERT_PEM)

    # get_ca_file() is a pure filesystem-path lookup (mitmproxy's CA
    # location) -- not a device call. Point it at our real fixture cert
    # instead of the developer's real mitmproxy CA so the test is
    # deterministic and does not depend on / mutate host state.
    monkeypatch.setattr(env_mod, 'get_ca_file', lambda: str(ca_path))

    recorded_calls = []
    real_adb_command = Environment.adb_command

    def recording_adb_command(self, cmd_list, shell=False, silent=False):
        # Record exactly what production code asked adb to run, then call
        # straight through to the REAL implementation: this still makes a
        # genuine (and, with no device attached, genuinely failing)
        # subprocess call that is swallowed internally exactly as it is
        # for every other caller -- nothing about adb_command's own
        # behavior is faked.
        recorded_calls.append(list(cmd_list))
        return real_adb_command(self, cmd_list, shell, silent)

    monkeypatch.setattr(Environment, 'adb_command', recording_adb_command)

    environment = Environment(identifier='127.0.0.1:5555')
    environment.install_mobinspect_ca('install')

    push_calls = [c for c in recorded_calls if c and c[0] == 'push']
    assert len(push_calls) == 1, recorded_calls
    pushed_ca_file = push_calls[0][2]

    expected_hash = _expected_ca_hash()
    assert expected_hash == '004f7f1e'
    assert pushed_ca_file == (
        f'/system/etc/security/cacerts/{expected_hash}.0')
    # The crux of the bug: must be a full 8 hex digits, not truncated.
    basename = pushed_ca_file.rsplit('/', 1)[1]
    assert basename == '004f7f1e.0'
    assert len(basename) == len('xxxxxxxx.0')
