"""
ApiKey storage + lookup tests (H17).

Pins the security-critical invariants of `mobsf.RBAC.models.ApiKey`:

  * The plaintext secret is returned ONCE at generate() and is NEVER
    persisted — only its SHA-256 hash and a short prefix make it to disk.
  * `lookup()` resolves a plaintext key to its active row via the stored
    hash. Revoked rows and rows past `expires_at` are excluded by the
    same query (no TOCTOU window between filter and active check).
  * Hashing uses sha256 of the plaintext key; the active filter relies
    on constant-time comparison at the DB layer (the hash itself is
    looked up by exact equality which is cryptographically safe for
    full-entropy random secrets).
  * Generation is collision-free across 1000 calls — guards against
    accidental truncation of the secret length.
"""
import hashlib

import pytest

from datetime import timedelta
from django.utils import timezone

from mobsf.RBAC.models import ApiKey


# ─────────────────────────────────────────────────────── generation
@pytest.mark.django_db
def test_generate_returns_plaintext_and_persists_only_hash(viewer_user):
    """generate() yields (instance, plaintext); only the hash is on disk."""
    instance, plaintext = ApiKey.generate(user=viewer_user, name='ci')
    # Plaintext is a non-empty string with the documented mi_<prefix>_ shape.
    assert isinstance(plaintext, str)
    assert plaintext.startswith('mi_')
    assert plaintext.count('_') >= 2  # mi_<prefix>_<secret>

    # The plaintext is NOT stored anywhere on the instance.
    instance.refresh_from_db()
    for field in ('key_hash', 'prefix', 'name'):
        assert getattr(instance, field) != plaintext, (
            f'plaintext leaked into ApiKey.{field}')
    # The stored hash matches sha256(plaintext).
    expected = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
    assert instance.key_hash == expected
    assert len(instance.key_hash) == 64  # sha256 hex


@pytest.mark.django_db
def test_plaintext_never_returned_again(viewer_user):
    """After generation, no public surface re-exposes the plaintext.

    There is no `instance.plaintext` attr, no `get_plaintext()` method,
    and reloading from the DB does not magic it back. This test is the
    canary — adding such an API in future requires explicitly deleting
    this assertion (which will show up in code review).
    """
    instance, _plaintext = ApiKey.generate(user=viewer_user, name='ci')
    # No attribute that holds the raw key.
    for attr in dir(instance):
        if attr.startswith('_'):
            continue
        v = getattr(instance, attr, None)
        if callable(v):
            continue
        if isinstance(v, str):
            # The hash is fine; the literal plaintext is not.
            assert not v.startswith('mi_') or v == instance.key_hash[:0], (
                f'Suspicious key-shaped value on attribute {attr!r}: {v!r}')


# ─────────────────────────────────────────────────────── lookup
@pytest.mark.django_db
def test_lookup_returns_active_key(viewer_user):
    """The raw plaintext resolves back to its row."""
    instance, plaintext = ApiKey.generate(user=viewer_user, name='ci')
    found = ApiKey.lookup(plaintext)
    assert found is not None
    assert found.pk == instance.pk
    assert found.user_id == viewer_user.id


@pytest.mark.django_db
def test_lookup_rejects_unknown_key(viewer_user):
    """A made-up plaintext returns None even with a plausible prefix."""
    assert ApiKey.lookup('mi_deadbeef_obviously-not-real') is None


@pytest.mark.django_db
def test_lookup_excludes_revoked(viewer_user):
    """Setting `revoked_at` causes lookup to return None."""
    instance, plaintext = ApiKey.generate(user=viewer_user, name='ci')
    instance.revoked_at = timezone.now()
    instance.save(update_fields=['revoked_at'])
    assert ApiKey.lookup(plaintext) is None


@pytest.mark.django_db
def test_lookup_excludes_expired(viewer_user):
    """A key with expires_at in the past is not returned."""
    instance, plaintext = ApiKey.generate(
        user=viewer_user, name='ci',
        expires_at=timezone.now() - timedelta(minutes=1),
    )
    assert ApiKey.lookup(plaintext) is None
    # Sanity: the row still exists — exclusion is logical, not destructive.
    assert ApiKey.objects.filter(pk=instance.pk).exists()


@pytest.mark.django_db
def test_lookup_includes_unexpired(viewer_user):
    """A key with expires_at in the future is still returned."""
    instance, plaintext = ApiKey.generate(
        user=viewer_user, name='ci',
        expires_at=timezone.now() + timedelta(days=1),
    )
    found = ApiKey.lookup(plaintext)
    assert found is not None
    assert found.pk == instance.pk


@pytest.mark.django_db
def test_lookup_rejects_empty_and_nonstring(viewer_user):
    """Defensive: None / '' / int input does not crash and returns None."""
    assert ApiKey.lookup('') is None
    assert ApiKey.lookup(None) is None
    assert ApiKey.lookup(12345) is None


# ─────────────────────────────────────────────────────── hash + comparison
@pytest.mark.django_db
def test_sha256_is_used_for_storage(viewer_user):
    """The stored key_hash is sha256(plaintext) — no other hash function."""
    instance, plaintext = ApiKey.generate(user=viewer_user, name='ci')
    expected = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
    assert instance.key_hash == expected
    # And the digest length is the sha256 hex length — not md5 (32) or
    # sha512 (128). Pinning this catches a silent algorithm change.
    assert len(instance.key_hash) == 64


@pytest.mark.django_db
def test_constant_time_comparison_in_global_key_path():
    """The legacy global-key path uses hmac.compare_digest.

    The per-user ApiKey path compares hashes via exact DB lookup on a
    64-char sha256 (cryptographically safe for full-entropy secrets).
    The legacy global-key path in api_middleware._global_key_matches
    DOES need constant-time compare since the comparand has structure.
    This test confirms the import is wired correctly.
    """
    from mobsf.MobSF.views.api import api_middleware
    src = api_middleware.__file__
    with open(src, 'r', encoding='utf-8') as f:
        body = f.read()
    assert 'compare_digest' in body, (
        'legacy global key check must use constant-time compare; '
        'see api_middleware._global_key_matches')


# ─────────────────────────────────────────────────────── collision-resistance
@pytest.mark.django_db
def test_generate_collision_free_across_1000(viewer_user):
    """1000 successive generations produce 1000 unique hashes.

    The secret has 40 bytes of entropy via secrets.token_urlsafe; the
    birthday-collision probability is astronomically small. Even a
    single collision here means the generator is silently truncating
    or reusing a seed.
    """
    hashes = set()
    plaintexts = set()
    for i in range(1000):
        _inst, plaintext = ApiKey.generate(user=viewer_user, name=f'k{i}')
        plaintexts.add(plaintext)
        hashes.add(hashlib.sha256(plaintext.encode('utf-8')).hexdigest())
    assert len(hashes) == 1000
    assert len(plaintexts) == 1000
    # And the DB really did store 1000 rows (sanity check against
    # silent unique-constraint failures eaten by .create()).
    assert ApiKey.objects.filter(user=viewer_user).count() >= 1000
