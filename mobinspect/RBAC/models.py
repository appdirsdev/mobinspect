"""
MobInspect — RBAC models.

Design rationale: docs/03-rbac-design.md and docs/adr/0001-django-groups-as-rbac-foundation.md.

The thin layer here adds:
  - Permission catalog (seeded; admins cannot freely create permissions)
  - Role wraps a Django Group with presentation metadata
  - RoleAssignment carries grantor / granted_at / expires_at
  - AuditEvent for compliance (tamper-evident hash chain — see H9)
  - ApiKey for per-user, revocable API access
"""
import json
import secrets
import hashlib

from django.conf import settings
from django.db import models
from django.utils import timezone


# ─────────────────────────────────────────────────────── catalog
class Permission(models.Model):
    """A single granular permission. Seeded via migrations.

    Codenames are dotted: 'category.action' or 'category.action.modifier'.
    """
    SCOPE_ACTION = 'action'
    SCOPE_RESOURCE = 'resource'
    SCOPE_CHOICES = (
        (SCOPE_ACTION, 'Action'),
        (SCOPE_RESOURCE, 'Resource'),
    )

    codename = models.SlugField(max_length=100, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=50, db_index=True)
    scope = models.CharField(
        max_length=20, choices=SCOPE_CHOICES, default=SCOPE_ACTION,
    )
    is_dangerous = models.BooleanField(default=False)

    class Meta:
        ordering = ['category', 'codename']

    def __str__(self):
        return self.codename


# ─────────────────────────────────────────────────────── role
class Role(models.Model):
    """A named bundle of permissions. Wraps a Django auth Group."""

    DEFAULT_COLOR = '#64748B'  # slate-500
    DEFAULT_ICON = 'shield'

    group = models.OneToOneField(
        'auth.Group',
        on_delete=models.CASCADE,
        related_name='mi_role',
    )
    name = models.CharField(max_length=80, unique=True)
    description = models.TextField(blank=True)
    color = models.CharField(max_length=7, default=DEFAULT_COLOR)
    icon = models.CharField(max_length=40, default=DEFAULT_ICON)
    is_system = models.BooleanField(
        default=False,
        help_text=(
            'System roles cannot be deleted or renamed. '
            'Their permission sets are still editable.'
        ),
    )
    permissions = models.ManyToManyField(
        Permission, related_name='roles', blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_system', 'name']

    def __str__(self):
        return self.name

    def codenames(self):
        """frozenset of permission codenames belonging to this role."""
        return frozenset(self.permissions.values_list('codename', flat=True))


# ─────────────────────────────────────────────────────── assignment
class RoleAssignment(models.Model):
    """Grant of a single role to a single user."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='role_assignments',
    )
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name='assignments',
    )
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='+',
    )
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [('user', 'role')]
        ordering = ['-granted_at']

    def __str__(self):
        return f'{self.user} → {self.role}'

    @property
    def is_active(self):
        if self.expires_at is None:
            return True
        return self.expires_at > timezone.now()


# ─────────────────────────────────────────────────────── audit
class AuditEvent(models.Model):
    """Single audit record. Append-only; never updated or deleted in code.

    Tamper-evident hash chain (H9):

      Each row carries a SHA-256 ``current_hash`` computed over the previous
      row's ``current_hash`` plus the immutable payload columns of THIS row
      (actor_id, action, target_type, target_id, metadata, occurred_at).
      The ``prev_hash`` column stores the predecessor's hash so the chain
      can be walked in either direction without re-querying.

      A SQLite BEFORE UPDATE / BEFORE DELETE trigger (see migration
      ``0007_auditevent_immutable_trigger``) blocks in-database mutation of
      the chain columns. An attacker that bypasses the trigger (or rewrites
      sqlite file in place) will still produce a chain mismatch detected by
      the ``audit_verify`` management command.
    """

    HASH_LEN = 64  # sha256 hex digest length

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, null=True, blank=True,
        related_name='+',
    )
    action = models.CharField(max_length=80, db_index=True)
    target_type = models.CharField(max_length=50, blank=True)
    target_id = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=400, blank=True)
    # NOTE: default=timezone.now rather than auto_now_add=True. The hash
    # chain folds occurred_at into current_hash, so save() needs to know
    # the timestamp BEFORE it lets the engine pick one. auto_now_add
    # would overwrite the value in pre_save (Django sets it after our
    # override has already computed the hash), producing a stored hash
    # that no longer matches the stored timestamp.
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)
    prev_hash = models.CharField(max_length=HASH_LEN, blank=True, default='')
    current_hash = models.CharField(
        max_length=HASH_LEN, blank=True, default='',
    )

    class Meta:
        ordering = ['-occurred_at']

    def __str__(self):
        actor = self.actor.username if self.actor_id else '<system>'
        return f'[{self.occurred_at:%Y-%m-%d %H:%M:%S}] {actor} {self.action}'

    # ───────── chain helpers
    @staticmethod
    def _compute_hash(prev_hash, actor_id, action, target_type,
                      target_id, metadata, occurred_at):
        """SHA-256 over the canonical payload string.

        Kept as a pure function so the management command can recompute
        hashes for verification without instantiating a model.
        """
        payload = ''.join((
            prev_hash or '',
            '' if actor_id is None else str(actor_id),
            action or '',
            target_type or '',
            target_id or '',
            json.dumps(metadata or {}, sort_keys=True, default=str),
            occurred_at.isoformat() if occurred_at else '',
        ))
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def save(self, *args, **kwargs):
        """Compute and seal the hash chain on INSERT.

        On UPDATE we deliberately do NOT recompute — the row is append-only
        and the database trigger will reject the mutation anyway. This lets
        non-chain columns (none currently exist, but future read-only flags
        like ``forwarded_at`` could) be saved without invalidating the
        chain.
        """
        if self.pk is None:
            # ``occurred_at`` is folded into the hash, so it must be
            # frozen BEFORE we compute current_hash. The field uses
            # ``default=timezone.now`` (not auto_now_add) so the default
            # has already fired by the time save() is called; we only
            # need to materialize it if a caller passed None explicitly.
            if self.occurred_at is None:
                self.occurred_at = timezone.now()
            prev = (
                type(self).objects
                .order_by('-id')
                .only('current_hash')
                .first()
            )
            prev_hash = prev.current_hash if prev else ''
            self.prev_hash = prev_hash
            self.current_hash = self._compute_hash(
                prev_hash,
                self.actor_id,
                self.action,
                self.target_type,
                self.target_id,
                self.metadata,
                self.occurred_at,
            )
        super().save(*args, **kwargs)

    @classmethod
    def _raw_purge_for_test(cls, where_sql='', params=()):
        """Bypass the append-only trigger to delete rows in tests.

        The DB-level append-only trigger (migration 0007) refuses ordinary
        ``DELETE`` statements, which would otherwise make ``TestCase``
        fixtures unable to isolate themselves from migration-seeded rows
        or from sibling tests. Tests opt in by calling this helper, which
        drops the trigger, runs the delete, and reinstalls the trigger so
        any assertion later in the test still proves the trigger is live.

        DO NOT call this from production code paths. It is intentionally
        named with a leading underscore and a ``_for_test`` suffix to make
        misuse loud in review.
        """
        from django.db import connection
        vendor = connection.vendor
        table = cls._meta.db_table
        clause = f' WHERE {where_sql}' if where_sql else ''
        with connection.cursor() as cur:
            if vendor == 'sqlite':
                cur.execute('DROP TRIGGER IF EXISTS no_audit_delete')
                cur.execute(f'DELETE FROM {table}{clause}', params)
                cur.execute(
                    'CREATE TRIGGER IF NOT EXISTS no_audit_delete '
                    f'BEFORE DELETE ON {table} '
                    "BEGIN SELECT RAISE(ABORT, "
                    "'audit log is append-only'); END;",
                )
            elif vendor == 'postgresql':
                # Django declares FK constraints DEFERRABLE INITIALLY
                # DEFERRED on Postgres, so audit rows inserted earlier in
                # this test's transaction leave deferred trigger events
                # queued. Postgres refuses ``ALTER TABLE ... DISABLE
                # TRIGGER`` while any trigger events are pending, so flush
                # them first.
                cur.execute('SET CONSTRAINTS ALL IMMEDIATE')
                cur.execute(
                    f'ALTER TABLE {table} DISABLE TRIGGER no_audit_delete',
                )
                cur.execute(f'DELETE FROM {table}{clause}', params)
                cur.execute(
                    f'ALTER TABLE {table} ENABLE TRIGGER no_audit_delete',
                )
            else:
                cur.execute(f'DELETE FROM {table}{clause}', params)


# ─────────────────────────────────────────────────────── api keys
class ApiKey(models.Model):
    """Per-user revocable API key.

    The plaintext key is shown to the user ONCE at creation time and never
    stored. We persist only a SHA-256 hash + a short prefix for UI display.
    """

    PREFIX_LEN = 8        # shown in UI like "mi_abc12345…"
    SECRET_LEN = 40       # bytes of randomness in the secret part

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='api_keys',
    )
    name = models.CharField(max_length=80)
    prefix = models.CharField(max_length=12, db_index=True)
    key_hash = models.CharField(max_length=64, unique=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user.username}:{self.name}'

    @property
    def is_active(self):
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= timezone.now():
            return False
        return True

    @classmethod
    def generate(cls, user, name, expires_at=None, granted_by=None):
        """Create a new key. Returns (instance, plaintext_key)."""
        prefix = secrets.token_hex(4)  # 8 chars
        secret = secrets.token_urlsafe(cls.SECRET_LEN)
        plaintext = f'mi_{prefix}_{secret}'
        key_hash = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        instance = cls.objects.create(
            user=user,
            name=name,
            prefix=prefix,
            key_hash=key_hash,
            expires_at=expires_at,
        )
        return instance, plaintext

    @classmethod
    def lookup(cls, plaintext):
        """Resolve a plaintext key to an active ApiKey instance, or None.

        Uses a single query with the active filter inline so the active
        check is atomic with the lookup (avoids a TOCTOU race against a
        concurrent revoke).
        """
        if not plaintext or not isinstance(plaintext, str):
            return None
        digest = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        now = timezone.now()
        return (
            cls.objects
            .select_related('user')
            .filter(key_hash=digest, revoked_at__isnull=True)
            .filter(models.Q(expires_at__isnull=True)
                    | models.Q(expires_at__gt=now))
            .first()
        )

    def touch(self):
        """Mark as recently used. Cheap fire-and-forget update."""
        type(self).objects.filter(pk=self.pk).update(
            last_used_at=timezone.now(),
        )


# ─────────────────────────────────────────────────────── adb connections
class AdbConnection(models.Model):
    """A user-configured remote ADB device target for dynamic analysis.

    Lets an admin wire a network-adb device (remote emulator / physical
    device) through the dashboard instead of the ``MOBINSPECT_ANALYZER_IDENTIFIER``
    env var. ``host_port`` is the value passed to ``adb connect`` and is
    validated against a strict ``host:port`` / ``[ipv6]:port`` regex BEFORE
    it is ever stored or handed to a subprocess — it is a command-execution
    surface, treat it as security-critical.

    At most one row per platform may be ``is_active=True``; use
    :meth:`set_active` to flip it so the "single active" invariant is
    enforced atomically.
    """

    PLATFORM_ANDROID = 'android'
    PLATFORM_IOS = 'ios'
    PLATFORM_CHOICES = (
        (PLATFORM_ANDROID, 'Android'),
        (PLATFORM_IOS, 'iOS'),
    )

    STATUS_UNKNOWN = 'unknown'
    STATUS_CONNECTED = 'connected'
    STATUS_FAILED = 'failed'
    STATUS_TIMEOUT = 'timeout'
    STATUS_CHOICES = (
        (STATUS_UNKNOWN, 'Unknown'),
        (STATUS_CONNECTED, 'Connected'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_TIMEOUT, 'Timeout'),
    )

    label = models.CharField(max_length=80)
    host_port = models.CharField(
        max_length=255, unique=True,
        help_text="Stored 'host:port' or '[ipv6]:port' for adb connect.",
    )
    platform = models.CharField(
        max_length=10, choices=PLATFORM_CHOICES, default=PLATFORM_ANDROID,
    )
    is_active = models.BooleanField(
        default=False,
        help_text='Only one connection per platform may be active.',
    )
    last_status = models.CharField(
        max_length=50, choices=STATUS_CHOICES, default=STATUS_UNKNOWN,
    )
    last_status_message = models.TextField(blank=True)
    last_status_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='adb_connections',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['platform', 'label']

    def __str__(self):
        flag = ' (active)' if self.is_active else ''
        return f'{self.label} [{self.host_port}]{flag}'

    def set_active(self):
        """Make this the sole active connection for its platform.

        Atomically clears ``is_active`` on every sibling of the same
        platform and sets it on this row, so the "one active per platform"
        invariant always holds even under concurrent callers.
        """
        from django.db import transaction
        with transaction.atomic():
            (type(self).objects
             .select_for_update()
             .filter(platform=self.platform, is_active=True)
             .exclude(pk=self.pk)
             .update(is_active=False))
            if not self.is_active:
                self.is_active = True
                self.save(update_fields=['is_active', 'updated_at'])


# ─────────────────────────────────────────────────────── AI model integrations
class ModelIntegration(models.Model):
    """A configured local LLM endpoint (e.g. Ollama) for AI enrichment.

    Lets an admin wire the AI model host through the Integrations dashboard
    instead of the ``MOBINSPECT_AI_BASE_URL`` env var. At most one row may be
    ``is_active=True``; the active row's endpoint + model drive AI enrichment
    (GraniteClient prefers it over the settings fallback). ``base_url`` is a
    network egress target — it is validated (scheme/host/port, enclave-only)
    before any request, treat it as security-critical.
    """

    STATUS_UNKNOWN = 'unknown'
    STATUS_CONNECTED = 'connected'
    STATUS_FAILED = 'failed'
    STATUS_TIMEOUT = 'timeout'
    STATUS_CHOICES = (
        (STATUS_UNKNOWN, 'Unknown'),
        (STATUS_CONNECTED, 'Connected'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_TIMEOUT, 'Timeout'),
    )

    # Each role has at most one configured endpoint (enforced in the view via
    # update_or_create on role). generate = report/summary model,
    # classify = short classification model.
    ROLE_GENERATE = 'generate'
    ROLE_CLASSIFY = 'classify'
    ROLE_CHOICES = (
        (ROLE_GENERATE, 'Generation'),
        (ROLE_CLASSIFY, 'Classification'),
    )

    label = models.CharField(max_length=80, blank=True, default='')
    role = models.CharField(
        max_length=20, choices=ROLE_CHOICES, default=ROLE_GENERATE,
    )
    base_url = models.CharField(
        max_length=255,
        help_text='Model endpoint, e.g. http://127.0.0.1:11434',
    )
    model_name = models.CharField(
        max_length=128, help_text='Model tag, e.g. granite4:3b',
    )
    is_active = models.BooleanField(
        default=True, help_text='Whether this role endpoint is in use.',
    )
    last_status = models.CharField(
        max_length=50, choices=STATUS_CHOICES, default=STATUS_UNKNOWN,
    )
    last_status_message = models.TextField(blank=True)
    last_status_at = models.DateTimeField(null=True, blank=True)
    detected_models = models.TextField(
        blank=True, default='',
        help_text='Comma-separated models detected at the endpoint.',
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='model_integrations',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['label']

    def __str__(self):
        flag = ' (active)' if self.is_active else ''
        return f'{self.label} [{self.model_name} @ {self.base_url}]{flag}'

    def set_active(self):
        """Make this the sole active model integration (atomic)."""
        from django.db import transaction
        with transaction.atomic():
            (type(self).objects
             .select_for_update()
             .filter(is_active=True)
             .exclude(pk=self.pk)
             .update(is_active=False))
            if not self.is_active:
                self.is_active = True
                self.save(update_fields=['is_active', 'updated_at'])
