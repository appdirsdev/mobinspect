# -*- coding: utf_8 -*-
"""Coverage tests for mobinspect/StaticAnalyzer/views/common/llm/signals.py.

`enqueue_ai_enrichment` is a django-q `post_execute` receiver: it is the
ONLY bridge between the real scan pipeline and the (separate, best-effort)
AI enrichment feature. It must:

  * do nothing unless MOBINSPECT_AI_ENABLED is on,
  * do nothing unless the finished task is a *scan* task that succeeded,
  * do nothing unless it can extract a well-formed 32-char checksum,
  * otherwise fire `enrich_in_background(checksum)` on a background thread,
  * and NEVER let an exception escape into django-q's worker loop.

These tests call the receiver directly (as a plain function — the same
pattern used by ``test_cov_async_task.py`` for the sibling ``detect_timeout``
receiver) with a mocked `enrich_in_background`, so no real thread, network
call, or DB access ever happens. `enrich_in_background` itself is imported
*inside* the function body on every call (`from ...tasks import
enrich_in_background`), so patching the attribute on the `tasks` module is
sufficient to intercept it deterministically.
"""
from unittest import mock

import pytest

from django.test import override_settings

from mobinspect.StaticAnalyzer.views.common.llm import signals
from mobinspect.StaticAnalyzer.views.common.llm.signals import (
    _SCAN_TASK_FUNCS,
    _func_name,
    enqueue_ai_enrichment,
)

VALID_MD5 = 'a' * 32
VALID_SCAN_FUNC = 'apk_analysis_task'

# Patch target: the receiver does a fresh `from ...tasks import
# enrich_in_background` on every invocation, so patching the attribute on
# the tasks module (not on signals) is what actually takes effect.
PATCH_TARGET = 'mobinspect.StaticAnalyzer.views.common.llm.tasks.enrich_in_background'


def _task(func=VALID_SCAN_FUNC, success=True, args=(VALID_MD5,), **extra):
    """Build a django-q-shaped task dict, matching real OrmQ payloads."""
    t = {'func': func, 'success': success, 'args': args}
    t.update(extra)
    return t


# ─────────────────────────────────────────────────────── AI disabled (kill switch)
@override_settings(MOBINSPECT_AI_ENABLED=False)
def test_disabled_never_enqueues_even_for_perfect_task():
    """The master switch is checked FIRST — nothing downstream matters."""
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task())
    enrich.assert_not_called()


def test_missing_setting_defaults_to_disabled(settings):
    """If MOBINSPECT_AI_ENABLED is entirely absent, getattr(..., False) wins."""
    delattr(settings, 'MOBINSPECT_AI_ENABLED')
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task())
    enrich.assert_not_called()


# ─────────────────────────────────────────────────────── happy path
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_valid_scan_task_enqueues_enrichment():
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task())
    enrich.assert_called_once_with(VALID_MD5)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_every_registered_scan_task_func_triggers_enrichment():
    """Every function name in _SCAN_TASK_FUNCS must be recognized (no drift)."""
    for func_name in sorted(_SCAN_TASK_FUNCS):
        with mock.patch(PATCH_TARGET) as enrich:
            enqueue_ai_enrichment(sender=None, task=_task(func=func_name))
        enrich.assert_called_once_with(VALID_MD5)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_func_as_dotted_path_string_resolves_to_basename():
    """django-q sometimes serializes `func` as 'module.path.func_name'."""
    dotted = 'mobinspect.StaticAnalyzer.tasks.apk_analysis_task'
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(func=dotted))
    enrich.assert_called_once_with(VALID_MD5)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_func_as_real_callable_uses_dunder_name():
    def apk_analysis_task(checksum):  # pragma: no cover - never invoked
        return checksum
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(func=apk_analysis_task))
    enrich.assert_called_once_with(VALID_MD5)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_extra_args_beyond_checksum_are_ignored():
    """Only args[0] is read; extra positional args must not break extraction."""
    args = (VALID_MD5, 'ignored-second-arg', {'k': 'v'})
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(args=args))
    enrich.assert_called_once_with(VALID_MD5)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_args_as_list_is_accepted():
    """django-q may deliver args as a list rather than a tuple."""
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(args=[VALID_MD5]))
    enrich.assert_called_once_with(VALID_MD5)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_extra_unknown_task_keys_are_ignored():
    """Unrelated django-q task-dict keys must not break extraction."""
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(
            sender=None,
            task=_task(id='q-1', started='x', stopped='y', result=None),
        )
    enrich.assert_called_once_with(VALID_MD5)


# ─────────────────────────────────────────────────────── task.success guard
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_failed_task_is_ignored():
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(success=False))
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('bad_task', [
    None,
    'apk_analysis_task',
    ['apk_analysis_task'],
    123,
    object(),
])
def test_non_dict_task_is_ignored(bad_task):
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=bad_task)
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('success_value', [0, '', None, False, 0.0, []])
def test_falsy_success_values_are_ignored(success_value):
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(success=success_value))
    enrich.assert_not_called()


# ─────────────────────────────────────────────────────── func-name guard
@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('func_name', [
    'static_analyzer',           # a real, non-scan-completion task in MobInspect
    'unknown_task',
    '',
    'apk_analysis_task_evil',    # near-miss / typosquat of a real name
    'ADMIN_DROP_TABLE',          # adversarial: SQL-ish func name, still just a string
])
def test_non_scan_task_func_is_ignored(func_name):
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(func=func_name))
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_non_callable_non_string_func_is_ignored():
    """func is neither callable nor a str (e.g. an int or dict) -> ''.join guard."""
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(func=42))
    enrich.assert_not_called()
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(func=None))
    enrich.assert_not_called()
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(func={'not': 'callable'}))
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_lambda_func_uses_lambda_dunder_name_and_is_ignored():
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(func=lambda x: x))
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_func_missing_key_defaults_to_none_and_is_ignored():
    """task.get('func') with the key entirely absent -> None -> _func_name('')."""
    task = {'success': True, 'args': (VALID_MD5,)}
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=task)
    enrich.assert_not_called()


# ─────────────────────────────────────────────────────── args guard
@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('args', [(), None, [], False])
def test_missing_or_empty_args_is_ignored(args):
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(args=args))
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_args_key_entirely_absent_is_ignored():
    task = {'func': VALID_SCAN_FUNC, 'success': True}
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=task)
    enrich.assert_not_called()


# ─────────────────────────────────────────────────────── checksum shape guard
@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('bad_checksum', [
    'a' * 31,                      # one char short
    'a' * 33,                      # one char over
    '',                            # empty string
])
def test_checksum_wrong_length_is_ignored(bad_checksum):
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(args=(bad_checksum,)))
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
@pytest.mark.parametrize('bad_checksum', [
    12345678901234567890123456789012,  # int, not str (32 digits)
    None,
    ('a' * 32,),                       # nested tuple, not a str
    {'checksum': 'a' * 32},            # dict, not a str
    b'a' * 32,                         # bytes, not str
    3.14,
])
def test_non_string_checksum_is_ignored(bad_checksum):
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(args=(bad_checksum,)))
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_checksum_length_32_but_not_valid_hex_still_passes_len_guard():
    """signals.py only checks type+length (not hex-ness / is_md5).

    This documents the real, intentional boundary: content validation
    (is_md5) happens downstream in tasks.py, not here. A 32-char string
    that is NOT valid hex still reaches enrich_in_background.
    """
    weird = ('../../etc/passwd!!' + '#' * 14)  # 32 chars, path-traversal-ish
    assert len(weird) == 32
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(args=(weird,)))
    enrich.assert_called_once_with(weird)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_checksum_length_32_with_sql_injection_payload_still_passes_len_guard():
    """Adversarial: a 32-char SQLi-shaped string is only length-checked here.

    enrich_in_background/tasks.py is responsible for ORM-safe lookup
    (Django's ORM parameterizes filters), so this is not exploitable
    downstream, but signals.py itself performs no content sanitization.
    """
    payload = "1' OR '1'='1'--        "  # padded/truncated to exactly 32 chars
    payload = (payload + ' ' * 32)[:32]
    assert len(payload) == 32
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(args=(payload,)))
    enrich.assert_called_once_with(payload)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_uppercase_32char_checksum_is_accepted_by_len_only_guard():
    upper = 'A' * 32
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task(args=(upper,)))
    enrich.assert_called_once_with(upper)


# ─────────────────────────────────────────────────────── exception swallowing
@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_enrich_in_background_raising_is_swallowed():
    """The receiver must never propagate — a worker-crashing bug here would
    be far worse than silently losing one enrichment."""
    with mock.patch(PATCH_TARGET, side_effect=RuntimeError('boom')) as enrich:
        enqueue_ai_enrichment(sender=None, task=_task())  # must not raise
    enrich.assert_called_once_with(VALID_MD5)


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_import_failure_of_tasks_module_is_swallowed(monkeypatch):
    """If the lazy import itself fails (e.g. broken dependency), the
    exception is caught by the outer try/except and never propagates."""
    import builtins
    real_import = builtins.__import__

    def _boom_import(name, *args, **kwargs):
        if name == 'mobinspect.StaticAnalyzer.views.common.llm.tasks':
            raise ImportError('simulated broken dependency')
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', _boom_import)
    enqueue_ai_enrichment(sender=None, task=_task())  # must not raise


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_malformed_task_get_raising_is_swallowed():
    """Any unexpected exception while introspecting `task` is swallowed too
    (e.g. a task-like mapping whose .get() misbehaves)."""
    class HostileTask(dict):
        def get(self, key, default=None):
            if key == 'func':
                raise RuntimeError('hostile task object')
            return super().get(key, default)

    hostile = HostileTask(success=True, args=(VALID_MD5,))
    with mock.patch(PATCH_TARGET) as enrich:
        enqueue_ai_enrichment(sender=None, task=hostile)  # must not raise
    enrich.assert_not_called()


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_settings_access_raising_is_swallowed(monkeypatch):
    """If reading the settings flag itself explodes, the receiver still
    must not propagate the exception into django-q's worker loop."""
    class ExplodingSettings:
        def __getattr__(self, item):
            raise RuntimeError('settings backend exploded')

    monkeypatch.setattr(signals, 'settings', ExplodingSettings())
    enqueue_ai_enrichment(sender=None, task=_task())  # must not raise


# ─────────────────────────────────────────────────────── _func_name unit tests
def test_func_name_with_plain_string():
    assert _func_name('apk_analysis_task') == 'apk_analysis_task'


def test_func_name_with_dotted_string():
    assert _func_name('pkg.mod.apk_analysis_task') == 'apk_analysis_task'


def test_func_name_with_callable():
    def src_analysis_task():  # pragma: no cover - never invoked
        pass
    assert _func_name(src_analysis_task) == 'src_analysis_task'


def test_func_name_with_callable_missing_dunder_name():
    class Weird:
        def __call__(self):  # pragma: no cover - never invoked
            pass
    obj = Weird()
    assert callable(obj)
    assert not hasattr(obj, '__name__')
    assert _func_name(obj) == ''


def test_func_name_with_none():
    assert _func_name(None) == ''


def test_func_name_with_non_callable_non_string():
    assert _func_name(12345) == ''
    assert _func_name({'a': 1}) == ''
    assert _func_name([1, 2, 3]) == ''


def test_func_name_with_empty_string():
    assert _func_name('') == ''


def test_func_name_dotted_string_with_trailing_dot():
    # rsplit('.', 1)[-1] on a trailing dot yields '' (documents real edge case).
    assert _func_name('pkg.mod.') == ''


# ─────────────────────────────────────────────────────── receiver registration
def test_receiver_is_registered_on_post_execute_signal():
    """The @receiver(post_execute) decorator must actually wire the
    function into django_q's signal so scans trigger it at runtime.

    Django's internal `Signal.receivers` entries are
    ``(lookup_key, receiver_ref, sender, is_async)`` tuples where
    `receiver_ref` is typically a weakref; unpack defensively by
    position rather than assuming an exact tuple length.
    """
    from django_q.signals import post_execute
    resolved = []
    for entry in post_execute.receivers:
        ref = entry[1]
        func = ref() if callable(ref) else ref
        if func is not None:
            resolved.append(func)
    assert enqueue_ai_enrichment in resolved


@override_settings(MOBINSPECT_AI_ENABLED=True)
def test_scan_task_funcs_set_contains_all_expected_platform_tasks():
    """Guard against accidental removal of a platform from the enrichment
    trigger list (would silently stop AI enrichment for that platform)."""
    expected = {
        'apk_analysis_task', 'src_analysis_task', 'ipa_analysis_task',
        'ios_analysis_task', 'so_analysis_task', 'jar_analysis_task',
        'aar_analysis_task', 'dylib_analysis_task', 'appx_analysis_task',
        'windows_analysis_task',
    }
    assert _SCAN_TASK_FUNCS == expected
