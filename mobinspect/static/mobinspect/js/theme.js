/**
 * MobInspect — theme manager.
 *
 * Reads/writes localStorage('mi-theme') with values:
 *   'light' | 'dark' | 'system'
 *
 * The no-flicker bootstrap (set <html data-theme=...> before paint)
 * is inlined in <head>; see mobinspect/MobInspect/templatetags/theme.py.
 *
 * This file adds the user-facing toggle behavior + Chart.js refresh hook.
 */
(function () {
  'use strict';

  const STORAGE_KEY = 'mi-theme';
  const VALID = ['light', 'dark', 'system'];

  function systemPref() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches
      ? 'dark'
      : 'light';
  }

  function resolve(value) {
    return value === 'system' ? systemPref() : value;
  }

  function apply(value) {
    const effective = resolve(value);
    document.documentElement.setAttribute('data-theme', effective);
    document.documentElement.setAttribute('data-theme-pref', value);
    // Notify listeners (Chart.js wrapper, etc.)
    window.dispatchEvent(new CustomEvent('mi:theme-change', {
      detail: { value, effective },
    }));
  }

  function get() {
    // localStorage can throw (private browsing / blocked storage / sandboxed
    // iframe) — don't let that exception escape and break the caller (e.g.
    // Alpine's x-data init on the theme toggle).
    let v;
    try {
      v = localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      v = null;
    }
    // Default (no stored choice yet) is 'dark' — matches the inline
    // no-flicker bootstrap in mi_theme.py; must stay in sync with it.
    return VALID.includes(v) ? v : 'dark';
  }

  function set(value) {
    if (!VALID.includes(value)) return;
    try {
      localStorage.setItem(STORAGE_KEY, value);
    } catch (e) {
      // Storage unavailable — still apply the theme for this page load,
      // it just won't persist across reloads.
    }
    apply(value);
  }

  function cycle() {
    const order = ['light', 'dark', 'system'];
    const current = get();
    const next = order[(order.indexOf(current) + 1) % order.length];
    set(next);
    return next;
  }

  // Re-apply when system pref changes if user is in 'system' mode.
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener(
    'change',
    () => { if (get() === 'system') apply('system'); },
  );

  window.MI = window.MI || {};
  window.MI.theme = { get, set, cycle, apply, resolve, systemPref };
})();
