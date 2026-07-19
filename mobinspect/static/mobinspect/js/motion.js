/**
 * MobInspect — motion helpers.
 *
 * Tiny wrapper around the native Web Animations API for the
 * orchestrated motions defined in docs/04-design-system.md.
 *
 * Honors `prefers-reduced-motion: reduce` automatically.
 *
 * Usage:
 *   MI.motion.reveal('.card');                  // staggered fade-up
 *   MI.motion.fadeIn(el);                       // single element
 *   MI.motion.scaleIn(modalPanel);              // modal content
 *   MI.motion.observeAndReveal('[data-reveal]'); // reveal on scroll into view
 */
(function () {
  'use strict';

  const PREFERS_REDUCED = window.matchMedia(
    '(prefers-reduced-motion: reduce)'
  ).matches;

  const EASE = {
    out:   'cubic-bezier(0.16, 1, 0.3, 1)',
    in:    'cubic-bezier(0.7, 0, 0.84, 0)',
    inOut: 'cubic-bezier(0.65, 0, 0.35, 1)',
  };

  const DUR = { fast: 120, base: 200, slow: 320 };

  function play(el, keyframes, options) {
    // fadeIn/fadeUp/scaleIn are exported on window.MI.motion for any caller
    // to use directly with a single element — guard against a missing one
    // so a null/undefined target doesn't throw and kill the caller's script.
    if (!el) return;
    if (PREFERS_REDUCED) {
      // Collapse to opacity-only fade.
      const last = keyframes[keyframes.length - 1];
      Object.assign(el.style, last);
      return;
    }
    el.animate(keyframes, options);
  }

  function fadeIn(el, duration = DUR.base) {
    play(el, [{ opacity: 0 }, { opacity: 1 }], {
      duration, easing: EASE.out, fill: 'both',
    });
  }

  function fadeUp(el, duration = DUR.slow, delay = 0) {
    play(
      el,
      [
        { opacity: 0, transform: 'translateY(4px)' },
        { opacity: 1, transform: 'translateY(0)' },
      ],
      { duration, delay, easing: EASE.out, fill: 'both' },
    );
  }

  function scaleIn(el, duration = DUR.base) {
    play(
      el,
      [
        { opacity: 0, transform: 'scale(0.95)' },
        { opacity: 1, transform: 'scale(1)' },
      ],
      { duration, easing: EASE.out, fill: 'both' },
    );
  }

  function reveal(selector, { stagger = 50, root = document } = {}) {
    const els = root.querySelectorAll(selector);
    els.forEach((el, i) => fadeUp(el, DUR.slow, i * stagger));
  }

  function observeAndReveal(selector, { stagger = 50 } = {}) {
    if (typeof IntersectionObserver === 'undefined') {
      reveal(selector, { stagger });
      return;
    }
    const seen = new WeakSet();
    const io = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((e) => e.isIntersecting && !seen.has(e.target))
        .map((e) => e.target);
      visible.forEach((el, i) => {
        seen.add(el);
        fadeUp(el, DUR.slow, i * stagger);
        io.unobserve(el);
      });
    }, { rootMargin: '0px 0px -10% 0px' });
    document.querySelectorAll(selector).forEach((el) => {
      el.style.opacity = '0';
      io.observe(el);
    });
  }

  // Expose under window.MI namespace.
  window.MI = window.MI || {};
  window.MI.motion = {
    fadeIn, fadeUp, scaleIn, reveal, observeAndReveal,
    EASE, DUR, PREFERS_REDUCED,
  };
})();
