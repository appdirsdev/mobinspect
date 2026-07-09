/**
 * MobInspect — Tailwind CSS configuration.
 *
 * Single source of truth for design tokens. Mirrored to docs/design/tokens.json.
 * See docs/04-design-system.md and docs/design/mood.md for usage rationale.
 */

/** @type {import('tailwindcss').Config} */
module.exports = {
  // Class-based dark mode — toggled via data-theme="dark" on <html>.
  // We use class strategy (not 'media') so users can override system preference.
  darkMode: ['class', '[data-theme="dark"]'],

  // Scan every place that can reference Tailwind class names.
  content: [
    './mobsf/templates/**/*.html',
    './mobsf/**/templates/**/*.html',
    './mobsf/**/*.py',                 // template strings, form widgets
    './mobsf/static/mobinspect/js/**/*.js',
  ],

  theme: {
    // Restrict the screens to a tighter set; we don't optimize for phones.
    screens: {
      sm:  '640px',
      md:  '768px',
      lg:  '1024px',
      xl:  '1280px',
      '2xl': '1536px',
    },

    extend: {
      // ───────────────────────────────────────── colors
      colors: {
        // Brand
        mobinspect: {
          50:  '#EFF6FF',
          100: '#DBEAFE',
          200: '#BFDBFE',
          300: '#93C5FD',
          400: '#3B82F6',
          500: '#2563EB',
          600: '#1D4ED8',
          700: '#1E40AF',
          800: '#1E3A8A',
          900: '#1E3A8A',
          950: '#172554',
        },

        // Chart duotone — reserved for data-visualization series only (never
        // buttons/nav/text/UI chrome, which stay on the `mobinspect` brand
        // ramp + logo). Sourced from the approved dashboard-design reference.
        chart: {
          amber:  '#FE4A23', // primary series (bars, line strokes, deltas)
          violet: '#8D5CFC', // secondary series (alternating bars, contrast line)
        },

        // Severity — semantic only. Never use for non-severity UI.
        // Two stops per severity: base (light theme) + 'on-dark' variant.
        severity: {
          critical:        '#DC2626',
          'critical-dark': '#F87171',
          high:            '#EA580C',
          'high-dark':     '#FB923C',
          medium:          '#D97706',
          'medium-dark':   '#FBBF24',
          low:             '#2563EB',
          'low-dark':      '#60A5FA',
          passed:          '#16A34A',
          'passed-dark':   '#4ADE80',
          unknown:         '#64748B',
          'unknown-dark':  '#94A3B8',
        },

        // System (interactive states)
        system: {
          success: '#16A34A',
          'success-dark': '#4ADE80',
          warning: '#D97706',
          'warning-dark': '#FBBF24',
          error:   '#DC2626',
          'error-dark': '#F87171',
          info:    '#2563EB',
          'info-dark': '#60A5FA',
        },

        // Surfaces — accessed via CSS variables for theme-aware components
        // (Chart.js wrapper reads these). See css/src/app.css.
        surface: {
          0: 'rgb(var(--surface-0) / <alpha-value>)',
          1: 'rgb(var(--surface-1) / <alpha-value>)',
          2: 'rgb(var(--surface-2) / <alpha-value>)',
          3: 'rgb(var(--surface-3) / <alpha-value>)',
          4: 'rgb(var(--surface-4) / <alpha-value>)',
        },
        border: {
          subtle:  'rgb(var(--border-subtle) / <alpha-value>)',
          DEFAULT: 'rgb(var(--border-default) / <alpha-value>)',
          strong:  'rgb(var(--border-strong) / <alpha-value>)',
        },
        text: {
          primary:   'rgb(var(--text-primary) / <alpha-value>)',
          secondary: 'rgb(var(--text-secondary) / <alpha-value>)',
          tertiary:  'rgb(var(--text-tertiary) / <alpha-value>)',
          inverse:   'rgb(var(--text-inverse) / <alpha-value>)',
          brand:     'rgb(var(--text-brand) / <alpha-value>)',
        },
      },

      // ───────────────────────────────────────── typography
      fontFamily: {
        sans: [
          'Inter',
          'system-ui',
          '-apple-system',
          '"Segoe UI"',
          'Roboto',
          'sans-serif',
        ],
        mono: [
          '"JetBrains Mono"',
          'ui-monospace',
          '"Cascadia Code"',
          'Menlo',
          'monospace',
        ],
      },
      fontSize: {
        // [size, { lineHeight, letterSpacing, fontWeight }]
        // NOTE: Tailwind's fontSize array shorthand does NOT support a
        // fontFamily key (verified empirically — silently dropped from the
        // compiled utility). display/h1-h4 get the Albert Sans display face
        // via an explicit override in app.css instead (search "Albert Sans"
        // there); this array stays limited to size/lineHeight/weight.
        display: ['48px', { lineHeight: '1.1',  fontWeight: '700' }],
        h1:      ['30px', { lineHeight: '1.2',  fontWeight: '600' }],
        h2:      ['24px', { lineHeight: '1.25', fontWeight: '600' }],
        h3:      ['20px', { lineHeight: '1.3',  fontWeight: '600' }],
        h4:      ['16px', { lineHeight: '1.4',  fontWeight: '600' }],
        body:    ['14px', { lineHeight: '1.55', fontWeight: '400' }],
        small:   ['13px', { lineHeight: '1.5',  fontWeight: '400' }],
        tiny:    ['12px', { lineHeight: '1.4',  fontWeight: '500', letterSpacing: '0.05em' }],
        mono:    ['13px', { lineHeight: '1.5',  fontWeight: '400' }],
      },

      // ───────────────────────────────────────── radius
      borderRadius: {
        sm:  '4px',
        md:  '6px',
        lg:  '8px',
        xl:  '12px',
        '2xl': '16px',
      },

      // ───────────────────────────────────────── elevation
      boxShadow: {
        'elevation-1':    '0 1px 2px rgb(0 0 0 / 0.05)',
        'elevation-2':    '0 4px 8px -2px rgb(0 0 0 / 0.08), 0 2px 4px -2px rgb(0 0 0 / 0.04)',
        'elevation-3':    '0 12px 24px -8px rgb(0 0 0 / 0.12), 0 4px 8px -4px rgb(0 0 0 / 0.06)',
        'elevation-4':    '0 24px 48px -12px rgb(0 0 0 / 0.18)',
        'elevation-glow': '0 0 0 4px rgb(37 99 235 / 0.15)',
      },

      // ───────────────────────────────────────── motion
      transitionDuration: {
        fast: '120ms',
        base: '200ms',
        slow: '320ms',
      },
      transitionTimingFunction: {
        out:    'cubic-bezier(0.16, 1, 0.3, 1)',
        in:     'cubic-bezier(0.7, 0, 0.84, 0)',
        'in-out': 'cubic-bezier(0.65, 0, 0.35, 1)',
      },
      keyframes: {
        'fade-in':    { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        'fade-up':    {
          '0%':   { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'scale-in': {
          '0%':   { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        'shimmer': {
          '0%':   { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
      animation: {
        'fade-in':  'fade-in 200ms cubic-bezier(0.16, 1, 0.3, 1) both',
        'fade-up':  'fade-up 320ms cubic-bezier(0.16, 1, 0.3, 1) both',
        'scale-in': 'scale-in 200ms cubic-bezier(0.16, 1, 0.3, 1) both',
        'shimmer':  'shimmer 1.5s linear infinite',
      },

      // ───────────────────────────────────────── layout
      maxWidth: {
        content: '1440px',
      },
      spacing: {
        sidebar:           '240px',
        'sidebar-collapsed': '64px',
        topbar:            '56px',
      },
    },
  },

  plugins: [],
};
