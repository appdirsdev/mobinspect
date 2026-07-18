# -*- coding: utf_8 -*-
"""Real-execution coverage tests for mi_score template tag filters.

Pure functions, no DB/mocks needed -- every tier boundary and the
None/invalid-value fail-closed paths are driven directly.
"""
from django.test import SimpleTestCase

from mobinspect.MobInspect.templatetags import mi_score as ms


class TierBoundaryTests(SimpleTestCase):

    def test_none_returns_none_tier(self):
        self.assertIsNone(ms._tier(None))

    def test_non_numeric_string_returns_none(self):
        self.assertIsNone(ms._tier('not-a-number'))

    def test_below_30_is_critical(self):
        self.assertEqual(ms._tier(0), 'critical')
        self.assertEqual(ms._tier(29.9), 'critical')

    def test_30_to_39_is_medium(self):
        self.assertEqual(ms._tier(30), 'medium')
        self.assertEqual(ms._tier(39.9), 'medium')

    def test_40_to_59_is_low(self):
        self.assertEqual(ms._tier(40), 'low')
        self.assertEqual(ms._tier(59.9), 'low')

    def test_60_and_above_is_passed(self):
        self.assertEqual(ms._tier(60), 'passed')
        self.assertEqual(ms._tier(100), 'passed')

    def test_numeric_string_is_coerced(self):
        self.assertEqual(ms._tier('75'), 'passed')


class ScoreTierFilterTests(SimpleTestCase):

    def test_unset_value_is_empty_string(self):
        self.assertEqual(ms.score_tier(None), '')

    def test_invalid_value_is_empty_string(self):
        self.assertEqual(ms.score_tier('nonsense'), '')

    def test_real_tier_name(self):
        self.assertEqual(ms.score_tier(10), 'critical')
        self.assertEqual(ms.score_tier(90), 'passed')


class ScoreColorFilterTests(SimpleTestCase):

    def test_unset_value_is_empty_string(self):
        self.assertEqual(ms.score_color(None), '')

    def test_invalid_value_is_empty_string(self):
        self.assertEqual(ms.score_color('nonsense'), '')

    def test_real_color_for_each_tier(self):
        self.assertEqual(ms.score_color(10), 'rgb(var(--score-critical))')
        self.assertEqual(ms.score_color(35), 'rgb(var(--score-medium))')
        self.assertEqual(ms.score_color(50), 'rgb(var(--score-low))')
        self.assertEqual(ms.score_color(80), 'rgb(var(--score-passed))')


class ScoreClassFilterTests(SimpleTestCase):

    def test_unset_value_is_empty_string(self):
        self.assertEqual(ms.score_class(None), '')

    def test_invalid_value_is_empty_string(self):
        self.assertEqual(ms.score_class('nonsense'), '')

    def test_real_class_for_each_tier(self):
        self.assertEqual(
            ms.score_class(10),
            'text-severity-critical dark:text-severity-critical-dark')
        self.assertEqual(
            ms.score_class(35),
            'text-severity-medium dark:text-severity-medium-dark')
        self.assertEqual(
            ms.score_class(50),
            'text-severity-low dark:text-severity-low-dark')
        self.assertEqual(
            ms.score_class(80),
            'text-severity-passed dark:text-severity-passed-dark')
