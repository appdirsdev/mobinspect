# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/binary_rule_matcher.py.

The real, shipped ``ipa_rules.IPA_RULES`` table currently contains ONLY
``input_case: 'exact'`` / ``type: 'Regex'`` rules (verified directly:
every one of the 10 real rules uses those exact values) -- so the
'lower'/'upper' input-case branches and the non-Regex rule-type branch
are genuinely unreachable with the real, shipped rule data. A crafted
rule list (same convention as the project's other crafted-dict tests,
e.g. GetScanSubjectTests in ios/test_cov_ipa.py) is patched onto the
``ipa_rules`` module for the duration of a test, and the REAL
``binary_rule_matcher()`` matching algorithm runs against it unmodified
-- this exercises real regex matching, real case-folding, and the real
error-logging branch, only substituting which rules are on the table.
"""
from unittest import mock

from django.test import SimpleTestCase

from mobinspect.StaticAnalyzer.views.ios import binary_rule_matcher as brm
from mobinspect.StaticAnalyzer.views.ios.rules import ipa_rules


def _rule(**overrides):
    base = {
        'description': 'desc',
        'detailed_desc': 'Found: {}',
        'type': 'Regex',
        'pattern': rb'\bSECRET\b',
        'severity': 'high',
        'input_case': 'exact',
        'cvss': 5,
        'cwe': 'CWE-000',
        'owasp-mobile': 'M0',
        'masvs': 'CODE-0',
    }
    base.update(overrides)
    return base


class BinaryRuleMatcherTests(SimpleTestCase):

    def test_lower_input_case_branch(self):
        # input_case == 'lower' -> tmp_data = data.lower() (line 40);
        # the pattern is matched against the lower-cased data.
        rules = [_rule(input_case='lower', pattern=rb'\bsecret\b')]
        with mock.patch.object(ipa_rules, 'IPA_RULES', rules):
            findings = {}
            brm.binary_rule_matcher(
                'a' * 32, findings, [b'SECRET'.decode()], b'')
        self.assertIn('desc', findings)

    def test_upper_input_case_branch(self):
        # input_case == 'upper' -> tmp_data = data.upper() (line 42).
        rules = [_rule(input_case='upper', pattern=rb'\bSECRET\b')]
        with mock.patch.object(ipa_rules, 'IPA_RULES', rules):
            findings = {}
            brm.binary_rule_matcher(
                'b' * 32, findings, ['secret'], b'')
        self.assertIn('desc', findings)

    def test_unsupported_rule_type_logs_error(self):
        # rule['type'] != 'Regex' -> the else branch logs a binary-rule
        # error and continues (lines 59-62); no exception propagates.
        rules = [_rule(type='UnsupportedType')]
        with mock.patch.object(ipa_rules, 'IPA_RULES', rules):
            findings = {}
            brm.binary_rule_matcher('c' * 32, findings, [], b'')
        self.assertEqual(findings, {})

    def test_outer_exception_non_bytes_classdump(self):
        # classdump is a str, not bytes -> `classdump + '\n'.join(...)
        # .encode('utf-8')` genuinely raises TypeError (str + bytes) ->
        # the function's own outer except (lines 63-66).
        findings = {}
        brm.binary_rule_matcher(
            'd' * 32, findings, ['x'], 'not-bytes-classdump')
        self.assertEqual(findings, {})
