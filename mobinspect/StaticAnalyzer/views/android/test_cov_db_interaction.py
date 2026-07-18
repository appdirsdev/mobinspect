# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for db_interaction.py.

Drives get_context_from_db_entry's except branch with a real object that
is missing the expected DB-row attributes, and save_or_update's second
(RecentScansDB) except branch with a *real* PostgreSQL length-constraint
violation (VERSION_NAME is CharField(50) on RecentScansDB but CharField
(100) on StaticAnalyzerAndroid, so an 80-char value saves to the first
table and genuinely overflows the second) -- no mocking.
"""
import pytest
from django.test import TestCase

from mobinspect.StaticAnalyzer.models import RecentScansDB, StaticAnalyzerAndroid
from mobinspect.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
    save_or_update,
)


class GetContextFromDbEntryTests(TestCase):

    def test_missing_attributes_hits_except_branch(self):
        # A real object lacking the expected DB-row attributes makes the
        # very first attribute access (PACKAGE_NAME) raise AttributeError.
        class Empty:
            pass

        result = get_context_from_db_entry([Empty()])
        self.assertIsNone(result)


def _full_dicts(checksum, androvername):
    app_dic = {
        'app_name': 'x.apk', 'real_name': 'App', 'zipped': 'apk',
        'size': '1MB', 'md5': checksum, 'sha1': 'a' * 40, 'sha256': 'b' * 64,
        'icon_path': '', 'file_analysis': [], 'files': [], 'playstore': {},
    }
    man_data_dic = {
        'packagename': 'com.x', 'mainactivity': 'com.x.Main',
        'activities': [], 'receivers': [], 'providers': [], 'services': [],
        'libraries': [], 'target_sdk': '30', 'max_sdk': '', 'min_sdk': '21',
        'androvername': androvername, 'androver': '1',
    }
    man_an_dic = {
        'exported_act': [], 'browsable_activities': {}, 'permissions': {},
        'malware_permissions': {}, 'manifest_anal': [], 'network_security': {},
        'exported_cnt': {},
    }
    code_an_dic = {
        'findings': {}, 'api': {}, 'niap': {}, 'perm_mappings': {},
        'urls': [], 'domains': {}, 'emails': [], 'strings': [],
        'firebase': {}, 'secrets': [], 'sbom': {}, 'behaviour': {},
    }
    return app_dic, man_data_dic, man_an_dic, code_an_dic


class SaveOrUpdateTests(TestCase):

    def test_full_save_succeeds_both_tables(self):
        checksum = 'e' * 32
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='apk', FILE_NAME='x.apk')
        app_dic, man_data_dic, man_an_dic, code_an_dic = _full_dicts(
            checksum, '1.2.3')
        save_or_update(
            'save', app_dic, man_data_dic, man_an_dic, code_an_dic,
            {}, {}, {}, {})
        self.assertTrue(
            StaticAnalyzerAndroid.objects.filter(MD5=checksum).exists())
        self.assertEqual(
            RecentScansDB.objects.get(MD5=checksum).VERSION_NAME, '1.2.3')

    def test_update_branch_when_db_entry_already_exists(self):
        # StaticAnalyzerAndroid row already present -> update_type != 'save'
        # takes the .filter(...).update(**values) branch instead of create.
        checksum = 'f' * 32
        RecentScansDB.objects.create(
            MD5=checksum, SCAN_TYPE='apk', FILE_NAME='x.apk')
        app_dic, man_data_dic, man_an_dic, code_an_dic = _full_dicts(
            checksum, '1.0')
        save_or_update(
            'save', app_dic, man_data_dic, man_an_dic, code_an_dic,
            {}, {}, {}, {})
        save_or_update(
            'update', app_dic, man_data_dic, man_an_dic, code_an_dic,
            {}, {}, {}, {})
        self.assertEqual(
            StaticAnalyzerAndroid.objects.filter(MD5=checksum).count(), 1)


@pytest.mark.django_db(transaction=True)
def test_recentscansdb_update_failure_is_caught():
    # RecentScansDB.VERSION_NAME is CharField(max_length=50), but
    # StaticAnalyzerAndroid.VERSION_NAME allows 100: an 80-char value
    # saves to the first table for real, then genuinely overflows the
    # second table's real PostgreSQL column, raising a real DataError
    # that save_or_update's second try/except must catch (not @override
    # settings/mocks -- transaction=True so the real, caught DB error
    # doesn't poison the rest of this test's transaction, matching
    # Postgres's real autocommit behaviour in production).
    checksum = 'a' * 32
    RecentScansDB.objects.create(
        MD5=checksum, SCAN_TYPE='apk', FILE_NAME='x.apk')
    app_dic, man_data_dic, man_an_dic, code_an_dic = _full_dicts(
        checksum, 'v' * 80)
    save_or_update(
        'save', app_dic, man_data_dic, man_an_dic, code_an_dic,
        {}, {}, {}, {})
    # First table saved fine (100-char column); second table's update
    # silently failed and was caught -> VERSION_NAME stays at its default.
    assert StaticAnalyzerAndroid.objects.filter(MD5=checksum).exists()
    assert RecentScansDB.objects.get(MD5=checksum).VERSION_NAME == ''
