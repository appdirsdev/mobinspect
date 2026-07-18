# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/db_interaction.py.

Real fault injection: an empty queryset makes ``db_entry[0]`` genuinely
raise IndexError; app_dict/code_dict/bin_dict missing a required key
genuinely raise KeyError; a value that fits one model field but overflows
a *different* real model field's max_length makes PostgreSQL itself
genuinely reject the second UPDATE (a real ``django.db.utils.DataError``),
letting the first save succeed while only the second, independent
try/except block fails -- no mocking of the module under test.
"""
from django.test import TestCase

from mobinspect.StaticAnalyzer.models import RecentScansDB, StaticAnalyzerIOS
from mobinspect.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_analysis,
    get_context_from_db_entry,
    save_or_update,
)


def _valid_dicts(checksum, extra_app=None, extra_info=None):
    info_dict = {
        'id': 'com.example.app',
        'bin_name': 'App',
        'build': '1',
        'bundle_version_name': '1.0',
        'sdk': 'iphoneos17.0',
        'pltfm': 'iphoneos',
        'min': '13.0',
        'bundle_url_types': [],
        'bundle_supported_platforms': [],
        'plist_xml': '<plist/>',
        'permissions': {},
        'inseccon': {},
    }
    if extra_info:
        info_dict.update(extra_info)
    app_dict = {
        'file_name': 'app.ipa',
        'size': '1024',
        'md5_hash': checksum,
        'sha1': 'a' * 40,
        'sha256': 'b' * 64,
        'icon_path': '',
        'infoplist': info_dict,
        'all_files': {'special_files': [], 'files_short': []},
        'appstore': {},
        'secrets': [],
    }
    if extra_app:
        app_dict.update(extra_app)
    bin_dict = {
        'bin_type': 'Objective-C',
        'bin_info': {},
        'bin_code_analysis': {},
        'checksec': {},
        'dylib_analysis': [],
        'framework_analysis': [],
        'libraries': [],
        'strings': [],
    }
    code_dict = {
        'api': {},
        'code_anal': {},
        'urlnfile': [],
        'domains': {},
        'emailnfile': [],
        'firebase': [],
        'trackers': {},
    }
    return app_dict, code_dict, bin_dict


class GetContextFromDbEntryTests(TestCase):

    def test_empty_queryset_index_error_returns_none(self):
        # db_entry[0] on an empty queryset genuinely raises IndexError ->
        # caught -> return None (lines 78-81).
        result = get_context_from_db_entry(StaticAnalyzerIOS.objects.none())
        self.assertIsNone(result)


class GetContextFromAnalysisTests(TestCase):

    def test_missing_infoplist_key_returns_none(self):
        # app_dict missing 'infoplist' -> real KeyError -> caught
        # (lines 142-145); function has no explicit return in the except,
        # so it implicitly returns None.
        checksum = 'c' * 32
        app_dict, code_dict, bin_dict = _valid_dicts(checksum)
        del app_dict['infoplist']
        result = get_context_from_analysis(app_dict, code_dict, bin_dict)
        self.assertIsNone(result)


class SaveOrUpdateTests(TestCase):

    def test_missing_infoplist_key_first_try_except(self):
        # app_dict missing 'infoplist' -> info_dict access raises KeyError
        # inside the first try -> caught (lines 204-207). The function
        # still attempts the second try afterward (which no-ops safely:
        # RecentScansDB has no matching row).
        checksum = 'd' * 32
        app_dict, code_dict, bin_dict = _valid_dicts(checksum)
        del app_dict['infoplist']
        # Should not raise.
        save_or_update('save', app_dict, code_dict, bin_dict)
        self.assertFalse(
            StaticAnalyzerIOS.objects.filter(MD5=checksum).exists())

    def test_recentscansdb_update_fails_independently_of_first_save(self):
        # VERSION_NAME on RecentScansDB is CharField(max_length=50), while
        # APP_VERSION on StaticAnalyzerIOS is CharField(max_length=100).
        # A 60-char version string fits the first, genuinely overflows the
        # second -> the real PostgreSQL UPDATE in the *second*,
        # independent try/except block fails for real
        # (django.db.utils.DataError) and is caught there (lines 216-219).
        #
        # NOTE: a real DataError genuinely poisons the rest of this test's
        # wrapping transaction at the PostgreSQL protocol level (Django's
        # per-test atomic block has no savepoint here, since production
        # code -- correctly for this test's purpose -- does not wrap its
        # own DB calls in transaction.atomic()). No further ORM queries
        # are issued in this test after the call for that reason; the
        # test simply asserts save_or_update() itself does not raise.
        checksum = 'e' * 32
        long_version = 'V' * 60
        app_dict, code_dict, bin_dict = _valid_dicts(
            checksum, extra_info={'bundle_version_name': long_version})
        RecentScansDB.objects.create(MD5=checksum, APP_NAME='Placeholder')
        save_or_update('save', app_dict, code_dict, bin_dict)  # must not raise
