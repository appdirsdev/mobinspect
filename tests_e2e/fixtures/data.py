"""Shared, environment-agnostic test data for the e2e suite.

Every hash below is a REAL scan already present against a freshly migrated
MobInspect DB when the fixture APKs/IPAs in ``test_files/`` at the repo root
are scanned once (see ``tests_e2e/README.md`` -> "Seeding test data"). Specs
read from here instead of hardcoding hashes so a single re-seed keeps the
whole suite in sync.
"""
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST_FILES_DIR = os.path.join(REPO_ROOT, 'test_files')

# One already-scanned sample per supported artifact type. MD5s are stable
# because the fixture file bytes never change; if a fixture file is replaced,
# re-run the seeding step in the README and update the hash here.
SCANNED = {
    'apk': {
        'hash': '82ab8b2193b3cfb1c737e3a786be363a',
        'app_name': 'Diva',
        'file_name': 'android.apk',
        'file': os.path.join(TEST_FILES_DIR, 'android.apk'),
    },
    'xapk': {
        'hash': '02e7989c457ab67eb514a8328779f256',
        'app_name': 'On Demand Sample',
        'file_name': 'android_xapk.xapk',
        'file': os.path.join(TEST_FILES_DIR, 'android_xapk.xapk'),
    },
    'jar': {
        'hash': 'e3d5a71257d1ef093a2b503283ee3a86',
        'app_name': '',
        'file_name': 'android.jar',
        'file': os.path.join(TEST_FILES_DIR, 'android.jar'),
    },
    'aar': {
        'hash': '353e4b9e37c4631dc3acad3b192ea3f7',
        'app_name': '',
        'file_name': 'android.aar',
        'file': os.path.join(TEST_FILES_DIR, 'android.aar'),
    },
    'android_src': {
        'hash': '52c50ae824e329ba8b5b7a0f523efffe',
        'app_name': 'WebViewIgnoreSSL',
        'file_name': 'android_src.zip',
        'file': os.path.join(TEST_FILES_DIR, 'android_src.zip'),
    },
    'so': {
        'hash': '1c7fd31930e37e23c59eaf58b384b782',
        'app_name': '',
        'file_name': 'android.so',
        'file': os.path.join(TEST_FILES_DIR, 'android.so'),
    },
    'ipa': {
        'hash': '6c23c2970551be15f32bbab0b5db0c71',
        'app_name': 'helloworld',
        'file_name': 'ios.ipa',
        'file': os.path.join(TEST_FILES_DIR, 'ios.ipa'),
    },
    'dylib': {
        'hash': 'bb0f473db989e545f0e4a49b67946471',
        'app_name': '',
        'file_name': 'macho.dylib',
        'file': os.path.join(TEST_FILES_DIR, 'macho.dylib'),
    },
    'ios_src': {
        'hash': '57bb5be0ea44a755ada4a93885c3825e',
        'app_name': 'DamnVulnerableIOSApp',
        'file_name': 'ios_src.zip',
        'file': os.path.join(TEST_FILES_DIR, 'ios_src.zip'),
    },
    'ios_swift_src': {
        'hash': '7b0a23bffc80bac05739ea1af898daad',
        'app_name': '$(PRODUCT_NAME)',
        'file_name': 'ios_swift_src.zip',
        'file': os.path.join(TEST_FILES_DIR, 'ios_swift_src.zip'),
    },
    'appx': {
        'hash': '8179b557433835827a70510584f3143e',
        'app_name': 'AppStudio',
        'file_name': 'windows.appx',
        'file': os.path.join(TEST_FILES_DIR, 'windows.appx'),
    },
}

# The primary sample most specs should default to: a real, richly-featured
# vulnerable Android app (permissions, exported activities, SQLite, secrets).
PRIMARY = SCANNED['apk']
PRIMARY_HASH = PRIMARY['hash']

# A second, distinct scanned Android app for compare()/search() specs that
# need two different results.
SECONDARY_HASH = SCANNED['jar']['hash']
