# -*- coding: utf_8 -*-
"""Common helpers for Android and iOS Dynamic Analysis."""
import logging
import os
import re
import errno
import json
import tarfile
import shutil
from pathlib import Path

from django.http import HttpResponse

from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.MobSF.exceptions import PathTraversalError
from mobsf.MobSF.utils import (
    EMAIL_REGEX,
    URL_REGEX,
    clean_filename,
    is_pipe_or_link,
)

logger = logging.getLogger(__name__)


def extract_urls_domains_emails(checksum, data):
    """Extract URLs, Domains and Emails."""
    # URL Extraction
    urls = re.findall(URL_REGEX, data)
    if urls:
        urls = list(set(urls))
    else:
        urls = []
    # Domain Extraction and Malware Check
    logger.info('Performing Malware check on extracted domains')
    # For domain extraction, use lowercased URLs
    domains = MalwareDomainCheck().scan(
        checksum,
        urls)
    # Email Extraction Regex
    emails = set()
    for email in EMAIL_REGEX.findall(data.lower()):
        if email.startswith('//'):
            continue
        if email.endswith('.png'):
            continue
        emails.add(email)
    return urls, domains, emails


def safe_paths(tar_meta):
    """Safe filenames in windows."""
    for fh in tar_meta:
        fh.name = clean_filename(fh.name)
        yield fh


def onexc(func, path, exc_info):
    _, exc_value, _ = exc_info
    if exc_value.errno == errno.EACCES:  # Permission error
        try:
            os.chmod(path, 0o755)
            func(path)
        except Exception:
            pass
    elif exc_value.errno == errno.ENOTEMPTY:  # Directory not empty
        try:
            func(path)
        except Exception:
            pass
    else:
        raise


def untar_files(tar_loc, untar_dir):
    """Untar files."""
    logger.info('Extracting Tar files')
    try:
        # Extract Device Data
        if not tar_loc.exists():
            return False
        if untar_dir.exists():
            # fix for permission errors
            shutil.rmtree(untar_dir, onexc=onexc)
        else:
            os.makedirs(untar_dir)
        with tarfile.open(tar_loc.as_posix(), errorlevel=1) as tar:

            def is_within_directory(directory, target):
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
                return (abs_target.startswith(abs_directory + os.sep)
                        or abs_target == abs_directory)

            def safe_extract(tar, path='.',
                             members=None,
                             *,
                             numeric_owner=False):
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise PathTraversalError('Attempted Path Traversal in Tar File')
                tar.extractall(path, members, numeric_owner=numeric_owner)

            safe_extract(tar, untar_dir, members=safe_paths(tar))
    except (FileExistsError, tarfile.ReadError):
        logger.warning('Failed to extract tar file')
    except Exception:
        logger.exception('Tar extraction failed')
    return True


def get_app_files(app_dir, tarname):
    """Get files from device."""
    logger.info('Getting app files')
    all_files = {'xml': [], 'sqlite': [], 'others': [], 'plist': []}
    appdir = Path(app_dir)
    tar_loc = appdir / f'{tarname}.tar'
    untar_dir = appdir / 'DYNAMIC_DeviceData'
    success = untar_files(tar_loc, untar_dir)
    if not success:
        return all_files
    # Do Static Analysis on Data from Device
    try:
        untar_dir = untar_dir.as_posix()
        for dir_name, _, files in os.walk(untar_dir):
            for jfile in files:
                file_path = os.path.join(untar_dir, dir_name, jfile)
                fileparam = file_path.replace(f'{untar_dir}/', '')
                if is_pipe_or_link(file_path):
                    continue
                if jfile == 'lib':
                    pass
                else:
                    if jfile.endswith('.xml'):
                        all_files['xml'].append(
                            {'type': 'xml', 'file': fileparam})
                    elif jfile.endswith('.plist'):
                        all_files['plist'].append(
                            {'type': 'plist', 'file': fileparam})
                    else:
                        with open(file_path,
                                  'r',
                                  encoding='ISO-8859-1') as flip:
                            file_cnt_sig = flip.read(6)
                        if file_cnt_sig == 'SQLite':
                            all_files['sqlite'].append(
                                {'type': 'db', 'file': fileparam})
                        elif not jfile.endswith('.DS_Store'):
                            all_files['others'].append(
                                {'type': 'others', 'file': fileparam})
    except Exception:
        logger.exception('Getting app files')
    return all_files


def send_response(data, api=False):
    """Return JSON Response."""
    if api:
        return data
    return HttpResponse(
        json.dumps(data),
        content_type='application/json; charset=utf-8')


def invalid_params(api=False):
    """Standard response for invalid params."""
    msg = 'Invalid Parameters'
    logger.error(msg)
    data = {'status': 'failed', 'message': msg}
    if api:
        return data
    return send_response(data)


def is_attack_pattern(user_input):
    """Check for attacks."""
    atk_pattern = re.compile(r';|\$\(|\|\||&&')
    stat = re.findall(atk_pattern, user_input)
    if stat:
        logger.error('Possible RCE attack detected')
    return stat


# Shared command allowlists for adb/ssh shell pass-throughs.
#
# Each entry is (verb_prefix, args_pattern_regex).
#   * `verb_prefix` is matched as a literal whitespace-tokenized prefix of the
#     user-supplied command (after `.split()` normalization).
#   * `args_pattern_regex` is either None (meaning no further args allowed
#     beyond the verb) or a regex that the joined remainder must fully match.
#
# Keep both lists conservative — anything not listed gets a 403.
ADB_CMD_ALLOWLIST = (
    ('shell pm list packages', None),
    ('shell pm list packages -3', None),
    ('shell getprop', r'[a-zA-Z0-9._-]+$'),
    ('shell dumpsys window', None),
    ('shell ps -A', None),
    ('shell logcat -d -t', r'\d+'),
    ('devices', None),
)

# iOS SSH commands: each entry is (verb_prefix, args_pattern_regex).
# Args are not currently expected for any of these — restrict to bare verbs.
SSH_CMD_ALLOWLIST = (
    ('ls', None),
    ('ps -A', None),
    ('cat /etc/version', None),
    ('plistutil', None),
)


def _match_allowlist(cmd, allowlist):
    """Return True if `cmd` matches a (verb, args_regex) entry in `allowlist`.

    Both the command and verbs are tokenized on whitespace before matching to
    avoid quoting/spacing shenanigans (e.g. multiple spaces between tokens).
    """
    if cmd is None:
        return False
    tokens = cmd.strip().split()
    if not tokens:
        return False
    for verb, args_regex in allowlist:
        verb_tokens = verb.split()
        if tokens[:len(verb_tokens)] != verb_tokens:
            continue
        rest_tokens = tokens[len(verb_tokens):]
        if args_regex is None:
            if not rest_tokens:
                return True
            continue
        rest = ' '.join(rest_tokens)
        if re.fullmatch(args_regex, rest):
            return True
    return False


def is_adb_command_allowed(cmd):
    """Return True if `cmd` matches the ADB command allowlist."""
    return _match_allowlist(cmd, ADB_CMD_ALLOWLIST)


def is_ssh_command_allowed(cmd):
    """Return True if `cmd` matches the iOS SSH command allowlist."""
    return _match_allowlist(cmd, SSH_CMD_ALLOWLIST)
