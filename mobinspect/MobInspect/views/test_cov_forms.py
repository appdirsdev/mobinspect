# -*- coding: utf_8 -*-
"""Real-execution coverage tests for mobinspect.MobInspect.forms.

Drives FormUtil, UploadFileForm, and RegisterForm with real Django form
binding, real Users, and real RBAC Role rows. One branch (RBAC models
unavailable) is exercised via a narrow, single-target sys.modules poison
of the RBAC dotted path, matching the established pattern elsewhere in
this repo's coverage suite (e.g. test_cov_home.py's
test_rollup_import_failure_returns_empty).
"""
import sys

from django.contrib.auth.models import User
from django.test import TestCase

from mobinspect.MobInspect.forms import FormUtil, RegisterForm, UploadFileForm


class UploadFileFormTests(TestCase):

    def test_missing_file_is_invalid(self):
        form = UploadFileForm({}, {})
        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)


class FormUtilTests(TestCase):
    """FormUtil is used as a static-method namespace in production
    (home.py calls FormUtil.errors_message(form) directly on the class),
    but its __init__ and .errors() are never actually invoked anywhere in
    the codebase -- exercised here directly."""

    def _invalid_upload_form(self):
        form = UploadFileForm({}, {})
        form.is_valid()
        return form

    def test_init_stores_form(self):
        form = self._invalid_upload_form()
        util = FormUtil(form)
        self.assertIs(util.form, form)

    def test_errors_message_joins_messages(self):
        form = self._invalid_upload_form()
        data = FormUtil.errors_message(form)
        self.assertIn('file', data)
        self.assertIn('required', data['file'])

    def test_errors_returns_raw_json_data(self):
        form = self._invalid_upload_form()
        data = FormUtil.errors(form)
        self.assertIn('file', data)
        # Raw get_json_data() shape: a list of {message, code} dicts.
        self.assertIsInstance(data['file'], list)
        self.assertIn('message', data['file'][0])


class RegisterFormTests(TestCase):
    """RegisterForm: dynamic role choices (real RBAC Role rows), the
    RBAC-unavailable fallback, and the duplicate-email validator."""

    def test_role_choices_populated_from_real_roles(self):
        from django.contrib.auth.models import Group
        from mobinspect.RBAC.models import Role
        Role.objects.all().delete()
        Role.objects.create(
            name='Zeta Role', group=Group.objects.create(name='Zeta Role'))
        Role.objects.create(
            name='Alpha Role', group=Group.objects.create(name='Alpha Role'))
        form = RegisterForm()
        labels = [label for _, label in form.fields['role'].choices]
        # order_by('name') -> Alpha before Zeta.
        self.assertEqual(labels, sorted(labels))
        self.assertIn('Alpha Role', labels)

    def test_role_choices_fallback_when_rbac_unavailable(self):
        # Real fault injection: poison sys.modules for the RBAC models
        # dotted path so the real `from mobinspect.RBAC.models import
        # Role` statement inside __init__ raises ImportError -- not a
        # return-value mock.
        target = 'mobinspect.RBAC.models'
        prev = sys.modules.get(target, False)
        sys.modules[target] = None
        try:
            form = RegisterForm()
        finally:
            if prev is False:
                sys.modules.pop(target, None)
            else:
                sys.modules[target] = prev
        self.assertEqual(form.fields['role'].choices, [])

    def test_clean_email_rejects_existing_email(self):
        User.objects.create_user(
            username='existing_email_user', password='x',
            email='dupe@example.com')
        form = RegisterForm({
            'username': 'newuser', 'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!', 'email': 'DUPE@example.com',
            'role': '',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)
        self.assertIn('Email already exists', str(form.errors['email']))

    def test_clean_email_allows_new_email(self):
        form = RegisterForm({
            'username': 'brandnewuser', 'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!', 'email': 'fresh@example.com',
            'role': '',
        })
        form.is_valid()
        # No email-uniqueness error (role may still be required/blank).
        self.assertNotIn('email', form.errors)

    def test_clean_email_allows_blank_when_another_user_has_blank(self):
        # Regression: the seeded admin account has a blank email, so a bare
        # exists() check on '' matched it and rejected EVERY subsequent
        # "create user without an email". A blank email must be allowed
        # (Django does not treat blank emails as unique).
        User.objects.create_user(
            username='blank_email_user', password='x', email='')
        form = RegisterForm({
            'username': 'anotherblankuser', 'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!', 'email': '',
            'role': '',
        })
        form.is_valid()
        self.assertNotIn('email', form.errors)
