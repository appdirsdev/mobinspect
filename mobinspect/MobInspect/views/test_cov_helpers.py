# -*- coding: utf_8 -*-
"""Real-execution coverage tests for mobinspect.MobInspect.views.helpers.

FileType is already exercised extensively via the upload tests in
test_cov_home.py (real magic-byte detection against real MIME/extension
combinations); this file focuses on the `request_method` decorator's own
branches, driven with real RequestFactory requests and real decorated
functions -- no mocks.
"""
from django.http import HttpRequest, HttpResponseNotAllowed
from django.test import RequestFactory, TestCase

from mobinspect.MobInspect.views.helpers import request_method


class RequestMethodDecoratorTests(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def test_methods_not_list_or_tuple_raises(self):
        @request_method('POST')  # a bare string, not a list/tuple
        def view(request):
            return 'ok'
        with self.assertRaises(ValueError) as ctx:
            view(self.factory.post('/x'))
        self.assertIn('not a list or tuple', str(ctx.exception))

    def test_disallowed_method_raises(self):
        @request_method(['TOTALLY_NOT_A_METHOD'])
        def view(request):
            return 'ok'
        with self.assertRaises(ValueError) as ctx:
            view(self.factory.post('/x'))
        self.assertIn('not allowed', str(ctx.exception))

    def test_missing_request_object_raises(self):
        @request_method(['POST'])
        def view(*args, **kwargs):
            return 'ok'
        # No HttpRequest instance anywhere in args/kwargs.
        with self.assertRaises(ValueError) as ctx:
            view('not-a-request', foo='bar')
        self.assertIn('Request object not found', str(ctx.exception))

    def test_wrong_http_method_returns_405(self):
        @request_method(['POST'])
        def view(request):
            return 'ok'
        resp = view(self.factory.get('/x'))
        self.assertIsInstance(resp, HttpResponseNotAllowed)
        self.assertEqual(resp.status_code, 405)

    def test_matching_method_calls_wrapped_function(self):
        @request_method(['POST', 'GET'])
        def view(request):
            return f'called with {request.method}'
        resp = view(self.factory.post('/x'))
        self.assertEqual(resp, 'called with POST')

    def test_request_found_among_multiple_args(self):
        @request_method(['GET'])
        def view(first, request, third=None):
            return request.method
        request = self.factory.get('/x')
        self.assertIsInstance(request, HttpRequest)
        result = view('first-positional', request, third='kw')
        self.assertEqual(result, 'GET')
