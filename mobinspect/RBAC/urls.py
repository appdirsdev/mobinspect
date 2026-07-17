"""URL conf for the RBAC admin UI."""
from django.urls import path

from mobinspect.RBAC import views

app_name = 'rbac'

urlpatterns = [
    path('roles/',                          views.roles_list,         name='roles_list'),
    path('roles/new/',                      views.role_create,        name='role_create'),
    path('roles/<int:role_id>/',            views.role_edit,          name='role_edit'),
    path('roles/<int:role_id>/delete/',     views.role_delete,        name='role_delete'),
    path('roles/<int:role_id>/assign/',     views.role_assign,        name='role_assign'),
    path('roles/<int:role_id>/unassign/<int:user_id>/',
         views.role_unassign, name='role_unassign'),

    path('permissions/',                    views.permissions_browse, name='permissions'),

    path('api-keys/',                       views.api_keys,           name='api_keys'),
    path('api-keys/<int:key_id>/revoke/',   views.api_key_revoke,     name='api_key_revoke'),

    path('audit/',                          views.audit_log,          name='audit_log'),

    # Integrations · ADB connections
    path('integrations/adb/',
         views.adb_connections_list, name='adb_connections'),
    # Fixed-box save/test (Android + iOS device cards)
    path('integrations/device/<slug:platform>/save/',
         views.device_save, name='device_save'),
    path('integrations/device/<slug:platform>/test/',
         views.device_test_key, name='device_test'),
    path('integrations/adb/add/',
         views.adb_connection_add, name='adb_connection_add'),
    path('integrations/adb/<int:conn_id>/remove/',
         views.adb_connection_remove, name='adb_connection_remove'),
    path('integrations/adb/<int:conn_id>/set-active/',
         views.adb_connection_set_active, name='adb_connection_set_active'),
    path('integrations/adb/<int:conn_id>/test/',
         views.adb_connection_test, name='adb_connection_test'),

    # Integrations · AI model endpoints
    # Legacy by-id routes FIRST so integer ids bind to the <int> converter
    # (the <slug:role> routes below also match pure-digit segments, which would
    # otherwise shadow these and make them unreachable via the URL router).
    path('integrations/model/add/',
         views.model_integration_add, name='model_integration_add'),
    path('integrations/model/<int:integ_id>/remove/',
         views.model_integration_remove, name='model_integration_remove'),
    path('integrations/model/<int:integ_id>/set-active/',
         views.model_integration_set_active, name='model_integration_set_active'),
    path('integrations/model/<int:integ_id>/test/',
         views.model_integration_test, name='model_integration_test'),
    # Fixed-box save/test (Generation + Classification model cards)
    path('integrations/model/<slug:role>/save/',
         views.model_save, name='model_save'),
    path('integrations/model/<slug:role>/test/',
         views.model_test_key, name='model_test'),
]
