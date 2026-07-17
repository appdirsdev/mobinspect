"""URLs for the MobInspect Analytics app."""
from django.urls import path

from mobinspect.Analytics import views

app_name = 'analytics'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
]
