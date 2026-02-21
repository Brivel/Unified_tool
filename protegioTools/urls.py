# project/recon/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('whois/', views.whois_view, name='whois'),
]