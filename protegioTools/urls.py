# project/recon/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('whois/', views.whois_view, name='whois'),
    path('export/word/', views.export_word, name='export_word'),
    path('export/excel/', views.export_excel, name='export_excel'),
    path('export/all/word/', views.export_all_word, name='export_all_word'),
    path('export/all/excel/', views.export_all_excel, name='export_all_excel'),
]