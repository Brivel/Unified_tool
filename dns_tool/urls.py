from django.urls import path
from django.views.generic import RedirectView
from .views import NslookupView, DigView

urlpatterns = [
    path('', RedirectView.as_view(url='nslookup/', permanent=False), name='dns_home'),
    path('nslookup/', NslookupView.as_view(), name='nslookup'),
    path('dig/', DigView.as_view(), name='dig'),
]
