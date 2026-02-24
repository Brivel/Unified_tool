from django.urls import path
from .views import intruder_view

urlpatterns = [
    path('', intruder_view, name='intruder'),
]