from django.urls import path
from . import views

app_name = 'perforNet'

urlpatterns = [
    path('', views.home, name='home'),
    path('api/run-test/', views.run_speed_test, name='run_test'),
    path('api/progress/', views.get_progress, name='progress'),
    path('api/latest/', views.get_latest_result, name='latest'),
    path('api/history/', views.get_history, name='history'),
    path('export/', views.export_results, name='export'),
]
