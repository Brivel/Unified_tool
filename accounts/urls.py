from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    
    # User Profile
    path('profile/', views.profile_view, name='profile'),
    path('activity/', views.activity_log_view, name='activity_log'),
    path('scans/', views.scan_history_view, name='scan_history'),
    
    # Admin pages
    path('admin/users/', views.admin_users_view, name='admin_users'),
    path('admin/audit-logs/', views.admin_audit_log_view, name='admin_audit_log'),
    
    # APIs
    path('api/audit-stats/', views.get_audit_stats_api, name='audit_stats_api'),
]
