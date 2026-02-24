from django.urls import path
from . import views

app_name = 'integrations'

urlpatterns = [
    # Dashboard
    path('', views.integrations_dashboard, name='dashboard'),
    
    # Nuclei Scanner
    path('nuclei/', views.nuclei_scanner, name='nuclei'),
    path('nuclei/<int:scan_id>/', views.nuclei_scan_detail, name='nuclei_scan_detail'),
    path('api/nuclei/<int:scan_id>/', views.api_nuclei_scan, name='api_nuclei'),
    
    # Port Scanner
    path('ports/', views.port_scanner, name='ports'),
    path('ports/<int:scan_id>/', views.port_scan_detail, name='port_scan_detail'),
    path('api/ports/<int:scan_id>/', views.api_port_scan, name='api_ports'),
    
    # SSL/TLS Checker
    path('ssl/', views.ssl_tls_checker, name='ssl'),
    path('ssl/<int:check_id>/', views.ssl_check_detail, name='ssl_check_detail'),
    path('api/ssl/<int:check_id>/', views.api_ssl_check, name='api_ssl'),
    
    # API Security
    path('api-security/', views.api_security_tester, name='api_security'),
    path('api-security/<int:test_id>/', views.api_test_detail, name='api_test_detail'),
    path('api/api-security/<int:test_id>/', views.api_security_result, name='api_security_result'),
    
    # CVE Lookup
    path('cve/', views.cve_lookup, name='cve'),
    path('cve/<int:cve_id>/', views.cve_detail, name='cve_detail'),
    path('api/cve/', views.api_cve_search, name='api_cve'),
    
    # Reports
    path('reports/', views.integration_report, name='reports'),
    path('reports/<int:report_id>/', views.report_detail, name='report_detail'),
]
