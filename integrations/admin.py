from django.contrib import admin
from .models import NucleiScan, PortScan, SSLTLSCert, APISecurityTest, CVELookup, IntegrationResult


@admin.register(NucleiScan)
class NucleiScanAdmin(admin.ModelAdmin):
    list_display = ('target', 'status', 'vulnerabilities_found', 'critical_count', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('target',)
    ordering = ('-created_at',)


@admin.register(PortScan)
class PortScanAdmin(admin.ModelAdmin):
    list_display = ('target', 'status', 'open_ports_count', 'host_status', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('target',)
    ordering = ('-created_at',)


@admin.register(SSLTLSCert)
class SSLTLSCertAdmin(admin.ModelAdmin):
    list_display = ('target', 'port', 'cert_valid', 'ssl_rating', 'created_at')
    list_filter = ('cert_valid', 'ssl_rating', 'created_at')
    search_fields = ('target', 'common_name')
    ordering = ('-created_at',)


@admin.register(APISecurityTest)
class APISecurityTestAdmin(admin.ModelAdmin):
    list_display = ('api_url', 'test_type', 'vulnerable', 'status', 'created_at')
    list_filter = ('test_type', 'vulnerable', 'status', 'created_at')
    search_fields = ('api_url',)
    ordering = ('-created_at',)


@admin.register(CVELookup)
class CVELookupAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'severity', 'cvss_score', 'publication_date')
    list_filter = ('severity', 'publication_date')
    search_fields = ('cve_id', 'title', 'description')
    ordering = ('-publication_date',)


@admin.register(IntegrationResult)
class IntegrationResultAdmin(admin.ModelAdmin):
    list_display = ('target', 'risk_level', 'total_vulnerabilities', 'report_generated', 'created_at')
    list_filter = ('risk_level', 'report_generated', 'created_at')
    search_fields = ('target',)
    ordering = ('-created_at',)
