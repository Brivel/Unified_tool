from django.contrib import admin
from .models import ScanResult


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('target_url', 'scan_type', 'created_at', 'total_alerts', 'high_count', 'medium_count')
    list_filter = ('scan_type', 'alert_level', 'created_at')
    search_fields = ('target_url',)
    readonly_fields = ('created_at', 'updated_at', 'high_count', 'medium_count', 'low_count', 'info_count')
    
    fieldsets = (
        ('Informations du Scan', {
            'fields': ('target_url', 'scan_type', 'alert_level', 'scan_policy')
        }),
        ('Résultats', {
            'fields': ('high_count', 'medium_count', 'low_count', 'info_count', 'total_alerts', 'urls_scanned')
        }),
        ('Rapport', {
            'fields': ('report_path', 'scan_duration'),
            'classes': ('collapse',)
        }),
        ('Dates', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
