from django.contrib import admin
from .models import SpeedTestResult


@admin.register(SpeedTestResult)
class SpeedTestResultAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'download_speed', 'upload_speed', 'ping', 'server_name', 'server_country', 'isp')
    list_filter = ('created_at', 'server_country')
    search_fields = ('server_name', 'isp', 'server_country')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Résultats de Vitesse', {
            'fields': ('download_speed', 'upload_speed', 'ping')
        }),
        ('Informations du Serveur', {
            'fields': ('server_name', 'server_country', 'server_city', 'isp')
        }),
        ('Dates', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
