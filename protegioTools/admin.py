from django.contrib import admin
from .models import WHOISResult


@admin.register(WHOISResult)
class WHOISResultAdmin(admin.ModelAdmin):
    list_display = ('domain', 'ip_address', 'updated_at', 'created_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('domain', 'ip_address')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Informations du Domaine', {
            'fields': ('domain', 'ip_address')
        }),
        ('Données WHOIS', {
            'fields': ('domain_info', 'raw_whois'),
            'classes': ('collapse',)
        }),
        ('Métadonnées', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
