from django.db import models
import json


class WHOISResult(models.Model):
    """
    Modèle pour stocker les résultats des recherches WHOIS
    """
    domain = models.CharField(max_length=255, unique=True)
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    country_from_tld = models.CharField(max_length=100, blank=True, default='')  # Pays identifié du TLD
    domain_info = models.JSONField()  # Stocke les données structurées
    raw_whois = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-updated_at']
        verbose_name_plural = "WHOIS Results"
    
    def __str__(self):
        return f"{self.domain} ({self.country_from_tld}) - {self.updated_at.strftime('%d/%m/%Y %H:%M:%S')}"

