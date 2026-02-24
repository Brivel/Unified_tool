from django.db import models
from django.utils import timezone


class ScanResult(models.Model):
    """
    Modèle pour stocker les résultats des scans ZAP
    """
    RISK_LEVELS = [
        ('HIGH', 'Élevé'),
        ('MEDIUM', 'Moyen'),
        ('LOW', 'Faible'),
        ('INFO', 'Info'),
    ]
    
    SCAN_TYPES = [
        ('passive', 'Scan Passif'),
        ('active', 'Scan Actif'),
        ('both', 'Passif + Actif'),
    ]
    
    target_url = models.URLField()
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES, default='both')
    alert_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='LOW')
    scan_policy = models.CharField(max_length=50, default='default')
    
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    total_alerts = models.IntegerField(default=0)
    
    urls_scanned = models.IntegerField(default=0)
    scan_duration = models.FloatField(default=0.0, help_text="Durée du scan en secondes")
    
    html_report = models.TextField(blank=True)
    report_path = models.CharField(max_length=255, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Résultat Scan ZAP"
        verbose_name_plural = "Résultats Scans ZAP"
    
    def __str__(self):
        return f"{self.target_url} - {self.created_at.strftime('%d/%m/%Y %H:%M')}"
