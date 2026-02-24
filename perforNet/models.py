from django.db import models


class SpeedTestResult(models.Model):
    """
    Modèle pour stocker les résultats des tests de vitesse internet
    """
    download_speed = models.FloatField(help_text="Vitesse de téléchargement en Mbps")
    upload_speed = models.FloatField(help_text="Vitesse de téléchargement inversé en Mbps")
    ping = models.FloatField(help_text="Latence (ping) en ms")
    server_name = models.CharField(max_length=255, help_text="Nom du serveur de test")
    server_country = models.CharField(max_length=100, help_text="Pays du serveur")
    server_city = models.CharField(max_length=100, blank=True, help_text="Ville du serveur")
    isp = models.CharField(max_length=255, help_text="Fournisseur d'accès internet")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Résultat Test Vitesse"
        verbose_name_plural = "Résultats Tests Vitesse"
    
    def __str__(self):
        return f"Test {self.created_at.strftime('%d/%m/%Y %H:%M')} - DL: {self.download_speed:.2f} Mbps"
