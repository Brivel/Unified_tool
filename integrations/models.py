from django.db import models
from django.utils import timezone


class NucleiScan(models.Model):
    """Résultats des scans Nuclei (template-based vulnerability scanner)"""
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('running', 'En cours'),
        ('completed', 'Complété'),
        ('failed', 'Erreur'),
    ]
    
    target = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    templates_used = models.IntegerField(default=0, help_text="Nombre de templates Nuclei utilisés")
    vulnerabilities_found = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    results_json = models.JSONField(default=dict, blank=True)
    duration = models.IntegerField(default=0, help_text="Durée en secondes")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Nuclei Scan - {self.target} ({self.status})"


class CVELookup(models.Model):
    """Résultats de recherche CVE"""
    cve_id = models.CharField(max_length=20, unique=True)  # e.g., "CVE-2024-1234"
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20)  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score = models.FloatField(null=True, blank=True)
    affected_versions = models.JSONField(default=list, blank=True)
    references = models.JSONField(default=list, blank=True)
    publication_date = models.DateField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-publication_date']
    
    def __str__(self):
        return f"{self.cve_id} - {self.title}"


class PortScan(models.Model):
    """Résultats des scans de ports Nmap"""
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('scanning', 'Scan en cours'),
        ('completed', 'Complété'),
        ('failed', 'Erreur'),
    ]
    
    target = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    open_ports_count = models.IntegerField(default=0)
    closed_ports_count = models.IntegerField(default=0)
    filtered_ports_count = models.IntegerField(default=0)
    ports_data = models.JSONField(default=dict, blank=True)  # {port: {state, service, version}}
    os_detection = models.CharField(max_length=255, blank=True)
    host_status = models.CharField(max_length=50)  # up/down
    duration = models.IntegerField(default=0, help_text="Durée du scan en secondes")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Port Scan - {self.target} ({self.open_ports_count} ports ouvert)"


class SSLTLSCert(models.Model):
    """Résultats d'analyse SSL/TLS"""
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('checking', 'Vérification'),
        ('completed', 'Complété'),
        ('failed', 'Erreur'),
    ]
    
    target = models.CharField(max_length=255)
    port = models.IntegerField(default=443)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Certificat
    cert_valid = models.BooleanField(default=False)
    common_name = models.CharField(max_length=255, blank=True)
    subject_alt_names = models.JSONField(default=list, blank=True)
    issuer = models.CharField(max_length=255, blank=True)
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)
    serial_number = models.CharField(max_length=255, blank=True)
    
    # SSL/TLS
    tls_versions = models.JSONField(default=list, blank=True)  # ['TLS 1.2', 'TLS 1.3']
    cipher_suites = models.JSONField(default=list, blank=True)
    vulnerable_ciphers = models.JSONField(default=list, blank=True)
    
    # Scores/Rating
    ssl_rating = models.CharField(max_length=2, blank=True)  # A+, A, B, C, D, E, F
    security_issues = models.JSONField(default=list, blank=True)
    
    results_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"SSL/TLS - {self.target}:{self.port}"


class APISecurityTest(models.Model):
    """Résultats de test de sécurité API"""
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('testing', 'Test en cours'),
        ('completed', 'Complété'),
        ('failed', 'Erreur'),
    ]
    
    TEST_TYPE_CHOICES = [
        ('auth', 'Authentication'),
        ('rate_limit', 'Rate Limiting'),
        ('injection', 'Injection Attacks'),
        ('cors', 'CORS Policy'),
        ('headers', 'Security Headers'),
    ]
    
    api_url = models.URLField()
    test_type = models.CharField(max_length=20, choices=TEST_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Résultats du test
    vulnerable = models.BooleanField(default=False)
    issues_found = models.IntegerField(default=0)
    test_details = models.JSONField(default=dict, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    
    duration = models.IntegerField(default=0, help_text="Durée du test en secondes")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"API Test - {self.test_type} on {self.api_url}"


class IntegrationResult(models.Model):
    """Résumé de tous les résultats d'intégration pour un audit"""
    nuclei_scan = models.ForeignKey(NucleiScan, on_delete=models.SET_NULL, null=True, blank=True)
    port_scan = models.ForeignKey(PortScan, on_delete=models.SET_NULL, null=True, blank=True)
    ssl_check = models.ForeignKey(SSLTLSCert, on_delete=models.SET_NULL, null=True, blank=True)
    
    target = models.CharField(max_length=255)
    total_vulnerabilities = models.IntegerField(default=0)
    critical_issues = models.IntegerField(default=0)
    risk_level = models.CharField(
        max_length=20,
        choices=[('critical', 'Critique'), ('high', 'Élevé'), ('medium', 'Moyen'), ('low', 'Bas')],
        default='low'
    )
    
    report_generated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Integration Audit - {self.target}"
