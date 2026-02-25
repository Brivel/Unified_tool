from django.db import models

class NucleiScan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    target = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    vulnerabilities_found = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    results = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"NucleiScan: {self.target}"


class PortScan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    target = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    open_ports_count = models.IntegerField(default=0)
    host_status = models.CharField(max_length=50, default='unknown')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    results = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"PortScan: {self.target}"


class SSLTLSCert(models.Model):
    target = models.CharField(max_length=255)
    port = models.IntegerField(default=443)
    cert_valid = models.BooleanField(default=False)
    ssl_rating = models.CharField(max_length=50, default='unknown')
    common_name = models.CharField(max_length=255, blank=True, null=True)
    issuer = models.CharField(max_length=255, blank=True, null=True)
    subject_alt_names = models.TextField(blank=True, null=True)
    valid_from = models.DateTimeField(blank=True, null=True)
    valid_to = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"SSLTLSCert: {self.target}:{self.port}"


class APISecurityTest(models.Model):
    TEST_TYPE_CHOICES = [
        ('auth', 'Authentication'),
        ('injection', 'Injection'),
        ('xss', 'Cross-Site Scripting'),
        ('cors', 'CORS'),
        ('other', 'Other'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    api_url = models.CharField(max_length=255)
    test_type = models.CharField(max_length=50, choices=TEST_TYPE_CHOICES)
    vulnerable = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    severity = models.CharField(max_length=50, blank=True, null=True)
    findings = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"APISecurityTest: {self.api_url}"


class CVELookup(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('unknown', 'Unknown'),
    ]
    
    cve_id = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='unknown')
    cvss_score = models.FloatField(blank=True, null=True)
    publication_date = models.DateField(blank=True, null=True)
    affected_software = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-publication_date']

    def __str__(self):
        return f"CVELookup: {self.cve_id}"


class IntegrationResult(models.Model):
    RISK_LEVEL_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    target = models.CharField(max_length=255)
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES)
    total_vulnerabilities = models.IntegerField(default=0)
    critical_vulnerabilities = models.IntegerField(default=0)
    high_vulnerabilities = models.IntegerField(default=0)
    medium_vulnerabilities = models.IntegerField(default=0)
    low_vulnerabilities = models.IntegerField(default=0)
    report_generated = models.BooleanField(default=False)
    report_file = models.FileField(upload_to='reports/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    summary = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"IntegrationResult: {self.target} - {self.risk_level}"
