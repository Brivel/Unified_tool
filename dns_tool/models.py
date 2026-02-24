from django.db import models

# Create your models here.

class DNSQueryHistory(models.Model):
    domain = models.CharField(max_length=255)
    record_type = models.CharField(max_length=10)
    result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.domain} ({self.record_type})"
