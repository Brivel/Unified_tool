#!/usr/bin/env python
"""
Script pour créer des données de test pour les intégrations
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, '/c/Users/Harol/Desktop/Unified_tool/unified_tool')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'unified_tool.settings')
django.setup()

from integrations.models import (
    NucleiScan, PortScan, SSLTLSCert, 
    APISecurityTest, CVELookup, IntegrationResult
)
from integrations.services import (
    NucleiService, PortScanService, SSLTLSService,
    APISecurityService, CVEService
)
import random
from datetime import datetime, timedelta

print("🔄 Création des données de test...")

# Créer des scans Nuclei
print("\n📌 Création 3 scans Nuclei...")
for i in range(3):
    target = f"example{i+1}.com"
    scan = NucleiService.start_scan(target)
    print(f"   • Scan Nuclei créé: {scan.target} (ID: {scan.id})")

# Créer des scans de ports
print("\n📌 Création 3 scans de ports...")
for i in range(3):
    target = f"192.168.1.{10+i}"
    scan = PortScanService.start_scan(target)
    print(f"   • Scan Port créé: {scan.target} (ID: {scan.id})")

# Créer des vérifications SSL/TLS
print("\n📌 Création 3 vérifications SSL/TLS...")
for i in range(3):
    target = f"secure{i+1}.com"
    check = SSLTLSService.start_check(target, 443)
    print(f"   • Vérification SSL créée: {check.domain} (ID: {check.id})")

# Créer des tests API Security
print("\n📌 Création 3 tests API Security...")
for i in range(3):
    api_url = f"https://api{i+1}.example.com/v1"
    test = APISecurityService.start_test(api_url)
    print(f"   • Test API créé: {test.api_url} (ID: {test.id})")

# Créer des recherches CVE
print("\n📌 Création 3 recherches CVE...")
cveids = ['CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9012']
for cve in cveids:
    lookup = CVEService.search_cve(cve)
    print(f"   • Recherche CVE créée: {lookup.cve_id} (ID: {lookup.id})")

print("\n✅ Toutes les données de test ont été créées!")
print("\nRésumé:")
print(f"   • {NucleiScan.objects.count()} scans Nuclei")
print(f"   • {PortScan.objects.count()} scans de ports")
print(f"   • {SSLTLSCert.objects.count()} vérifications SSL/TLS")
print(f"   • {APISecurityTest.objects.count()} tests API")
print(f"   • {CVELookup.objects.count()} recherches CVE")
