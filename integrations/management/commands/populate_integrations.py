from django.core.management.base import BaseCommand
from integrations.models import (
    NucleiScan, PortScan, SSLTLSCert, 
    APISecurityTest, CVELookup
)
from integrations.services import (
    NucleiService, PortScanService, SSLTLSService,
    APISecurityService, CVEService
)


class Command(BaseCommand):
    help = 'Crée des données de test pour les intégrations'

    def handle(self, *args, **options):
        self.stdout.write("🔄 Création des données de test...\n")

        # Créer des scans Nuclei
        self.stdout.write("📌 Création 3 scans Nuclei...")
        for i in range(3):
            target = f"example{i+1}.com"
            scan = NucleiService.start_scan(target)
            self.stdout.write(f"   ✓ Scan Nuclei créé: {scan.target} (ID: {scan.id})")

        # Créer des scans de ports
        self.stdout.write("\n📌 Création 3 scans de ports...")
        for i in range(3):
            target = f"192.168.1.{10+i}"
            scan = PortScanService.start_scan(target)
            self.stdout.write(f"   ✓ Scan Port créé: {scan.target} (ID: {scan.id})")

        # Créer des vérifications SSL/TLS
        self.stdout.write("\n📌 Création 3 vérifications SSL/TLS...")
        for i in range(3):
            target = f"secure{i+1}.com"
            check = SSLTLSService.start_check(target, 443)
            self.stdout.write(f"   ✓ Vérification SSL créée: {check.target} (ID: {check.id})")

        # Créer des tests API Security
        self.stdout.write("\n📌 Création 3 tests API Security...")
        test_types = ['auth', 'rate_limit', 'injection']
        for i, test_type in enumerate(test_types):
            api_url = f"https://api{i+1}.example.com/v1"
            test = APISecurityService.start_test(api_url, test_type)
            self.stdout.write(f"   ✓ Test API créé: {test.api_url} (type: {test_type}, ID: {test.id})")

        # Créer des recherches CVE
        self.stdout.write("\n📌 Création 3 recherches CVE...")
        cveids = ['CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9012']
        for cve in cveids:
            lookup = CVEService.search_cve(cve)
            self.stdout.write(f"   ✓ Recherche CVE créée: {lookup.cve_id} (ID: {lookup.id})")

        self.stdout.write("\n✅ Toutes les données de test ont été créées!")
        self.stdout.write("\nRésumé:")
        self.stdout.write(f"   • {NucleiScan.objects.count()} scans Nuclei")
        self.stdout.write(f"   • {PortScan.objects.count()} scans de ports")
        self.stdout.write(f"   • {SSLTLSCert.objects.count()} vérifications SSL/TLS")
        self.stdout.write(f"   • {APISecurityTest.objects.count()} tests API")
        self.stdout.write(f"   • {CVELookup.objects.count()} recherches CVE")
