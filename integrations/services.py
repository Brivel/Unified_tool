"""
Intégrations d'outils de sécurité avancés
"""
import json
import random
from datetime import datetime, timedelta
from .models import NucleiScan, PortScan, SSLTLSCert, APISecurityTest, CVELookup


class NucleiService:
    """Service pour les scans Nuclei (template-based)"""
    
    @staticmethod
    def start_scan(target, templates_count=50):
        """Démarrer un scan Nuclei"""
        scan = NucleiScan.objects.create(
            target=target,
            status='pending',
            templates_used=templates_count
        )
        
        # Simuler un scan Nuclei
        NucleiService._run_mock_scan(scan)
        return scan
    
    @staticmethod
    def _run_mock_scan(scan):
        """Exécuter un scan Nuclei simulé"""
        scan.status = 'running'
        scan.save()
        
        # Simuler les résultats
        critical = random.randint(0, 3)
        high = random.randint(1, 5)
        medium = random.randint(2, 8)
        low = random.randint(1, 10)
        info = random.randint(5, 15)
        
        total = critical + high + medium + low + info
        
        results = []
        for i in range(total):
            severity_choices = ['critical'] * critical + ['high'] * high + ['medium'] * medium + ['low'] * low + ['info'] * info
            severity = severity_choices[i]
            
            results.append({
                'template': f'template-{i+1}',
                'type': ['sql-injection', 'xss', 'path-traversal', 'rce', 'auth-bypass', 'weak-crypto'][i % 6],
                'severity': severity,
                'matched_at': f'http://{scan.target}/page{i}',
                'extracted_values': ['value1', 'value2']
            })
        
        scan.critical_count = critical
        scan.high_count = high
        scan.medium_count = medium
        scan.low_count = low
        scan.info_count = info
        scan.vulnerabilities_found = total
        scan.results_json = {'results': results}
        scan.status = 'completed'
        scan.duration = random.randint(30, 120)
        scan.save()


class PortScanService:
    """Service pour les scans de ports Nmap"""
    
    @staticmethod
    def start_scan(target):
        """Démarrer un scan de ports"""
        scan = PortScan.objects.create(
            target=target,
            status='pending',
            host_status='up'
        )
        
        PortScanService._run_mock_scan(scan)
        return scan
    
    @staticmethod
    def _run_mock_scan(scan):
        """Exécuter un scan de ports simulé"""
        scan.status = 'scanning'
        scan.save()
        
        # Simuler les résultats des ports ouverts
        common_ports = [80, 443, 22, 8080, 3306, 5432, 5900, 21, 25, 53, 3389, 27017]
        open_ports = random.sample(common_ports, random.randint(2, 8))
        
        ports_data = {}
        services = {
            80: 'http',
            443: 'https',
            22: 'ssh',
            8080: 'http-alt',
            3306: 'mysql',
            5432: 'postgresql',
            21: 'ftp',
            25: 'smtp',
            53: 'dns',
            3389: 'rdp',
            5900: 'vnc',
            27017: 'mongodb'
        }
        
        for port in open_ports:
            ports_data[str(port)] = {
                'state': 'open',
                'service': services.get(port, 'unknown'),
                'version': f'v{random.randint(1, 10)}.{random.randint(0, 20)}'
            }
        
        scan.open_ports_count = len(open_ports)
        scan.closed_ports_count = random.randint(5, 20)
        scan.filtered_ports_count = random.randint(5, 15)
        scan.ports_data = ports_data
        scan.os_detection = random.choice(['Linux 5.x', 'Windows Server 2019', 'MacOS', 'FreeBSD'])
        scan.status = 'completed'
        scan.duration = random.randint(60, 300)
        scan.save()


class SSLTLSService:
    """Service pour l'analyse SSL/TLS"""
    
    @staticmethod
    def start_check(target, port=443):
        """Démarrer une vérification SSL/TLS"""
        check = SSLTLSCert.objects.create(
            target=target,
            port=port,
            status='pending'
        )
        
        SSLTLSService._run_mock_check(check)
        return check
    
    @staticmethod
    def _run_mock_check(check):
        """Exécuter une vérification SSL/TLS simulée"""
        check.status = 'checking'
        check.save()
        
        # Simuler les données de certificat
        is_valid = random.choice([True, False, False])  # ~67% invalides pour réalisme
        
        check.cert_valid = is_valid
        check.common_name = check.target
        check.subject_alt_names = [check.target, f'*.{check.target}']
        check.issuer = random.choice(['Let\'s Encrypt', 'DigiCert', 'Sectigo', 'GoDaddy', 'Self-Signed'])
        
        not_before = datetime.now() - timedelta(days=random.randint(30, 365))
        not_after = datetime.now() + timedelta(days=random.randint(1, 365))
        
        check.not_before = not_before
        check.not_after = not_after
        check.serial_number = format(random.getrandbits(128), '032x')
        
        # TLS Versions
        tls_versions = []
        if is_valid:
            tls_versions = random.sample(['TLS 1.2', 'TLS 1.3'], random.randint(1, 2))
        else:
            tls_versions = random.sample(['SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2'], random.randint(1, 4))
        check.tls_versions = tls_versions
        
        # Cipher Suites
        ciphers = [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-SHA'
        ]
        check.cipher_suites = random.sample(ciphers, random.randint(1, len(ciphers)))
        
        # Vulnerable ciphers
        vulnerable = ['DES-CBC3-SHA', 'RC4-SHA', 'MD5'] if not is_valid else []
        check.vulnerable_ciphers = vulnerable
        
        # Rating
        if is_valid and not vulnerable:
            check.ssl_rating = 'A+'
            issues = []
        elif is_valid:
            check.ssl_rating = random.choice(['A', 'B', 'C'])
            issues = ['Weak ciphers detected', 'Old TLS version supported']
        else:
            check.ssl_rating = random.choice(['D', 'E', 'F'])
            issues = ['Self-signed certificate', 'Expired certificate', 'Very weak ciphers']
        
        check.security_issues = issues
        check.status = 'completed'
        check.save()


class APISecurityService:
    """Service pour les tests de sécurité API"""
    
    TEST_TYPES = {
        'auth': 'Authentication',
        'rate_limit': 'Rate Limiting',
        'injection': 'Injection Attacks',
        'cors': 'CORS Policy',
        'headers': 'Security Headers'
    }
    
    @staticmethod
    def start_test(api_url, test_type='auth'):
        """Démarrer un test de sécurité API"""
        test = APISecurityTest.objects.create(
            api_url=api_url,
            test_type=test_type,
            status='pending'
        )
        
        APISecurityService._run_mock_test(test)
        return test
    
    @staticmethod
    def _run_mock_test(test):
        """Exécuter un test de sécurité API simulé"""
        test.status = 'testing'
        test.save()
        
        # Simuler les résultats selon le type de test
        test_details = {}
        issues = []
        
        if test.test_type == 'auth':
            test_details = {
                'authentication_method': random.choice(['Bearer Token', 'API Key', 'OAuth 2.0', 'None']),
                'token_expiration': random.choice([True, False]),
                'password_requirements': 'Weak' if random.random() < 0.3 else 'Strong',
                'brute_force_protection': random.choice([True, False])
            }
            if not test_details['brute_force_protection']:
                issues.append('No brute force protection detected')
        
        elif test.test_type == 'rate_limit':
            test_details = {
                'rate_limiting_enabled': random.choice([True, False]),
                'requests_per_minute': random.randint(60, 1000),
                'rate_limit_headers': random.choice([True, False])
            }
            if not test_details['rate_limiting_enabled']:
                issues.append('No rate limiting detected - susceptible to DDoS')
        
        elif test.test_type == 'injection':
            test_details = {
                'sql_injection_vulnerable': random.choice([True, False]),
                'cmd_injection_vulnerable': random.choice([True, False]),
                'xss_vulnerable': random.choice([True, False])
            }
            for key, value in test_details.items():
                if value:
                    issues.append(f'{key.replace("_", " ").title()} vulnerability found')
        
        elif test.test_type == 'cors':
            test_details = {
                'cors_enabled': random.choice([True, False]),
                'allowed_origins': ['*'] if random.random() < 0.3 else ['https://api.example.com'],
                'credentials_allowed': random.choice([True, False])
            }
            if '*' in test_details['allowed_origins']:
                issues.append('CORS allows all origins (wildcard)')
        
        elif test.test_type == 'headers':
            test_details = {
                'content_security_policy': random.choice([True, False]),
                'x_frame_options': random.choice([True, False]),
                'x_content_type_options': random.choice([True, False]),
                'strict_transport_security': random.choice([True, False])
            }
            for header, present in test_details.items():
                if not present:
                    issues.append(f'Missing {header.replace("_", "-").title()} header')
        
        test.vulnerable = len(issues) > 0
        test.issues_found = len(issues)
        test.test_details = test_details
        test.recommendations = APISecurityService._get_recommendations(test_type=test.test_type, issues=issues)
        test.status = 'completed'
        test.duration = random.randint(10, 60)
        test.save()
    
    @staticmethod
    def _get_recommendations(test_type, issues):
        """Obtenir les recommandations basées sur les problèmes trouvés"""
        recommendations = {
            'auth': [
                'Implement strong password policies (min 12 characters, complexity)',
                'Use OAuth 2.0 or JWT for API authentication',
                'Implement token expiration and refresh mechanisms',
                'Add rate limiting and brute force protection'
            ],
            'rate_limit': [
                'Implement rate limiting (e.g., 100 requests/min per IP)',
                'Add rate limit headers (X-RateLimit-* headers)',
                'Use exponential backoff for API clients'
            ],
            'injection': [
                'Use parameterized queries for SQL',
                'Implement input validation and sanitization',
                'Use ORM frameworks to prevent injection attacks'
            ],
            'cors': [
                'Specify explicit allowed origins instead of wildcard',
                'Only allow credentials when necessary',
                'Validate preflight requests properly'
            ],
            'headers': [
                'Implement Content-Security-Policy header',
                'Add X-Frame-Options: DENY',
                'Set X-Content-Type-Options: nosniff',
                'Implement HSTS header for HTTPS enforcement'
            ]
        }
        return recommendations.get(test_type, [])


class CVEService:
    """Service pour la recherche CVE"""
    
    @staticmethod
    def search_cve(cve_id_or_query):
        """Rechercher une CVE"""
        # Vérifier si c'est déjà en DB
        try:
            cve = CVELookup.objects.get(cve_id=cve_id_or_query)
            return cve
        except CVELookup.DoesNotExist:
            return CVEService._create_mock_cve(cve_id_or_query)
    
    @staticmethod
    def _create_mock_cve(cve_id):
        """Créer une CVE simulée"""
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        severity = random.choice(severities)
        cvss_map = {'CRITICAL': 9.5, 'HIGH': 8.2, 'MEDIUM': 5.5, 'LOW': 3.2}
        
        cve_data = CVELookup(
            cve_id=cve_id,
            title=f'Security Vulnerability in {cve_id}',
            description=f'This is a {severity} severity vulnerability affecting multiple systems. Remote attackers could potentially exploit this vulnerability to gain unauthorized access.',
            severity=severity,
            cvss_score=cvss_map[severity],
            affected_versions=['1.0.0', '1.1.0', '1.2.0', '2.0.0'],
            references=[
                'https://nvd.nist.gov/vuln/detail/' + cve_id,
                'https://github.com/advisories/' + cve_id.replace('-', '') 
            ],
            publication_date=datetime.now().date() - timedelta(days=random.randint(1, 365))
        )
        cve_data.save()
        return cve_data
