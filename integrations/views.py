from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from .models import NucleiScan, PortScan, SSLTLSCert, APISecurityTest, CVELookup, IntegrationResult
from .services import NucleiService, PortScanService, SSLTLSService, APISecurityService, CVEService


def integrations_dashboard(request):
    """Dashboard des intégrations"""
    context = {
        'nuclei_scans': NucleiScan.objects.all()[:5],
        'port_scans': PortScan.objects.all()[:5],
        'ssl_checks': SSLTLSCert.objects.all()[:5],
        'api_tests': APISecurityTest.objects.all()[:5],
    }
    return render(request, 'integrations/dashboard.html', context)


# ============== NUCLEI ENDPOINTS ==============

@require_http_methods(["GET", "POST"])
def nuclei_scanner(request):
    """Nuclei Scanner View"""
    if request.method == 'POST':
        target = request.POST.get('target', '')
        if target:
            scan = NucleiService.start_scan(target)
            return redirect('integrations:nuclei_scan_detail', scan_id=scan.id)
    
    scans = NucleiScan.objects.all().order_by('-created_at')
    paginator = Paginator(scans, 10)
    page_number = request.GET.get('page', 1)
    scans = paginator.get_page(page_number)
    
    return render(request, 'integrations/nuclei.html', {'scans': scans})


def nuclei_scan_detail(request, scan_id):
    """Détail d'un scan Nuclei"""
    scan = NucleiScan.objects.get(id=scan_id)
    return render(request, 'integrations/nuclei_detail.html', {'scan': scan})


@require_http_methods(["GET"])
def api_nuclei_scan(request, scan_id):
    """API pour obtenir les détails d'un scan Nuclei"""
    try:
        scan = NucleiScan.objects.get(id=scan_id)
        return JsonResponse({
            'id': scan.id,
            'target': scan.target,
            'status': scan.status,
            'vulnerabilities': scan.vulnerabilities_found,
            'critical': scan.critical_count,
            'high': scan.high_count,
            'medium': scan.medium_count,
            'low': scan.low_count,
            'info': scan.info_count,
            'templates': scan.templates_used,
            'duration': scan.duration,
            'results': scan.results_json
        })
    except NucleiScan.DoesNotExist:
        return JsonResponse({'error': 'Scan not found'}, status=404)


# ============== PORT SCAN ENDPOINTS ==============

@require_http_methods(["GET", "POST"])
def port_scanner(request):
    """Port Scanner View"""
    if request.method == 'POST':
        target = request.POST.get('target', '')
        if target:
            scan = PortScanService.start_scan(target)
            return redirect('integrations:port_scan_detail', scan_id=scan.id)
    
    scans = PortScan.objects.all().order_by('-created_at')
    paginator = Paginator(scans, 10)
    page_number = request.GET.get('page', 1)
    scans = paginator.get_page(page_number)
    
    return render(request, 'integrations/port_scanner.html', {'scans': scans})


def port_scan_detail(request, scan_id):
    """Détail d'un scan de ports"""
    scan = PortScan.objects.get(id=scan_id)
    return render(request, 'integrations/port_scan_detail.html', {'scan': scan})


@require_http_methods(["GET"])
def api_port_scan(request, scan_id):
    """API pour obtenir les détails d'un scan de ports"""
    try:
        scan = PortScan.objects.get(id=scan_id)
        return JsonResponse({
            'id': scan.id,
            'target': scan.target,
            'status': scan.status,
            'open_ports': scan.open_ports_count,
            'closed_ports': scan.closed_ports_count,
            'filtered_ports': scan.filtered_ports_count,
            'ports_data': scan.ports_data,
            'os_detection': scan.os_detection,
            'duration': scan.duration
        })
    except PortScan.DoesNotExist:
        return JsonResponse({'error': 'Scan not found'}, status=404)


# ============== SSL/TLS ENDPOINTS ==============

@require_http_methods(["GET", "POST"])
def ssl_tls_checker(request):
    """SSL/TLS Checker View"""
    if request.method == 'POST':
        target = request.POST.get('target', '')
        port = request.POST.get('port', '443')
        if target:
            check = SSLTLSService.start_check(target, int(port))
            return redirect('integrations:ssl_check_detail', check_id=check.id)
    
    checks = SSLTLSCert.objects.all().order_by('-created_at')
    paginator = Paginator(checks, 10)
    page_number = request.GET.get('page', 1)
    checks = paginator.get_page(page_number)
    
    return render(request, 'integrations/ssl_tls.html', {'checks': checks})


def ssl_check_detail(request, check_id):
    """Détail d'une vérification SSL/TLS"""
    check = SSLTLSCert.objects.get(id=check_id)
    return render(request, 'integrations/ssl_tls_detail.html', {'check': check})


@require_http_methods(["GET"])
def api_ssl_check(request, check_id):
    """API pour obtenir les détails SSL/TLS"""
    try:
        check = SSLTLSCert.objects.get(id=check_id)
        return JsonResponse({
            'id': check.id,
            'target': check.target,
            'port': check.port,
            'status': check.status,
            'cert_valid': check.cert_valid,
            'common_name': check.common_name,
            'issuer': check.issuer,
            'ssl_rating': check.ssl_rating,
            'tls_versions': check.tls_versions,
            'cipher_suites': check.cipher_suites,
            'vulnerable_ciphers': check.vulnerable_ciphers,
            'security_issues': check.security_issues
        })
    except SSLTLSCert.DoesNotExist:
        return JsonResponse({'error': 'Check not found'}, status=404)


# ============== API SECURITY TEST ENDPOINTS ==============

@require_http_methods(["GET", "POST"])
def api_security_tester(request):
    """API Security Tester View"""
    if request.method == 'POST':
        api_url = request.POST.get('api_url', '')
        test_type = request.POST.get('test_type', 'auth')
        if api_url:
            test = APISecurityService.start_test(api_url, test_type)
            return redirect('integrations:api_test_detail', test_id=test.id)
    
    tests = APISecurityTest.objects.all().order_by('-created_at')
    paginator = Paginator(tests, 10)
    page_number = request.GET.get('page', 1)
    tests = paginator.get_page(page_number)
    
    context = {
        'tests': tests,
        'test_types': APISecurityTest.TEST_TYPE_CHOICES
    }
    return render(request, 'integrations/api_security.html', context)


def api_test_detail(request, test_id):
    """Détail d'un test de sécurité API"""
    test = APISecurityTest.objects.get(id=test_id)
    return render(request, 'integrations/api_test_detail.html', {'test': test})


@require_http_methods(["GET"])
def api_security_result(request, test_id):
    """API pour obtenir les résultats d'un test"""
    try:
        test = APISecurityTest.objects.get(id=test_id)
        return JsonResponse({
            'id': test.id,
            'api_url': test.api_url,
            'test_type': test.test_type,
            'status': test.status,
            'vulnerable': test.vulnerable,
            'issues_found': test.issues_found,
            'test_details': test.test_details,
            'recommendations': test.recommendations,
            'duration': test.duration
        })
    except APISecurityTest.DoesNotExist:
        return JsonResponse({'error': 'Test not found'}, status=404)


# ============== CVE LOOKUP ENDPOINTS ==============

@require_http_methods(["GET", "POST"])
def cve_lookup(request):
    """CVE Lookup View"""
    cves = []
    search_performed = False
    
    if request.method == 'GET' and request.GET.get('cve_id'):
        search_query = request.GET.get('cve_id', '')
        search_performed = True
        if search_query:
            cve = CVEService.search_cve(search_query)
            cves = [cve]
    
    if not cves:
        cves = CVELookup.objects.all().order_by('-publication_date')[:20]
    
    return render(request, 'integrations/cve_lookup.html', {
        'cves': cves,
        'search_performed': search_performed
    })


def cve_detail(request, cve_id):
    """Détail d'une CVE"""
    cve = CVELookup.objects.get(id=cve_id)
    return render(request, 'integrations/cve_detail.html', {'cve': cve})


@require_http_methods(["GET"])
def api_cve_search(request):
    """API pour rechercher une CVE"""
    cve_id = request.GET.get('cve_id', '')
    
    if not cve_id:
        return JsonResponse({'error': 'CVE ID required'}, status=400)
    
    try:
        cve = CVEService.search_cve(cve_id)
        return JsonResponse({
            'cve_id': cve.cve_id,
            'title': cve.title,
            'description': cve.description,
            'severity': cve.severity,
            'cvss_score': cve.cvss_score,
            'affected_versions': cve.affected_versions,
            'references': cve.references,
            'publication_date': cve.publication_date.isoformat() if cve.publication_date else None
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============== INTEGRATION REPORT ==============

@require_http_methods(["GET", "POST"])
def integration_report(request):
    """Rapport combiné de toutes les intégrations"""
    if request.method == 'POST':
        target = request.POST.get('target', '')
        if target:
            # Créer un rapport d'intégration complet
            nuclei_scan = NucleiService.start_scan(target)
            port_scan = PortScanService.start_scan(target)
            ssl_check = SSLTLSService.start_check(target)
            
            total_vulns = nuclei_scan.vulnerabilities_found + port_scan.open_ports_count
            critical = nuclei_scan.critical_count + (1 if port_scan.open_ports_count > 5 else 0)
            
            risk_level = 'critical' if critical > 5 else 'high' if total_vulns > 10 else 'medium' if total_vulns > 3 else 'low'
            
            report = IntegrationResult.objects.create(
                target=target,
                nuclei_scan=nuclei_scan,
                port_scan=port_scan,
                ssl_check=ssl_check,
                total_vulnerabilities=total_vulns,
                critical_issues=critical,
                risk_level=risk_level,
                report_generated=True
            )
            return redirect('integrations:report_detail', report_id=report.id)
    
    reports = IntegrationResult.objects.all().order_by('-created_at')
    return render(request, 'integrations/reports.html', {'reports': reports})


def report_detail(request, report_id):
    """Détail d'un rapport d'intégration"""
    report = IntegrationResult.objects.get(id=report_id)
    return render(request, 'integrations/report_detail.html', {'report': report})
