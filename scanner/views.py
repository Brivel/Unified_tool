import time
import os
import re
import requests
from datetime import datetime
from django.shortcuts import render
from django.views import View
from django.conf import settings
from .forms import ScanForm
from .models import ScanResult
from bs4 import BeautifulSoup
from .zap_mock import MockZAPScanner


def is_zap_available():
    """
    Vérifie si OWASP ZAP daemon est disponible
    """
    try:
        zap_url = getattr(settings, 'ZAP_DAEMON_URL', 'http://127.0.0.1:8080')
        response = requests.get(f"{zap_url}/JSON/core/view/version/", timeout=2)
        return response.status_code == 200
    except (requests.exceptions.RequestException, requests.exceptions.Timeout):
        return False


class HomeView(View):
    template_name = 'scanner/home.html'

    def get(self, request):
        form = ScanForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = ScanForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {'form': form})

        target = form.cleaned_data['target_url'].rstrip('/')
        max_depth = form.cleaned_data.get('max_depth', 5)
        scan_type = form.cleaned_data.get('scan_type', 'both')
        alert_level = form.cleaned_data.get('alert_level', 'LOW')
        scan_policy = form.cleaned_data.get('scan_policy', 'default')

        start_time = time.time()
        context = self.perform_zap_scan(target, max_depth, scan_type, alert_level, scan_policy)
        context['scan_duration'] = round(time.time() - start_time, 2)
        
        return render(request, 'scanner/result.html', context)


    def parse_alerts_from_html(self, html_report):
        """
        Parse le rapport HTML de ZAP pour extraire les alertes par risque
        """
        try:
            soup = BeautifulSoup(html_report, 'html.parser')
            
            high_count = len(soup.find_all('div', class_='risk-high')) or 0
            medium_count = len(soup.find_all('div', class_='risk-medium')) or 0
            low_count = len(soup.find_all('div', class_='risk-low')) or 0
            info_count = len(soup.find_all('div', class_='risk-info')) or 0
            
            # Chercher les nombres dans le rapport si ces classes n'existe pas
            if not high_count:
                match = re.search(r'High.*?(\d+)', html_report)
                if match:
                    high_count = int(match.group(1))
            
            if not medium_count:
                match = re.search(r'Medium.*?(\d+)', html_report)
                if match:
                    medium_count = int(match.group(1))
            
            if not low_count:
                match = re.search(r'Low.*?(\d+)', html_report)
                if match:
                    low_count = int(match.group(1))
            
            if not info_count:
                match = re.search(r'Info.*?(\d+)', html_report)
                if match:
                    info_count = int(match.group(1))
            
            return {
                'high_count': high_count,
                'medium_count': medium_count,
                'low_count': low_count,
                'info_count': info_count,
                'total_alerts': high_count + medium_count + low_count + info_count
            }
        except Exception as e:
            print(f"Erreur parsing alertes: {e}")
            return {
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0,
                'total_alerts': 0
            }

    def perform_mock_zap_scan(self, target, scan_type='both', alert_level='LOW'):
        """
        Effectue un scan avec le mock ZAP pour développement
        """
        try:
            print(f"[*] Utilisation du Mock ZAP pour: {target}")
            mock_scanner = MockZAPScanner(target)
            
            # Générer le rapport HTML
            html_report = mock_scanner.generate_html_report()
            
            # Récupérer les alertes
            alerts = mock_scanner.get_alerts_response()
            
            # Compter par risque
            high_count = len([a for a in alerts if a['riskcode'] == '3'])
            medium_count = len([a for a in alerts if a['riskcode'] == '2'])
            low_count = len([a for a in alerts if a['riskcode'] == '1'])
            info_count = len([a for a in alerts if a['riskcode'] == '0'])
            
            # Sauvegarder le rapport
            os.makedirs("reports", exist_ok=True)
            report_filename = f"zap_report_{int(time.time())}.html"
            report_path = os.path.join("reports", report_filename)
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_report)
            
            # Créer le résultat en base de données
            scan_result = ScanResult.objects.create(
                target_url=target,
                scan_type=scan_type,
                alert_level=alert_level,
                scan_policy='mock',
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                info_count=info_count,
                total_alerts=high_count + medium_count + low_count + info_count,
                urls_scanned=len(alerts),
                html_report=html_report,
                report_path=report_path,
            )
            
            return {
                'success': True,
                'target': target,
                'scan_type': scan_type,
                'alert_level': alert_level,
                'html_report': html_report,
                'report_path': report_path,
                'high_count': high_count,
                'medium_count': medium_count,
                'low_count': low_count,
                'info_count': info_count,
                'alert_count': high_count + medium_count + low_count + info_count,
                'urls_scanned': len(alerts),
                'scan_result_id': scan_result.id,
                'mode': 'mock'  # Indiquer que c'est un mock
            }
            
        except Exception as e:
            print(f"Erreur mock ZAP: {str(e)}")
            return {'error': f"Erreur lors du scan mock: {str(e)}"}

    def perform_zap_scan(self, target, max_depth=5, scan_type='both', alert_level='LOW', scan_policy='default'):
        """
        Exécute un test de sécurité avec OWASP ZAP ou utilise le mock si indisponible
        """
        # Vérifier si ZAP est disponible
        if not is_zap_available():
            print("[!] ZAP daemon non disponible, utilisation du mock")
            return self.perform_mock_zap_scan(target, scan_type, alert_level)
        
        try:
            # Récupérer les paramètres de configuration avec des valeurs par défaut
            base_url = getattr(settings, 'ZAP_DAEMON_URL', 'http://127.0.0.1:8080').rstrip('/')
            apikey = getattr(settings, 'ZAP_API_KEY', '')

            params = {}
            if apikey:
                params['apikey'] = apikey

            # 1. SPIDER (découverte)
            print(f"[*] Spider → {target}")
            spider_resp = requests.get(
                f"{base_url}/JSON/spider/action/scan/",
                params={**params, 'url': target, 'maxChildren': max_depth or None},
                timeout=30
            )
            spider_resp.raise_for_status()
            spider_id = spider_resp.json()['scan']

            # Attente spider
            while True:
                status_resp = requests.get(
                    f"{base_url}/JSON/spider/view/status/",
                    params={**params, 'scanId': spider_id},
                    timeout=15
                )
                status = int(status_resp.json()['status'])
                if status >= 100:
                    break
                time.sleep(2)
                print(f"[*] Spider progress: {status}%")

            # 2. PASSIVE SCAN (toujours actif)
            print("[*] Passive scan...")
            passive_scan_resp = requests.get(
                f"{base_url}/JSON/pscan/view/recordsToScan/",
                params=params,
                timeout=15
            )
            
            # Attendre les scans passifs
            time.sleep(5)

            # 3. ACTIVE SCAN (si demandé)
            ascan_id = None
            if scan_type in ['active', 'both']:
                print("[*] Active scan...")
                ascan_resp = requests.get(
                    f"{base_url}/JSON/ascan/action/scan/",
                    params={**params, 'url': target, 'recurse': 'true', 'scanPolicyName': scan_policy},
                    timeout=30
                )
                ascan_resp.raise_for_status()
                ascan_id = ascan_resp.json()['scan']

                # Attente active scan (avec timeout)
                start_time = time.time()
                max_wait = getattr(settings, 'ZAP_TIMEOUT', 300)  # 5 min par défaut
                
                while True:
                    status_resp = requests.get(
                        f"{base_url}/JSON/ascan/view/status/",
                        params={**params, 'scanId': ascan_id},
                        timeout=15
                    )
                    status = int(status_resp.json()['status'])
                    if status >= 100:
                        break
                    if time.time() - start_time > max_wait:
                        print("[!] Active scan timeout")
                        break
                    time.sleep(3)
                    print(f"[*] Active scan progress: {status}%")

            # 4. RÉCUPÉRER LES ALERTES
            print("[*] Fetching alerts...")
            alerts_resp = requests.get(
                f"{base_url}/JSON/core/view/alerts/",
                params={**params, 'baseurl': target},
                timeout=15
            )
            alerts_data = alerts_resp.json() if alerts_resp.ok else []

            # 5. RAPPORT HTML
            print("[*] Generating report...")
            report_resp = requests.get(
                f"{base_url}/OTHER/core/other/htmlreport/",
                params=params,
                timeout=30
            )
            report_resp.raise_for_status()
            html_report = report_resp.text

            # 6. SAUVEGARDER RAPPORT
            os.makedirs("reports", exist_ok=True)
            report_filename = f"zap_report_{int(time.time())}.html"
            report_path = os.path.join("reports", report_filename)
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_report)

            # 7. PARSER ET CRÉER CONTEXTE
            alert_counts = self.parse_alerts_from_html(html_report)
            
            # Enregistrer le résultat en BD
            urls_scanned = len(set([alert.get('url') for alert in alerts_data if isinstance(alert, dict)]))
            
            scan_result = ScanResult.objects.create(
                target_url=target,
                scan_type=scan_type,
                alert_level=alert_level,
                scan_policy=scan_policy,
                high_count=alert_counts['high_count'],
                medium_count=alert_counts['medium_count'],
                low_count=alert_counts['low_count'],
                info_count=alert_counts['info_count'],
                total_alerts=alert_counts['total_alerts'],
                urls_scanned=urls_scanned if urls_scanned > 0 else len(alerts_data),
                html_report=html_report,
                report_path=report_path,
            )

            return {
                'success': True,
                'target': target,
                'scan_type': scan_type,
                'alert_level': alert_level,
                'html_report': html_report,
                'report_path': report_path,
                'high_count': alert_counts['high_count'],
                'medium_count': alert_counts['medium_count'],
                'low_count': alert_counts['low_count'],
                'info_count': alert_counts['info_count'],
                'alert_count': alert_counts['total_alerts'],
                'urls_scanned': urls_scanned if urls_scanned > 0 else len(alerts_data),
                'scan_result_id': scan_result.id,
            }

        except requests.exceptions.Timeout:
            print("[!] ZAP timeout, basculement vers mock")
            return self.perform_mock_zap_scan(target, scan_type, alert_level)
        except requests.exceptions.ConnectionError:
            print("[!] ZAP connexion échouée, basculement vers mock")
            return self.perform_mock_zap_scan(target, scan_type, alert_level)
        except requests.exceptions.RequestException as e:
            print(f"[!] Erreur API ZAP: {str(e)}, basculement vers mock")
            return self.perform_mock_zap_scan(target, scan_type, alert_level)
        except Exception as e:
            print(f"[!] Erreur lors du scan ZAP: {str(e)}, basculement vers mock")
            return self.perform_mock_zap_scan(target, scan_type, alert_level)