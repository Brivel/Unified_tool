import time
import os
import requests
from django.shortcuts import render
from django.views import View
from django.conf import settings
from django import forms

# Formulaire (on le met ici pour que le fichier soit autonome)
class ScanForm(forms.Form):
    target_url = forms.URLField(
        label="URL à scanner",
        widget=forms.URLInput(attrs={'placeholder': 'https://example.com', 'class': 'form-control'}),
        required=True
    )
    max_depth = forms.IntegerField(
        label="Profondeur max du spider (0 = illimité)",
        initial=5,
        min_value=0,
        required=False
    )

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

        context = self.perform_zap_scan(target, max_depth)
        return render(request, 'scanner/result.html', context)

    def perform_zap_scan(self, target, max_depth=5):
        try:
            base_url = settings.ZAP_DAEMON_URL.rstrip('/')  # ex: http://127.0.0.1:8080
            apikey = settings.ZAP_API_KEY

            params = {}
            if apikey:
                params['apikey'] = apikey

            # 1. Spider (découverte)
            print(f"[*] Spider → {target}")
            spider_resp = requests.get(
                f"{base_url}/JSON/spider/action/scan/",
                params={**params, 'url': target, 'maxChildren': max_depth or None}
            )
            spider_resp.raise_for_status()
            spider_id = spider_resp.json()['scan']

            # Attente spider
            while True:
                status = requests.get(
                    f"{base_url}/JSON/spider/view/status/",
                    params={**params, 'scanId': spider_id}
                ).json()['status']
                if int(status) >= 100:
                    break
                time.sleep(5)

            # 2. Active scan
            print("[*] Active scan...")
            ascan_resp = requests.get(
                f"{base_url}/JSON/ascan/action/scan/",
                params={**params, 'url': target, 'recurse': 'true', 'inScopeOnly': 'true'}
            )
            ascan_resp.raise_for_status()
            ascan_id = ascan_resp.json()['scan']

            # Attente active scan
            start_time = time.time()
            while True:
                status = requests.get(
                    f"{base_url}/JSON/ascan/view/status/",
                    params={**params, 'scanId': ascan_id}
                ).json()['status']
                if int(status) >= 100:
                    break
                if time.time() - start_time > settings.ZAP_TIMEOUT:
                    return {'error': 'Scan actif timeout'}
                time.sleep(10)

            # 3. Rapport HTML
            report_resp = requests.get(
                f"{base_url}/OTHER/core/other/htmlreport/",
                params=params
            )
            report_resp.raise_for_status()
            html_report = report_resp.text

            # Sauvegarde optionnelle
            os.makedirs("reports", exist_ok=True)
            report_filename = f"zap_report_{int(time.time())}.html"
            report_path = os.path.join("reports", report_filename)
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_report)

            # Nombre d'alertes (simple appel API)
            alerts_resp = requests.get(
                f"{base_url}/JSON/core/view/alerts/",
                params={**params, 'baseurl': target}
            )
            alert_count = len(alerts_resp.json()) if alerts_resp.ok else 0

            return {
                'success': True,
                'target': target,
                'html_report': html_report,
                'report_path': report_path,
                'alert_count': alert_count
            }

        except requests.exceptions.RequestException as e:
            return {'error': f"Erreur de connexion à ZAP : {str(e)}"}
        except Exception as e:
            return {'error': str(e)}