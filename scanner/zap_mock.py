"""
Mock OWASP ZAP pour développement et tests
Simule les réponses de ZAP quand le daemon n'est pas disponible
"""
import json
import random
from datetime import datetime


class MockZAPScanner:
    """Simulateur de ZAP pour les tests"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.scan_id = random.randint(1000, 9999)
        self.spider_id = random.randint(1000, 9999)
        self.ascan_id = random.randint(1000, 9999)
        
    def get_servers_response(self):
        """Simule la réponse get_servers"""
        return {'scan': self.spider_id}
    
    def get_spider_status(self):
        """Simule le statut du spider"""
        return {'status': '100'}  # Complété
    
    def get_ascan_status(self):
        """Simule le statut du active scan"""
        return {'status': '100'}  # Complété
    
    def get_alerts_response(self):
        """Simule les alertes du scan"""
        # Générer des alertes aléatoires
        alerts = []
        
        # Quelques alertes haute priorité
        for i in range(random.randint(1, 3)):
            alerts.append({
                'alertRef': '10001',
                'alert': 'SQL Injection',
                'riskcode': '3',
                'confidence': '3',
                'riskdesc': 'High',
                'confidencedesc': 'High',
                'description': 'Potential SQL injection vulnerability detected',
                'instances': [
                    {'uri': f'{self.target_url}/search?q=test{i}'}
                ]
            })
        
        # Quelques alertes medium priorité
        for i in range(random.randint(2, 4)):
            alerts.append({
                'alertRef': '10002',
                'alert': 'Cross Site Scripting',
                'riskcode': '2',
                'confidence': '2',
                'riskdesc': 'Medium',
                'confidencedesc': 'Medium',
                'description': 'Potential XSS vulnerability detected',
                'instances': [
                    {'uri': f'{self.target_url}/profile?id=test{i}'}
                ]
            })
        
        # Quelques alertes low priorité
        for i in range(random.randint(3, 5)):
            alerts.append({
                'alertRef': '10003',
                'alert': 'Insecure HTTP Method',
                'riskcode': '1',
                'confidence': '2',
                'riskdesc': 'Low',
                'confidencedesc': 'Medium',
                'description': 'Insecure HTTP method allowed',
                'instances': [
                    {'uri': f'{self.target_url}/admin{i}'}
                ]
            })
        
        # Quelques info
        for i in range(random.randint(2, 3)):
            alerts.append({
                'alertRef': '10004',
                'alert': 'Information Disclosure',
                'riskcode': '0',
                'confidence': '1',
                'riskdesc': 'Informational',
                'confidencedesc': 'Low',
                'description': 'Information disclosure',
                'instances': [
                    {'uri': f'{self.target_url}/info{i}'}
                ]
            })
        
        return alerts
    
    def generate_html_report(self):
        """Génère un rapport HTML simulé pour ZAP"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        alerts = self.get_alerts_response()
        
        # Compter les alertes par risque
        high_count = len([a for a in alerts if a['riskcode'] == '3'])
        medium_count = len([a for a in alerts if a['riskcode'] == '2'])
        low_count = len([a for a in alerts if a['riskcode'] == '1'])
        info_count = len([a for a in alerts if a['riskcode'] == '0'])
        
        alerts_html = ""
        for alert in alerts:
            riskdesc = alert['riskdesc']
            risk_color = {
                'High': '#ff0000',
                'Medium': '#ff9900', 
                'Low': '#ffff00',
                'Informational': '#0099ff'
            }.get(riskdesc, '#cccccc')
            
            alerts_html += f"""
            <div class="risk-{riskdesc.lower()}" style="border-left: 4px solid {risk_color}; padding: 10px; margin: 5px 0; background: #f5f5f5;">
                <h4>{alert['alert']}</h4>
                <p><strong>Risk:</strong> {alert['riskdesc']}</p>
                <p><strong>Confidence:</strong> {alert['confidencedesc']}</p>
                <p><strong>Description:</strong> {alert['description']}</p>
                <p><strong>URL:</strong> {alert['instances'][0]['uri']}</p>
            </div>
            """
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OWASP ZAP Security Report (Mock)</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; border-bottom: 2px solid #666; padding-bottom: 10px; }}
                .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .risk-high {{ color: #d00; }}
                .risk-medium {{ color: #d80; }}
                .risk-low {{ color: #dd0; }}
                .risk-informational {{ color: #08d; }}
                .high {{ color: #ff0000; font-weight: bold; }}
                .medium {{ color: #ff9900; font-weight: bold; }}
                .low {{ color: #ffff00; font-weight: bold; }}
                .info {{ color: #0099ff; font-weight: bold; }}
                .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }}
                .stat-box {{ padding: 15px; border-radius: 5px; text-align: center; }}
                .stat-high {{ background: #ffcccc; }}
                .stat-medium {{ background: #ffe6cc; }}
                .stat-low {{ background: #ffffcc; }}
                .stat-info {{ background: #ccf2ff; }}
            </style>
        </head>
        <body>
            <h1>OWASP ZAP Security Assessment Report</h1>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Target URL:</strong> {self.target_url}</p>
                <p><strong>Scan Date:</strong> {timestamp}</p>
                <p><strong>Report Type:</strong> Mock Report (Development Mode)</p>
            </div>
            
            <div class="stats">
                <div class="stat-box stat-high">
                    <h3 class="high">{high_count}</h3>
                    <p>High Risk Issues</p>
                </div>
                <div class="stat-box stat-medium">
                    <h3 class="medium">{medium_count}</h3>
                    <p>Medium Risk Issues</p>
                </div>
                <div class="stat-box stat-low">
                    <h3 class="low">{low_count}</h3>
                    <p>Low Risk Issues</p>
                </div>
                <div class="stat-box stat-info">
                    <h3 class="info">{info_count}</h3>
                    <p>Informational</p>
                </div>
            </div>
            
            <h2>Alerts Details</h2>
            {alerts_html}
            
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; color: #999; font-size: 12px;">
                <p>This is a mock report generated for development/testing purposes.</p>
                <p>For production use, install and configure OWASP ZAP daemon on port 8080.</p>
            </div>
        </body>
        </html>
        """
        
        return html_template.strip()
