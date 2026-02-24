from django.shortcuts import render
from django.http import JsonResponse, StreamingHttpResponse
import json
import threading
import time
from datetime import datetime
from .models import SpeedTestResult

# Dictionnaire pour tracker la progression des tests en cours
test_progress = {}
test_results = {}


class SpeedTestProgress:
    """Classe pour tracker la progression du test en temps réel"""
    def __init__(self, test_id):
        self.test_id = test_id
        self.current_step = 0
        self.total_steps = 4
        self.current_message = "Initialisation..."
        self.progress_percent = 0
    
    def update(self, step, message, percent):
        self.current_step = step
        self.current_message = message
        self.progress_percent = percent
        test_progress[self.test_id] = {
            'step': step,
            'message': message,
            'percent': percent
        }


def execute_speedtest(test_id):
    """
    Exécute le test de vitesse dans un thread séparé
    """
    try:
        import speedtest
        
        progress = SpeedTestProgress(test_id)
        
        # ÉTAPE 1: Initialisation
        progress.update(1, "🔍 Recherche des serveurs disponibles...", 10)
        st = speedtest.Speedtest()
        st.get_servers()
        
        # ÉTAPE 2: Test de téléchargement
        progress.update(2, "📥 Test de téléchargement en cours...", 35)
        download_speed = st.download() / 1_000_000  # Convertir en Mbps
        
        # ÉTAPE 3: Test de mise en ligne
        progress.update(3, "📤 Test de mise en ligne en cours...", 70)
        upload_speed = st.upload() / 1_000_000  # Convertir en Mbps
        
        # ÉTAPE 4: Récupération des infos
        progress.update(4, "📊 Récupération des informations finales...", 90)
        ping = st.results.ping
        server_info = st.results.server
        client_info = st.results.client
        
        # Enregistrer le résultat en base de données
        result = SpeedTestResult.objects.create(
            download_speed=round(download_speed, 2),
            upload_speed=round(upload_speed, 2),
            ping=round(ping, 2),
            server_name=server_info.get('sponsor', 'Unknown'),
            server_country=server_info.get('country', 'Unknown'),
            server_city=server_info.get('cc', 'Unknown'),
            isp=client_info.get('isp', 'Unknown'),
        )
        
        # Test complété
        progress.update(4, "✅ Test terminé avec succès!", 100)
        
        test_results[test_id] = {
            'success': True,
            'data': {
                'download_speed': result.download_speed,
                'upload_speed': result.upload_speed,
                'ping': result.ping,
                'server_name': result.server_name,
                'server_country': result.server_country,
                'server_city': result.server_city,
                'isp': result.isp,
                'timestamp': result.created_at.strftime('%d/%m/%Y %H:%M:%S'),
            }
        }
        
    except Exception as e:
        print(f"Erreur speedtest: {str(e)}")
        import traceback
        traceback.print_exc()
        test_results[test_id] = {
            'success': False,
            'error': f'Erreur lors du test: {str(e)}'
        }
        progress.update(0, f"❌ Erreur: {str(e)}", 0)
    
    # Nettoyage après 5 minutes
    cleanup_time = time.time() + 300
    while time.time() < cleanup_time:
        time.sleep(1)
    
    if test_id in test_progress:
        del test_progress[test_id]
    if test_id in test_results:
        del test_results[test_id]


def home(request):
    """
    Page d'accueil du test de vitesse internet
    """
    results = SpeedTestResult.objects.all().order_by('-created_at')[:10]
    
    return render(request, 'perforNet/speedtest.html', {
        'results': results,
    })


def get_progress(request):
    """
    Endpoint pour obtenir la progression en temps réel
    """
    # Si pas de test_id spécifié, retourner le dernier test en cours
    test_id = request.GET.get('test_id')
    
    if not test_id:
        # Retourner le test le plus récent en cours
        if test_progress:
            test_id = list(test_progress.keys())[-1]
        else:
            return JsonResponse({'percent': 0, 'message': 'Aucun test en cours'})
    
    if test_id in test_progress:
        data = test_progress[test_id].copy()
        # Si résultat disponible, l'ajouter
        if test_id in test_results:
            data['result'] = test_results[test_id]
        return JsonResponse(data)
    
    # Vérifier si le test est terminé
    if test_id in test_results:
        result = test_results[test_id]
        response = {
            'percent': 100,
            'message': '✅ Test terminé!',
            'result': result
        }
        return JsonResponse(response)
    
    return JsonResponse({'percent': 0, 'message': 'Test introuvable'})


def run_speed_test(request):
    """
    Lance un test de vitesse internet (asynchrone)
    """
    if request.method == 'POST':
        test_id = str(int(time.time() * 1000))  # ID unique du test
        
        try:
            import speedtest
            print(f"[PerforNet] Démarrage test {test_id}")
            
            # Initier la progression
            progress = SpeedTestProgress(test_id)
            progress.update(0, "⏳ Test en attente de démarrage...", 5)
            
            # Lancer le test dans un thread
            thread = threading.Thread(target=execute_speedtest, args=(test_id,), daemon=True)
            thread.start()
            
            response_data = {
                'success': True,
                'test_id': test_id,
                'message': 'Test de vitesse lancé...'
            }
            print(f"[PerforNet] Réponse envoyée: {response_data}")
            
            return JsonResponse(response_data)
            
        except ImportError as e:
            print(f"[PerforNet] ImportError: {e}")
            return JsonResponse({
                'success': False,
                'error': 'Module speedtest-cli non installé'
            }, status=500)
        except Exception as e:
            print(f"[PerforNet] Erreur initialisation speedtest: {str(e)}")
            import traceback
            traceback.print_exc()
            return JsonResponse({
                'success': False,
                'error': f'Erreur initialisation: {str(e)}'
            }, status=500)
    
    print(f"[PerforNet] Méthode non POST reçue: {request.method}")
    return JsonResponse({'success': False, 'error': 'Invalid request - POST required'}, status=400)


def get_latest_result(request):
    """
    Récupère le dernier résultat du test de vitesse
    """
    try:
        latest = SpeedTestResult.objects.latest('created_at')
        return JsonResponse({
            'success': True,
            'data': {
                'download_speed': latest.download_speed,
                'upload_speed': latest.upload_speed,
                'ping': latest.ping,
                'server_name': latest.server_name,
                'server_country': latest.server_country,
                'isp': latest.isp,
                'timestamp': latest.created_at.strftime('%d/%m/%Y %H:%M:%S'),
            }
        })
    except SpeedTestResult.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'No test results found'}, status=404)


def get_history(request):
    """
    Récupère l'historique des tests de vitesse
    """
    results = SpeedTestResult.objects.all().order_by('-created_at')[:50]
    
    data = []
    for result in results:
        data.append({
            'download_speed': result.download_speed,
            'upload_speed': result.upload_speed,
            'ping': result.ping,
            'server_name': result.server_name,
            'server_country': result.server_country,
            'timestamp': result.created_at.strftime('%d/%m/%Y %H:%M:%S'),
        })
    
    return JsonResponse({
        'success': True,
        'data': data
    })


def export_results(request):
    """
    Exporte les résultats en PDF ou CSV
    """
    format_type = request.GET.get('format', 'csv')
    
    try:
        results = SpeedTestResult.objects.all().order_by('-created_at')
        
        if format_type == 'csv':
            import csv
            from django.http import HttpResponse
            
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="speed_test_results_{datetime.now().strftime("%d%m%Y_%H%M%S")}.csv"'
            
            writer = csv.writer(response)
            writer.writerow(['Date/Heure', 'Téléchargement (Mbps)', 'Téléchargement Inversé (Mbps)', 'Ping (ms)', 'Serveur', 'Pays', 'FAI'])
            
            for result in results:
                writer.writerow([
                    result.created_at.strftime('%d/%m/%Y %H:%M:%S'),
                    round(result.download_speed, 2),
                    round(result.upload_speed, 2),
                    round(result.ping, 2),
                    result.server_name,
                    result.server_country,
                    result.isp,
                ])
            
            return response
        
        return JsonResponse({'success': False, 'error': 'Format not supported'}, status=400)
    
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)



def get_latest_result(request):
    """
    Récupère le dernier résultat du test de vitesse
    """
    try:
        latest = SpeedTestResult.objects.latest('created_at')
        return JsonResponse({
            'success': True,
            'data': {
                'download_speed': latest.download_speed,
                'upload_speed': latest.upload_speed,
                'ping': latest.ping,
                'server_name': latest.server_name,
                'server_country': latest.server_country,
                'isp': latest.isp,
                'timestamp': latest.created_at.strftime('%d/%m/%Y %H:%M:%S'),
            }
        })
    except SpeedTestResult.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'No test results found'}, status=404)


def get_history(request):
    """
    Récupère l'historique des tests de vitesse
    """
    results = SpeedTestResult.objects.all().order_by('-created_at')[:50]
    
    data = []
    for result in results:
        data.append({
            'download_speed': result.download_speed,
            'upload_speed': result.upload_speed,
            'ping': result.ping,
            'server_name': result.server_name,
            'server_country': result.server_country,
            'timestamp': result.created_at.strftime('%d/%m/%Y %H:%M:%S'),
        })
    
    return JsonResponse({
        'success': True,
        'data': data
    })


def export_results(request):
    """
    Exporte les résultats en PDF ou CSV
    """
    format_type = request.GET.get('format', 'csv')
    
    try:
        results = SpeedTestResult.objects.all().order_by('-created_at')
        
        if format_type == 'csv':
            import csv
            from django.http import HttpResponse
            
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="speed_test_results_{datetime.now().strftime("%d%m%Y_%H%M%S")}.csv"'
            
            writer = csv.writer(response)
            writer.writerow(['Date/Heure', 'Téléchargement (Mbps)', 'Téléchargement Inversé (Mbps)', 'Ping (ms)', 'Serveur', 'Pays', 'FAI'])
            
            for result in results:
                writer.writerow([
                    result.created_at.strftime('%d/%m/%Y %H:%M:%S'),
                    round(result.download_speed, 2),
                    round(result.upload_speed, 2),
                    round(result.ping, 2),
                    result.server_name,
                    result.server_country,
                    result.isp,
                ])
            
            return response
        
        return JsonResponse({'success': False, 'error': 'Format not supported'}, status=400)
    
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

