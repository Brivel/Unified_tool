from django.shortcuts import render
from django.http import JsonResponse
import whois
import socket
import json
from datetime import datetime
from .export_utils import export_whois_to_word, export_whois_to_excel, export_all_whois_to_word, export_all_whois_to_excel
from .models import WHOISResult
from .country_utils import get_country_from_domain, get_country_flag


def convert_datetime_to_string(value):
    """
    Convertit un objet datetime en string pour la sérialisation JSON
    """
    if isinstance(value, datetime):
        return value.strftime('%d/%m/%Y %H:%M:%S')
    return value


def home(request):
    result = None
    error = None
    domain = None
    ip_address = None
    domain_info = None
    raw_whois = None
    country_from_tld = None
    all_results = None

    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip()
        if domain:
            try:
                # Identifier le pays à partir du TLD
                country_from_tld = get_country_from_domain(domain)
                
                # Résolution IP
                try:
                    ip_address = socket.gethostbyname(domain)
                except socket.gaierror:
                    ip_address = "Non résolu (DNS)"

                # WHOIS
                w = whois.whois(domain)

                # On passe les données structurées au template
                domain_info = {
                    'domain_name': w.domain_name or "Inconnu",
                    'registrar': w.registrar or "Inconnu",
                    'creation_date': convert_datetime_to_string(w.creation_date) or "Inconnu",
                    'expiration_date': convert_datetime_to_string(w.expiration_date) or "Inconnu",
                    'last_updated': convert_datetime_to_string(w.last_updated) or "Inconnu",
                    'name_servers': w.name_servers or [],
                    'status': w.status or [],
                    'country': w.country or "Inconnu",
                    'org': w.org or "Inconnu",
                }

                raw_whois = w.text or "Aucune donnée brute disponible"
                
                # Enregistrer en base de données
                WHOISResult.objects.update_or_create(
                    domain=domain,
                    defaults={
                        'ip_address': ip_address,
                        'country_from_tld': country_from_tld,
                        'domain_info': domain_info,
                        'raw_whois': raw_whois,
                    }
                )
                
                # Stocker les données en session pour l'export rapide
                request.session['last_whois_data'] = {
                    'domain': domain,
                    'ip_address': ip_address,
                    'country_from_tld': country_from_tld,
                    'domain_info': domain_info,
                    'raw_whois': raw_whois,
                }

            except Exception as e:
                error = f"Erreur lors de la requête : {str(e)}"

    # Récupérer tous les résultats
    all_results = WHOISResult.objects.all()

    return render(request,'protegioTools/protegiotools.html', {
        'domain': domain,
        'error': error,
        'ip_address': ip_address,
        'domain_info': domain_info,
        'raw_whois': raw_whois,
        'country_from_tld': country_from_tld,
        'country_flag': get_country_flag(country_from_tld) if country_from_tld else '',
        'all_results': all_results,
    })


def whois_view(request):
    return home(request)


def export_word(request):
    """
    Exporte les derniers résultats WHOIS en format Word
    """
    try:
        whois_data = request.session.get('last_whois_data')
        
        if not whois_data:
            return JsonResponse({'error': 'Aucune donnée à exporter. Veuillez d\'abord faire une recherche WHOIS.'}, status=400)
        
        return export_whois_to_word(
            whois_data['domain'],
            whois_data['ip_address'],
            whois_data.get('country_from_tld', ''),
            whois_data['domain_info'],
            whois_data['raw_whois']
        )
    except Exception as e:
        return JsonResponse({'error': f'Erreur lors de l\'export en Word: {str(e)}'}, status=500)


def export_excel(request):
    """
    Exporte les derniers résultats WHOIS en format Excel
    """
    try:
        whois_data = request.session.get('last_whois_data')
        
        if not whois_data:
            return JsonResponse({'error': 'Aucune donnée à exporter. Veuillez d\'abord faire une recherche WHOIS.'}, status=400)
        
        return export_whois_to_excel(
            whois_data['domain'],
            whois_data['ip_address'],
            whois_data.get('country_from_tld', ''),
            whois_data['domain_info'],
            whois_data['raw_whois']
        )
    except Exception as e:
        return JsonResponse({'error': f'Erreur lors de l\'export en Excel: {str(e)}'}, status=500)


def export_all_word(request):
    """
    Exporte tous les résultats WHOIS en format Word
    """
    try:
        results = WHOISResult.objects.all()
        
        if not results.exists():
            return JsonResponse({'error': 'Aucun résultat à exporter. Effectuez d\'abord des recherches WHOIS.'}, status=400)
        
        return export_all_whois_to_word(results)
    except Exception as e:
        return JsonResponse({'error': f'Erreur lors de l\'export en Word: {str(e)}'}, status=500)


def export_all_excel(request):
    """
    Exporte tous les résultats WHOIS en format Excel
    """
    try:
        results = WHOISResult.objects.all()
        
        if not results.exists():
            return JsonResponse({'error': 'Aucun résultat à exporter. Effectuez d\'abord des recherches WHOIS.'}, status=400)
        
        return export_all_whois_to_excel(results)
    except Exception as e:
        return JsonResponse({'error': f'Erreur lors de l\'export en Excel: {str(e)}'}, status=500)
