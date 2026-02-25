from django.shortcuts import render
import whois
import socket

def home(request):
    result = None
    error = None
    domain = None
    ip_address = None
    domain_info = None
    raw_whois = None

    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip()
        if domain:
            try:
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
                    'creation_date': w.creation_date or "Inconnu",
                    'expiration_date': w.expiration_date or "Inconnu",
                    'last_updated': w.last_updated or "Inconnu",
                    'name_servers': w.name_servers or [],
                    'status': w.status or [],
                    'country': w.country or "Inconnu",
                    'org': w.org or "Inconnu",
                }

                raw_whois = w.text or "Aucune donnée brute disponible"

            except Exception as e:
                error = f"Erreur lors de la requête : {str(e)}"

    return render(request,'protegioTools/protegiotools.html', {
        'domain': domain,
        'error': error,
        'ip_address': ip_address,
        'domain_info': domain_info,
        'raw_whois': raw_whois,
    })

def whois_view(request):
    return home(request)