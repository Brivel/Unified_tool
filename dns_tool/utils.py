# dns_tool/utils.py
import dns.resolver

# -------------------
# NSLOOKUP
# -------------------
def run_nslookup(domain, nameservers=None):
    """
    Exécute NSLookup sur le domaine pour tous les types d'enregistrement.
    nameservers: liste de serveurs DNS (ex: ["8.8.8.8"])
    """
    alerts = []
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                alerts.append({
                    "record": rtype,
                    "level": "success",
                    "message": str(rdata)
                })
        except dns.resolver.NoAnswer:
            alerts.append({"record": rtype, "level": "success", "message": "Aucun enregistrement"})
        except dns.resolver.NXDOMAIN:
            alerts.append({"record": rtype, "level": "error", "message": "Le domaine n'existe pas"})
        except Exception as e:
            alerts.append({"record": rtype, "level": "error", "message": str(e)})

    return alerts

# -------------------
# DIG
# -------------------
def run_dig(domain, record_type):
    """
    Exécute une requête DNS (type dig) pour un seul type d'enregistrement.
    """
    alerts = []
    try:
        answers = dns.resolver.resolve(domain, record_type)
        for rdata in answers:
            alerts.append({
                "record": record_type,
                "level": "success",
                "message": str(rdata)
            })
    except dns.resolver.NoAnswer:
        alerts.append({
            "record": record_type,
            "level": "success",
            "message": "Aucun résultat"
        })
    except dns.resolver.NXDOMAIN:
        alerts.append({
            "record": record_type,
            "level": "error",
            "message": "Le domaine n'existe pas"
        })
    except Exception as e:
        alerts.append({
            "record": record_type,
            "level": "error",
            "message": str(e)
        })
    return alerts

# -------------------
# Comparaison multi-DNS
# -------------------
def compare_multi_dns(domain, servers=None):
    """
    Compare les réponses DNS entre plusieurs serveurs.
    Retourne un dict {record_type: {server: [résultats]}}
    """
    if servers is None:
        servers = ["8.8.8.8", "1.1.1.1"]  # Google + Cloudflare par défaut

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    comparison = {}

    for rtype in record_types:
        comparison[rtype] = {}
        for server in servers:
            try:
                alerts = run_nslookup(domain, nameservers=[server])
                messages = [a["message"] for a in alerts if a["record"] == rtype]
                comparison[rtype][server] = messages if messages else ["Aucun résultat"]
            except Exception as e:
                comparison[rtype][server] = [f"Erreur: {e}"]

    return comparison

# -------------------
# Détection d'anomalies
# -------------------
def detect_anomalies(alerts):
    """
    Analyse les alertes DNS et détecte les anomalies.
    alerts peut être une liste de dict OU de strings
    """
    anomalies = []

    for alert in alerts:
        # 🔹 Si alert est une string
        if isinstance(alert, str):
            message = alert.lower()
            if "timeout" in message or "erreur" in message or "fail" in message:
                anomalies.append({
                    "level": "danger",
                    "message": alert
                })

        # 🔹 Si alert est un dict
        elif isinstance(alert, dict):
            level = alert.get("level", "info")
            message = alert.get("message", "")

            if level == "danger":
                anomalies.append(alert)

    return anomalies

# -------------------
# Analyse centralisée des réponses DNS
# -------------------
def analyze_dns_response(alerts):
    """
    Analyse les alertes DNS et renvoie un résumé des succès, avertissements, erreurs et dangers.
    alerts : liste de dicts OU de strings (issue de run_nslookup, run_dig ou compare_multi_dns)
    """
    summary = {
        "success": [],
        "warnings": [],
        "errors": [],
        "danger": []
    }

    for alert in alerts:
        # Si alert est un dict
        if isinstance(alert, dict):
            level = alert.get("level", "info").lower()
            message = alert.get("message", "")

            if level in summary:
                summary[level].append(message)
            else:
                summary["warnings"].append(message)

        # Si alert est une string
        elif isinstance(alert, str):
            summary["warnings"].append(alert)

        else:
            # cas inattendu
            summary["warnings"].append(str(alert))

    return summary

