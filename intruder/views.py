import requests
import time
from urllib.parse import urlparse
from django.shortcuts import render


def intruder_view(request):
    results = []
    summary = {
        "total": 0,
        "vulnerable": 0
    }

    if request.method == "POST":

        # Récupération sécurisée des données
        target_url = request.POST.get("target_url", "").strip()
        param_name = request.POST.get("param_name", "").strip()
        payloads_raw = request.POST.get("payloads", "").strip()

        # Vérification URL valide
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            return render(request, "intruder/intruder.html", {
                "results": [],
                "summary": summary,
                "error": "URL invalide. Exemple: https://example.com"
            })

        # Transformation des payloads (un par ligne)
        payloads = [p.strip() for p in payloads_raw.splitlines() if p.strip()]

        summary["total"] = len(payloads)

        for payload in payloads:
            try:
                start_time = time.time()

                response = requests.get(
                    target_url,
                    params={param_name: payload},
                    timeout=5
                )

                end_time = time.time()
                response_time = round(end_time - start_time, 3)

                content = response.text.lower()

                # --- Détection simple SQL ---
                sql_errors = [
                    "sql syntax",
                    "mysql",
                    "warning",
                    "unterminated",
                    "odbc",
                    "syntax error"
                ]

                # --- Détection simple XSS ---
                xss_detected = payload.lower() in content

                sql_detected = any(error in content for error in sql_errors)

                vulnerable = False
                risk = "Low"

                if sql_detected:
                    vulnerable = True
                    risk = "High"

                elif xss_detected:
                    vulnerable = True
                    risk = "Medium"

                if vulnerable:
                    summary["vulnerable"] += 1

                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "length": len(response.text),
                    "time": response_time,
                    "vulnerable": vulnerable,
                    "risk": risk
                })

            except requests.exceptions.RequestException as e:
                results.append({
                    "payload": payload,
                    "status": "Error",
                    "length": 0,
                    "time": 0,
                    "vulnerable": False,
                    "risk": "Low"
                })

    return render(request, "intruder/intruder.html", {
        "results": results,
        "summary": summary
    })