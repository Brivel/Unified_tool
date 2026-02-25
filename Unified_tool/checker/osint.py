import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0 (OSINT Django Scanner)"
}

def get_site_url(site, username):
    """
    Récupère dynamiquement l’URL selon les clés existantes
    """
    for key in ["url", "check_uri", "uri_check", "uri"]:
        if key in site and site[key]:
            return site[key].replace("{username}", username)
    return None

def check_username(site, username, timeout=10):
    url = get_site_url(site, username)

    # ❌ Aucun schéma exploitable → on ignore
    if not url:
        return {
            "exists": False,
            "status": "NO_URL",
            "url": None
        }

    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=True
        )

        exists = False

        if site.get("errorType") == "status_code":
            exists = resp.status_code != site.get("errorCode", 404)

        elif site.get("errorType") == "message":
            error_msg = site.get("errorMsg", "")
            exists = error_msg not in resp.text

        else:
            exists = resp.status_code == 200

        return {
            "exists": exists,
            "status": resp.status_code,
            "url": url
        }

    except Exception as e:
        return {
            "exists": False,
            "status": "ERROR",
            "error": str(e),
            "url": url
        }
