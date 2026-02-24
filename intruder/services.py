from concurrent.futures import ThreadPoolExecutor
import requests

# Fonction qui envoie un payload à une URL
def send_payload(url, payload):
    response = requests.post(url, data={"password": payload})
    return payload, response.status_code

# Fonction principale qui exécute les attaques en parallèle
def start_attack(url, payload_list):
    results = []

    # Création du ThreadPool
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_payload, url, p) for p in payload_list]

        for future in futures:
            results.append(future.result())

    return results
