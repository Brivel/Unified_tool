
import json
import os
from django.shortcuts import render
from django.http import JsonResponse
from .forms import UsernameForm
from .osint import check_username

DATA_PATH = os.path.join(
    os.path.dirname(__file__),
    "data",
    "wmn-data.json"
)

def load_data():
    with open(DATA_PATH, encoding="utf-8") as f:
        return json.load(f)

def index(request):
    return render(request, "checker/index.html", {
        "form": UsernameForm()
    })

def results(request):
    form = UsernameForm(request.GET)
    results = []

    if form.is_valid():
        username = form.cleaned_data["username"]
        data = load_data()

        for site in data["sites"][:50]:  # limite sécurité
            scan = check_username(site, username)
            results.append({
                "name": site.get("name"),
                "category": site.get("category"),
                "url": scan["url"],
                "exists": scan.get("exists"),
                "status": scan.get("status", "N/A")
            })

    return render(request, "checker/results.html", {
        "form": form,
        "results": results
    })

def api_search(request):
    username = request.GET.get("username")
    if not username:
        return JsonResponse({"error": "username requis"}, status=400)

    data = load_data()
    output = []

    for site in data["sites"]:
        scan = check_username(site, username)
        if scan["status"]=="NO_URL":

            results.append({
                "name":site.get("name"),
                "category":site.get("category","N/A"),
                "url":scan["url"],
                "exists":scan["exists"],
                "status":scan["status"]
            })
