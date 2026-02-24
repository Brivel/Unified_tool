from django.views import View
from django.shortcuts import render
from .forms import NslookupForm, DigForm
from .utils import run_nslookup, run_dig, compare_multi_dns, detect_anomalies


class NslookupView(View):
    template_name = "nslookup.html"

    def get(self, request):
        return render(request, self.template_name, {
            "form": NslookupForm()
        })

    def post(self, request):
        form = NslookupForm(request.POST)

        records = {}
        anomalies = []
        comparison = {}
        analysis = []

        if form.is_valid():
            domain = form.cleaned_data["domain"]

            alerts = run_nslookup(domain)

            for alert in alerts:
                if isinstance(alert, dict):
                    rtype = alert.get("record", "UNKNOWN")
                    message = alert.get("message", "")

                    records.setdefault(rtype, "")
                    records[rtype] += message + "\n"

            anomalies = detect_anomalies(alerts)
            comparison = compare_multi_dns(domain)
            analysis = alerts

        return render(request, self.template_name, {
            "form": form,
            "domain": form.cleaned_data.get("domain", ""),
            "records": records,
            "comparison": comparison,
            "anomalies": anomalies,
            "analysis": analysis
        })


class DigView(View):
    template_name = "dig.html"

    def get(self, request):
        return render(request, self.template_name, {
            "form": DigForm()
        })

    def post(self, request):
        form = DigForm(request.POST)
        records = {}
        anomalies = []

        if form.is_valid():
            domain = form.cleaned_data["domain"]
            record_type = form.cleaned_data["record_type"]

            alerts = run_dig(domain, record_type)

            for alert in alerts:
                if isinstance(alert, dict):
                    records.setdefault(alert["record"], "")
                    records[alert["record"]] += alert["message"] + "\n"

            anomalies = detect_anomalies(alerts)

        return render(request, self.template_name, {
            "form": form,
            "records": records,
            "anomalies": anomalies
        })
