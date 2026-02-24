from django.shortcuts import render

def dashboard_home(request):
    # Ex: stats fictives
    stats = {
        'protegioTools_uses': 42,
        'project_uses': 28,
        'dns_tool_uses': 15,
        'scanner_uses': 111,
        'intruder_uses': 11,   
        'dns_tool_uses': 112, 

    }
    return render(request, 'dashboard/dashboard.html', {'stats': stats})