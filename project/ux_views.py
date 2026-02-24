from django.shortcuts import render
from django.views.decorators.http import require_http_methods

@require_http_methods(["GET"])
def ux_demo(request):
    """Page de démonstration de l'UX améliorée"""
    return render(request, 'ux_demo.html')
