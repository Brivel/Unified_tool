from django import forms

class ScanForm(forms.Form):
    SCAN_CHOICES = [
        ('passive', 'Scan Passif'),
        ('active', 'Scan Actif'),
        ('both', 'Passif + Actif'),
    ]
    
    ALERT_LEVEL_CHOICES = [
        ('LOW', 'Faible (tous risques)'),
        ('MEDIUM', 'Moyen (défaut)'),
        ('HIGH', 'Élevé (critiques)'),
    ]
    
    POLICY_CHOICES = [
        ('default', 'Par défaut (équilibré)'),
        ('light', 'Léger (rapide)'),
        ('strict', 'Strict (OWASP Top 10)'),
        ('custom', 'Personnalisée'),
    ]
    
    target_url = forms.URLField(
        label="URL à scanner",
        widget=forms.URLInput(attrs={'placeholder': 'https://example.com', 'class': 'form-control'}),
        required=True
    )
    max_depth = forms.IntegerField(
        label="Profondeur max du spider (0 = illimité)",
        initial=5,
        min_value=0,
        required=False
    )
    scan_type = forms.ChoiceField(
        label="Type de scan",
        choices=SCAN_CHOICES,
        initial='both',
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'}),
        required=False
    )
    alert_level = forms.ChoiceField(
        label="Niveau d'alerte minimum",
        choices=ALERT_LEVEL_CHOICES,
        initial='MEDIUM',
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False
    )
    scan_policy = forms.ChoiceField(
        label="Politique de scan",
        choices=POLICY_CHOICES,
        initial='default',
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False
    )