from django import forms


class NslookupForm(forms.Form):
    domain = forms.CharField(
        label="Nom de domaine",
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "ex: google.com"
        })
    )


class DigForm(forms.Form):
    domain = forms.CharField(
        max_length=255,
        label="Nom de domaine",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ex: example.com'})
    )
    record_type = forms.ChoiceField(
        choices=[('A', 'A'), ('AAAA', 'AAAA'), ('MX', 'MX'), ('NS', 'NS'), ('TXT', 'TXT'), ('CNAME', 'CNAME'), ('SOA', 'SOA')],
        label="Type d'enregistrement",
        widget=forms.Select(attrs={'class': 'form-control'})
    )
