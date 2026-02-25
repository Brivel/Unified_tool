from django import forms

class UsernameForm(forms.Form):
    username = forms.CharField(
        label="Nom d’utilisateur",
        max_length=100,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "ex: johndoe"
        })
    )
