from django import forms

class ScanForm(forms.Form):
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