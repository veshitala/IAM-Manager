from django import forms


class BucketForm(forms.Form):
    bucket_name = forms.CharField(max_length=100)
    region_name = forms.CharField(max_length=100)
