from django import forms


class CreatePolicyForm(forms.Form):

    amazon_s3_service = forms.CharField(max_length=100)
    bucket_name = forms.CharField(max_length=100)
    action = forms.CharField(max_length=100)
    policy_name = forms.CharField(max_length=150)
