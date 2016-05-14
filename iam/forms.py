from django import forms


class CreatePolicyForm(forms.Form):

    aws_service = forms.CharField(max_length=100)
    related_service = forms.CharField(max_length=100)
    action = forms.CharField(max_length=100)
    policy_name = forms.CharField(max_length=150)
