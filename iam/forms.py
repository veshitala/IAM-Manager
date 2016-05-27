from django import forms


class BucketForm(forms.Form):
    bucket_name = forms.CharField(max_length=100)
    region_name = forms.CharField(max_length=100)


class ChangePasswordForm(forms.Form):
    new_password = forms.CharField(max_length=150)
    confirm_password = forms.CharField(max_length=150)


class EmailAddressForm(forms.Form):
    email = forms.CharField(max_length=150)