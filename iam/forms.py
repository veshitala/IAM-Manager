from django import forms
from iam.models import *


class RegisterForm(forms.Form):

    email = forms.CharField()
    first_name = forms.CharField()
    username = forms.CharField()
    password = forms.CharField()


class UserProfileForm(forms.ModelForm):

    class Meta:
        model = UserProfile
        fields = ["access_key", "secret_key"]


class IAMUserForm(forms.ModelForm):

    class Meta:
        model = IAMUser
        fields = ["email", "username"]


class ResetPasswordForm(forms.Form):
    new_pwd = forms.CharField()
    confirm_pwd = forms.CharField()

    
