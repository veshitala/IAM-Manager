from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.http.response import HttpResponse, HttpResponseRedirect, Http404
from iam.models import *
from iam.forms import *
import json
from django.contrib.auth.models import User
import boto3
from django.core.urlresolvers import reverse


'''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Login
    Description:when user hits the url "^$" this function is called
    First this function renders to login template,
    when user is provided with correct data, user gets login only when this user is active and renders to base template,
    when user is provided with incorrect data, user gets an error message,
    when user is provided with correct data, but the user is inactive, provides an error message.
    '''


def user_login(request):
    if request.method == "POST":
        user = authenticate(username=request.POST.get("username"), password=request.POST.get("password"))
        if user is not None:
            if user.is_active:
                login(request, user)
                data = {"error": False, "message": "Loggedin Successfully"}
                return HttpResponse(json.dumps(data))
            else:
                data = {"error": True, "message": "User is not active."}
                return HttpResponse(json.dumps(data))
        else:
            data = {"error": True, "message": "Username and Password were incorrect."}
        return HttpResponse(json.dumps(data))
    else:
        if request.user.is_authenticated():
            user = User.objects.get(email=request.user.email)
            return render(request, "base.html", {"user": user})
    return render(request, "login.html")

'''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Logout
    Description:when user hits the url "^/logout$" this function is called, user gets logged out and redirected to login template.
    '''


def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/')

'''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Register
    Description:when user hits the url "^/register$" this function is called
    First this function renders to register template,
    when user is provided with correct data, user gets registered and redirected to login template,
    when user is provided with incorrect data, user gets an error message,
    '''


def user_register(request):
    if request.method == 'POST':
        new_member = RegisterForm(request.POST)
        if new_member.is_valid():
            new_member = User.objects.create(email=request.POST.get("email"), username=request.POST.get("username"), first_name=request.POST.get("first_name"))
            new_member.set_password(request.POST.get("password"))
            new_member.save()
            data = {"error": False}
        else:
            data = {"error": True, "response": new_member.errors}
        return HttpResponse(json.dumps(data))
    return render(request, "register.html")


'''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Settings
    Description:when user hits the url "^/settings$" this function is called
    First this function renders to settings template,
    Here user creates access key and secret keys,
    '''


def settings(request):
    user_obj = User.objects.get(id=request.user.id)
    user_profile = UserProfile.objects.filter(user=request.user)
    if request.method == 'POST':
        if not user_profile:
            user = UserProfileForm(request.POST)
            if user.is_valid():
                obj = user.save(commit=False)
                obj.user = user_obj
                obj.save()
                data = {"error": False}
            else:
                data = {"error": True, "response": user.errors}
            return HttpResponse(json.dumps(data))
        else:
            user_profile[0].access_key = request.POST.get("access_key")
            user_profile[0].secret_key = request.POST.get("secret_key")
            user_profile[0].save()
            data = {"error": False}
            return HttpResponse(json.dumps(data))
    return render(request, "settings.html", {"user": user_profile[0] if user_profile else None})


'''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Add IAM User
    Description:when user hits the url "^iam/user/add/$" this function is called
    First this function renders to add_iam_user template,
    New IAM user can create only when User updated settings(Access key, secret Keys).
    Connecting to boto3 IAM client with AWS Access key and Secret Keys.
    when post data is requested, new IAM user is created, when user selects to generate access and secret keys then acess keys are generated and saved in our database.
    '''


def add_iam_user(request):
    user_profile = UserProfile.objects.get(user=request.user)
    client = boto3.client(
       'iam',
       aws_access_key_id=user_profile.access_key,
       aws_secret_access_key=user_profile.secret_key
    )
    user_profile = UserProfile.objects.filter(user=request.user)
    if request.method == "POST":
        new_iam_user = IAMUserForm(request.POST)
        if user_profile:
            if new_iam_user.is_valid():
                client.create_user(Path="/", UserName=request.POST.get("username"))
                iam_user = new_iam_user.save()
                if request.POST.get("generate_keys"):
                    response = client.create_access_key(UserName=iam_user.username)
                    iam_user.access_key = response["AccessKey"]["AccessKeyId"]
                    iam_user.secret_key = response["AccessKey"]["SecretAccessKey"]
                    iam_user.status = True
                    iam_user.save()
                data = {"error": False}
            else:
                data = {"error": True, "response": new_iam_user.errors}
        else:
            data = {"error": True, "message": "Please Update Settings"}
        return HttpResponse(json.dumps(data))
    return render(request, "iam_user/add_iam_user.html")


'''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Add IAM User List
    Description:when user hits the url "^iam/user/list/$" this function is called
    First this function renders to iam_users_list template,
    Connecting to boto3 IAM client, Displays all IAM Users.
    '''


def iam_users_list(request):
    user_profile = UserProfile.objects.get(user=request.user)
    client = boto3.client(
       'iam',
       aws_access_key_id=user_profile.access_key,
       aws_secret_access_key=user_profile.secret_key
    )
    response = client.list_users()
    return render(request, "iam_user/iam_users_list.html", {"response": response["Users"]})


'''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Add IAM User Detail
    Description:when user hits the url "^iam/user/detail/$" this function is called
    First this function renders to iam_users_list template,
    Connecting to boto3 IAM client, Display details of specific IAM User.
    '''


def iam_user_detail(request, user_name):
    user_profile = UserProfile.objects.get(user=request.user)
    client = boto3.client(
       'iam',
       aws_access_key_id=user_profile.access_key,
       aws_secret_access_key=user_profile.secret_key
    )
    response = client.get_user(UserName=user_name)
    response1 = client.list_policies(
            Scope='All',
            OnlyAttached=False,
        )
    return render(request, "iam_user/iam_user_detail.html", {"response": response["User"]})


def iam_user_change_password(request, iam_user_id):
    user_profile = UserProfile.objects.get(user=request.user)
    client = boto3.client(
       'iam',
       aws_access_key_id=user_profile.access_key,
       aws_secret_access_key=user_profile.secret_key
    )
    iam_user = IAMUser.objects.get(id=iam_user_id)
    if request.method == 'POST':
        validate_changepwd = ResetPasswordForm(request.POST)
        if validate_changepwd.is_valid():
            if request.POST.get("new_pwd") != request.POST.get("confirm_pwd"):
                data = {"error": True, 'response': {"confirm_pwd": "Confirm Password should match with Password."}}
                return HttpResponse(json.dumps(data))
            elif request.POST.get("new_pwd") == request.POST.get("confirm_pwd"):
                iam_user.password = request.POST.get("new_pwd")
                respnse = client.get_account_password_policy()
                response = client.create_login_profile(
                    UserName=iam_user.username,
                    Password=request.POST.get("new_pwd"),
                    PasswordResetRequired=False
                )
                iam_user.save()
                data = {"error": False}
                return HttpResponse(json.dumps(data))
        else:
            data = {'error': True, 'response': validate_changepwd.errors}
            return HttpResponse(json.dumps(data))
    return render(request, 'iam_user/change_password.html')


def policies_list(request, iam_user_id):
    iam_user = IAMUser.objects.get(id=iam_user_id)
    user_profile = UserProfile.objects.get(user=request.user)
    client = boto3.client(
       'iam',
       aws_access_key_id=user_profile.access_key,
       aws_secret_access_key=user_profile.secret_key
    )
    response = client.list_policies(
            Scope='All',
            OnlyAttached=False,
            MaxItems=10
            )
    if request.method == "POST":
        iam_user.policies.clear()
        for policy in request.POST.getlist("policy"):
            policy, created = Policy.objects.get_or_create(arn=policy)
            attach_policy_to_user = client.attach_user_policy(
                UserName=iam_user.username,
                PolicyArn=policy.arn
            )
            iam_user.policies.add(policy)
        return HttpResponseRedirect(reverse("iam_user_detail", kwargs={'user_name': iam_user.username}))
    return render(request, "policies.html", {"response": response["Policies"], "iam_user": iam_user})


def detach_user_policies(request, iam_user_id, policy_id):
    user_profile = UserProfile.objects.get(user=request.user)
    client = boto3.client(
       'iam',
       aws_access_key_id=user_profile.access_key,
       aws_secret_access_key=user_profile.secret_key
    )
    iam_user = IAMUser.objects.get(id=iam_user_id)
    policy = Policy.objects.get(id=policy_id)
    response = client.detach_user_policy(
        UserName=iam_user.username,
        PolicyArn=policy.arn
    )
    p = iam_user.policies.filter(id=policy.id)
    p.delete()
    policy.delete()
    return HttpResponseRedirect(reverse("iam_user_detail", kwargs={'user_name': iam_user.username}))