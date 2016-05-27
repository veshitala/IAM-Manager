from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
import json
import boto3
import csv
from django.shortcuts import render
from django.contrib.auth import logout
from django.http.response import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from botocore.exceptions import ClientError
from iam.models import REGIONS
from iam.forms import BucketForm, ChangePasswordForm


def home(request):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Description:when user hits the url "^home/$" this function is called
    This function renders to "base" template,
    After log in with thier Access keys and Secret Keys.
    '''
    return render(request, "base.html")


def user_logout(request):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Logout
    Description:when user hits the url "^/logout$" this function is called, user gets logged out and redirected to login template.
    Here when user log out respective user access key, secret key, username will be removed from session.
    '''
    if 'access_key' in request.session:
        request.session['access_key'] = None
    if 'secret_key' in request.session:
        request.session['secret_key'] = None
    if 'client_username' in request.session:
        request.session['client_username'] = None
    logout(request)
    return HttpResponseRedirect('/')


def login(request):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:login
    Description:when user hits the url "^$" this function is called
    First this function renders to "login" template,
    Here user login by entering valid access key and secret keys, then these varibles are stored in django session for further use.
    '''

    if request.method == "POST":
        client = boto3.client(
           'iam',
           aws_access_key_id=request.POST.get("access_key"),
           aws_secret_access_key=request.POST.get("secret_key")
        )
        try:
            if request.POST.get("access_key") and request.POST.get("secret_key") and request.POST.get("username"):
                client.get_login_profile(UserName=request.POST.get("username"))
                if 'access_key' not in request.session:
                    request.session['access_key'] = request.POST.get("access_key")
                if 'secret_key' not in request.session:
                    request.session['secret_key'] = request.POST.get("secret_key")
                if 'client_username' not in request.session:
                    request.session['client_username'] = request.POST.get("username")

                data = {"error": False}
            else:
                data = {"error": True, "response": "Please Enter Username, Access key, Secret Key."}
            return HttpResponse(json.dumps(data))

        except ClientError as e:
            data = {"error": True, "response": "Credentials are not valid."}
            return HttpResponse(json.dumps(data))
    if 'access_key' in request.session:
        return HttpResponseRedirect(reverse("home"))
    return render(request, "login.html")


def add_iam_user(request):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Add IAM User
    Description:when user hits the url "^iam/user/add/$" this function is called
    First this function renders to "add_iam_user" template,
    New IAM user can create only when User updated settings(Access key, secret Keys).
    Connecting to boto3 IAM client with AWS Access key and Secret Keys.
    when post data is requested, new IAM user is created, when user selects to generate access and
    secret keys then acess keys are generated and saved in our database.
    '''
    client = boto3.client(
       'iam',
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )

    if request.method == "POST":
        if request.POST.get("username"):
            try:
                if request.POST.get("iam_user_password"):
                    if request.POST.get("password"):
                        try:
                            try:
                                response_without_keys = client.create_user(Path="/", UserName=request.POST.get("username"))
                            
                                client.create_login_profile(
                                    UserName=request.POST.get("username"),
                                    Password=request.POST.get("password"),
                                    PasswordResetRequired=False
                                )

                            except ClientError as e:
                                data = {"error": True, "response": str(e)}
                                return HttpResponse(json.dumps(data))
                        except ClientError as e:
                            data = {"error": True, "response": "Password Should contain atleast one UpperCase letter, LowerCase letter and Numbers."}
                            return HttpResponse(json.dumps(data))
                    else:
                        data = {"error": True, "response": "Please Enter Password"}
                        return HttpResponse(json.dumps(data))
                else:
                    try:
                        response_without_keys = client.create_user(Path="/", UserName=request.POST.get("username"))
                    except ClientError as e:
                        data = {"error": True, "response": str(e)}
                        return HttpResponse(json.dumps(data))

                if request.POST.get("generate_keys"):
                    response = client.create_access_key(UserName=request.POST.get("username"))
                    data = {"error": False, "iam_username": response["AccessKey"]["UserName"], "iam_access_key": response["AccessKey"]["AccessKeyId"], "iam_secret_key": response["AccessKey"]["SecretAccessKey"]}
                else:
                    data = {"error": False, "iam_username": response_without_keys["User"]["UserName"]}
                return HttpResponse(json.dumps(data))
            except ClientError as e:
                data = {"error": True, "response": str(e)}
            return HttpResponse(json.dumps(data))
        else:
            data = {"error": True, "response": "Please enter IAM User Name"}
        return HttpResponse(json.dumps(data))
    return render(request, "iam_user/add_iam_user.html")


def generate_custom_policy(request, user_name):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Create Custom Policy
    Description:when user hits the url "^iam/custom-policy/(<user_name>)/$" this function is called
    First this function renders to "custom_policy" template,
    Here by selecting Amazon service(S3), policy name and provided details custom policy is created.
    Returns Error message for the data invalid or not given correctly.
    '''
    client = boto3.client(
       'iam',
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    client_s3 = boto3.client(
        's3',
        aws_access_key_id=request.session["access_key"],
        aws_secret_access_key=request.session["secret_key"])
    client_ec2 = boto3.client(
       'ec2', region_name=request.POST.get("region"),
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    response_instances = client_ec2.describe_instances()
    response_buckets = client_s3.list_buckets()
    if request.method == "POST":
        statement = []
        for dict in json.loads(request.POST.get("policy_document")):
            l = []
            action = ""
            for index, a in enumerate(dict["action"]):
                action = dict["aws_service"].split(":")[0]+':'+str(a)
                l.append(action)
            text = {}
            text['Effect'] = "Deny"
            text['Action'] = l
            if dict["aws_service"] == "s3":
                text['Resource'] = "arn:aws:s3:::"+dict["service_type"]+"/*"
                statement.append(text)

            elif dict["aws_service"] == "ec2":
                text['Resource'] = "arn:aws:ec2:"+request.POST.get("region")+"::"+dict["service_type"]+"/*"
                statement.append(text)
        policy_document = '{"Version": "2012-10-17","Statement": ['+str(json.dumps(statement)).strip("[]")+']}'
        policy_document = policy_document.replace("'", '"')
        if request.POST.get("show_policy") == "show":
            data = {'error': False, "policy_document": json.loads(policy_document)}
            return HttpResponse(json.dumps(data))
        else:
            try:
                policy = client.create_policy(
                    PolicyName=request.POST.get("policy_name"),
                    PolicyDocument=policy_document
                )
                client.attach_user_policy(
                    UserName=user_name,
                    PolicyArn=policy["Policy"]["Arn"]
                )
                data = {'error': False}
                return HttpResponse(json.dumps(data))
            except ClientError as e:
                data = {'error': True, 'exception_error': str(e)}
                return HttpResponse(json.dumps(data))
    else:
        return render(request, "policies.html", {"regions": REGIONS, "user_name": user_name, "response_buckets": response_buckets["Buckets"],
                                                 "response_instances": response_instances["Reservations"],
                                                 "user_policies": user_policies["AttachedPolicies"], "response": response["Policies"]})


def iam_user_details_download(request):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Download Access Credentials
    Description:This function generates CSV file download with username, Access Keys, Secret Keys.
    '''
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="Credentials.csv"'
    writer = csv.writer(response)
    writer.writerow(["UserName", "AccessKey", "SecretKey"])

    writer.writerow([request.POST.get("download_username"), request.POST.get("download_access_key"), request.POST.get("download_secret_key")])
    return response


def iam_users_list(request):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Add IAM User List
    Description:when user hits the url "^iam/user/list/$" this function is called
    First this function renders to "iam_users_list" template,
    Connecting to boto3 IAM client, Displays all IAM Users.
    '''
    client = boto3.client(
       'iam',
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    response = client.list_users()
    return render(request, "iam_user/iam_users_list.html", {"response": response["Users"]})


def iam_user_detail(request, user_name):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Add IAM User Detail
    Description:when user hits the url "^iam/user/detail/$" this function is called
    First this function renders to "iam_users_list" template,
    Connecting to boto3 IAM client, Display details of specific IAM User.
    '''
    client = boto3.client(
       'iam',
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )

    if request.GET.get("generate_keys"):
        response = client.create_access_key(UserName=user_name)
        data = {"error": False, "iam_username": response["AccessKey"]["UserName"], "iam_access_key": response["AccessKey"]["AccessKeyId"], "iam_secret_key": response["AccessKey"]["SecretAccessKey"]}
        return HttpResponse(json.dumps(data))

    response = client.get_user(UserName=user_name)

    user_policies = client.list_attached_user_policies(
        UserName=response["User"]["UserName"]
    )

    user_access_keys = client.list_access_keys(
        UserName=response["User"]["UserName"],
    )

    return render(request, "iam_user/iam_user_detail.html", {"response": response["User"],
                  "user_policies": user_policies["AttachedPolicies"],
                  "user_name": user_name, "user_access_keys": user_access_keys["AccessKeyMetadata"]})


def iam_user_change_password(request, user_name):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Change password of IAM User
    Description:when user hits the url "^iam/user/change-password/username/$" this function is called
    First this function renders to "change_password" template,
    Connecting to boto3 IAM client, Checks whether the new password and confirm password matches, if not raises an error if not save the data.
    '''
    client = boto3.client(
       'iam',
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    if request.method == 'POST':
        form = ChangePasswordForm(request.POST)
        if form.is_valid():
            if request.POST.get("new_password") != request.POST.get("confirm_password"):
                data = {"error": True, 'message': "Confirm Password should match with New Password."}
                return HttpResponse(json.dumps(data))
            else:
                if request.POST.get("type") == "change_password":
                    try:
                        response = client.update_login_profile(
                            UserName=user_name,
                            Password=request.POST.get("new_password"),
                            PasswordResetRequired=False
                        )
                        data = {"error": False}
                        return HttpResponse(json.dumps(data))
                    except ClientError as e:
                        data = {"error": True, "message": str(e)}
                        return HttpResponse(json.dumps(data))
                else:
                    try:
                        client.create_login_profile(
                            UserName=user_name,
                            Password=request.POST.get("new_password"),
                            PasswordResetRequired=False
                        )
                        data = {"error": False}
                        return HttpResponse(json.dumps(data))
                    except ClientError as e:
                        data = {"error": True, "message": str(e)}
                        return HttpResponse(json.dumps(data))
        else:
            data = {"error": True, "response": form.errors}
            return HttpResponse(json.dumps(data))
    try:
        get_profile = client.get_login_profile(UserName=user_name)
        get_profile = True
    except:
        get_profile = False
    return render(request, 'iam_user/change_password.html', {"user_name": user_name, "get_profile": get_profile}) 


def policies_list(request, user_name):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Policies list
    Description:when user hits the url "^policies/username/$" this function is called
    First this function renders to "policies" template,
    Connecting to boto3 IAM client,when user can attach multiple policies.
    '''
    client = boto3.client(
       'iam',
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    user_policies = client.list_attached_user_policies(
        UserName=user_name
    )
    response = client.list_policies(
            Scope='All',
            OnlyAttached=False
            )
    client_s3 = boto3.client(
        's3',
        aws_access_key_id=request.session["access_key"],
        aws_secret_access_key=request.session["secret_key"])

    client_ec2 = boto3.client(
       'ec2', region_name=request.POST.get("region") if request.POST.get("region") else "us-west-2",
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    response_instances = client_ec2.describe_instances()
    response_buckets = client_s3.list_buckets()

    if request.method == "POST":
        if request.POST.getlist("policy"):
            for policy in request.POST.getlist("policy"):
                client.attach_user_policy(
                    UserName=user_name,
                    PolicyArn=policy
                )
            return HttpResponseRedirect(reverse("iam_user_detail", kwargs={'user_name': user_name}))
        if request.POST.get("region"):
            l = []
            for instance in response_instances["Reservations"]:
                for i in instance["Instances"]:
                    dict = {}
                    dict["name"] = i["KeyName"]
                    dict["region"] = i["Placement"]["AvailabilityZone"]
                    l.append(dict)
            data = {'error': False, "response_instances": l}
            return HttpResponse(json.dumps(data))
    else:
        return render(request, "policies.html", {"regions": REGIONS, "user_policies": user_policies["AttachedPolicies"], "response": response["Policies"], "user_name": user_name, "response_buckets": response_buckets["Buckets"], "response_instances": response_instances["Reservations"]})


def detach_user_policies(request, user_name):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:Policy detach
    Description:when user hits the url "^iam-userpolicy/detach/username/$" this function is called
    First this function renders to 'iam_user_detail' template,
    Connecting to boto3 IAM client,detach policy for the particular user.
    '''
    client = boto3.client(
       'iam',
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )

    client.detach_user_policy(
        UserName=user_name,
        PolicyArn=request.GET.get("policy_arn")
    )
    return HttpResponseRedirect(reverse("iam_user_detail", kwargs={'user_name': user_name}))


def delete_iam_user(request, user_name):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:delete User
    Description:when user hits the url "^iam/user/delete/username/$" this function is called
    First this function renders to 'iam_user_list' template,
    Connecting to boto3 IAM client,deletes particular user.
    '''
    client = boto3.client(
       'iam',
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    if request.method == "POST":
        if request.POST.get("iam_user_name"):
            if request.POST.get("iam_user_name") == user_name:
                iam_user = client.get_user(UserName=user_name)
                user_access_keys = client.list_access_keys(
                    UserName=iam_user["User"]["UserName"],
                )
                if user_access_keys["AccessKeyMetadata"]:
                    for key in user_access_keys["AccessKeyMetadata"]:
                        delete_access_keys = client.delete_access_key(
                            UserName=user_name,
                            AccessKeyId=key["AccessKeyId"]
                        )
                attached_policies = client.list_attached_user_policies(
                    UserName=user_name,
                )
                for policy in attached_policies["AttachedPolicies"]:
                    client.detach_user_policy(
                        UserName=user_name,
                        PolicyArn=policy["PolicyArn"]
                    )
                try:
                    s = client.delete_login_profile(
                        UserName=user_name
                    )
                except:
                    pass
                response = client.delete_user(
                    UserName=user_name
                )
                data = {'error': False}
                return HttpResponse(json.dumps(data))
            else:
                data = {'error': True, 'message': "Please Check the user name"}
                return HttpResponse(json.dumps(data))
        else:
            data = {'error': True, 'message': "This field is required"}
            return HttpResponse(json.dumps(data))
    else:
        return HttpResponseRedirect(reverse("iam_users_list"))


def ec2_instances_list(request):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:EC2 Instances List
    Description:when user hits the url "^ec2-instances/list/$" this function is called
    First this function renders to 'EC2/instances' template,
    Connecting to boto3 IAM client,Lists all EC2 Instances.
    '''
    client_ec2 = boto3.client(
       'ec2', region_name=request.POST.get("region") if request.POST.get("region") else "us-west-2",
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    response_instances = client_ec2.describe_instances()
    return render(request, "EC2/instances.html", {"regions": REGIONS, "instances": response_instances['Reservations'],
                                                  "region": request.POST.get("region") if request.POST.get("region") else "us-west-2"})


def s3_buckets_list(request):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:EC2 Instances List
    Description:when user hits the url "^s3-buckets/list/$" this function is called
    First this function renders to 'S3/buckets' template,
    Connecting to boto3 IAM client,Lists all S3 Buckets.
    '''
    client_s3 = boto3.client(
        's3',
        aws_access_key_id=request.session["access_key"],
        aws_secret_access_key=request.session["secret_key"])

    response_buckets = client_s3.list_buckets()
    return render(request, "S3/buckets.html", {"regions": REGIONS, "buckets": response_buckets["Buckets"]})


def send_email(request, region_name=None):
    if request.method == 'GET':
        session = boto3.Session(aws_access_key_id=request.session["access_key"], aws_secret_access_key=request.session["secret_key"])
        ses_client = session.client('ses', region_name=region_name)

        verified_email_addresses = ses_client.list_verified_email_addresses()['VerifiedEmailAddresses']
        return render(request, 'ses/send_email.html', {'verified_email_addresses': verified_email_addresses})

    msg = MIMEMultipart()
    msg['Subject'] = request.POST['subject']
    msg['From'] = request.POST['source']
    msg['To'] = request.POST['destinations']
    
    # what a recipient sees if they don't use an email reader
    msg.preamble = 'Multipart message.\n'
    
    part = MIMEText(request.POST['body'])
    msg.attach(part)

    part = MIMEApplication(request.FILES['attachment'].read())
    part.add_header('Content-Disposition', 'attachment', filename=request.FILES['attachment'].name)
    msg.attach(part)
    
    region_name = request.POST['region_name']
    session = boto3.Session(aws_access_key_id=request.session['access_key'], aws_secret_access_key=request.session['secret_key'])
    ses_client = session.client('ses', region_name=region_name)
    try:
        response = ses_client.send_raw_email(RawMessage={'Data': msg.as_string()}, Source=msg['From'], \
                Destinations=msg['To'].split(','))
    except Exception as e:
        data = {'error': True, 'response': str(e)}
        return HttpResponse(json.dumps(data), content_type='application/json')

    return HttpResponseRedirect('/')


def instance_detail(request, instance_id, region_name):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:EC2 Instances detail
    Description:when user hits the url "^ec2-instances/detail/<instance_id>/<region_name>/$" this function is called
    First this function renders to 'EC2/detail' template,
    Connecting to boto3 IAM client,displays the detailed information of specific Instance.
    '''
    client = boto3.client(
       'ec2', region_name=region_name if region_name else "us-west-2",
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    response_instance = client.describe_instances(InstanceIds=[instance_id])
    return render(request, "EC2/detail.html", {"region_name": region_name, "response_instance": response_instance['Reservations']})


def change_instance_status(request, instance_id, region_name):
    '''
    Authored by:Swetha
    Other Modules Involved:
    Tasks Involved:EC2 Instances detail
    Description:when user hits the url "^ec2-instances/change-status/<instance_id>/<region_name>/$" this function is called
    Connecting to boto3 IAM client,changes the status of specific instances(start, stop, terminate).
    '''
    client = boto3.client(
       'ec2', region_name=region_name if region_name else "us-west-2",
       aws_access_key_id=request.session["access_key"],
       aws_secret_access_key=request.session["secret_key"]
    )
    if request.GET.get("action") == "start":
        response = client.start_instances(
            InstanceIds=[instance_id]
        )
    elif request.GET.get("action") == "stop":
        response = client.stop_instances(
            InstanceIds=[instance_id]
        )
    elif request.GET.get("action") == "terminate":
        response = client.terminate_instances(
            InstanceIds=[instance_id]
        )
    return HttpResponseRedirect(reverse("ec2_instances_list"))


def create_s3_bucket(request):
    if request.method == "POST":
        client_s3 = boto3.client(
            's3',
            aws_access_key_id=request.session["access_key"],
            aws_secret_access_key=request.session["secret_key"])
        form = BucketForm(request.POST)
        if form.is_valid():
            try:
                response = client_s3.create_bucket(
                    Bucket=request.POST.get("bucket_name"),
                    CreateBucketConfiguration={'LocationConstraint': request.POST.get("region_name")},
                )
                data = {'error': False}
                return HttpResponse(json.dumps(data))
            except Exception as e:
                data = {'error': True, 'message': str(e)}
                return HttpResponse(json.dumps(data))
        else:
            data = {'error': True, 'response': form.errors}
            return HttpResponse(json.dumps(data))
    else:
        return HttpResponseRedirect(reverse('s3_buckets_list'))


def delete_bucket(request, bucket_name):
    client_s3 = boto3.client(
            's3',
            aws_access_key_id=request.session["access_key"],
            aws_secret_access_key=request.session["secret_key"])
    if request.method == "POST":
        if request.POST.get("s3_bucket_name"):
            if request.POST.get("s3_bucket_name") == bucket_name:
                try:
                    response = client_s3.delete_bucket(
                        Bucket=bucket_name
                    )
                    data = {'error': False}
                except Exception as e:
                    data = {'error': True, 'message': str(e)}
                return HttpResponse(json.dumps(data))
            else:
                data = {'error': True, 'message': "Please Check your bucket name"}
                return HttpResponse(json.dumps(data))
        else:
            data = {'error': True, 'message': "This field is required"}
            return HttpResponse(json.dumps(data))
    else:
        return HttpResponseRedirect(reverse("s3_buckets_list"))


def emails_list(request):
    ses_client = boto3.client(
        'ses',  region_name=request.POST.get("region") if request.POST.get("region") else "us-west-2",
        aws_access_key_id=request.session["access_key"],
        aws_secret_access_key=request.session["secret_key"])
    verified_email_addresses = ses_client.list_verified_email_addresses()
    return render(request, "ses/email_adresses.html", {"regions": REGIONS, "selected_region": request.POST.get("region") if request.POST.get("region") else "us-west-2",
                                                       "verified_email_addresses": verified_email_addresses["VerifiedEmailAddresses"]})


def add_new_email_adress(request, region_name):
    ses_client = boto3.client(
        'ses',  region_name=region_name,
        aws_access_key_id=request.session["access_key"],
        aws_secret_access_key=request.session["secret_key"])
    if request.method == "POST":
        form = EmailAddressForm(request.POST)
        if form.is_valid():
            try:
                response = ses_client.verify_email_address(
                        EmailAddress=request.POST.get("email")
                    )
            except:
                pass
            data = {'error': False}
            return HttpResponse(json.dumps(data))
        else:
            data = {'error': True, "response": form.errors}
            return HttpResponse(json.dumps(data))
    else:
        return HttpResponseRedirect(reverse('emails_list'))