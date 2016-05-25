from django.conf.urls import url
from .views import *


urlpatterns = [
    url(r'^home/$', home, name="home"),
    url(r'^logout/$', user_logout, name="user_logout"),


    url(r'^$', login, name="login"),

    # IAM User
    url(r'^iam/user/add/$', add_iam_user, name="add_iam_user"),
    url(r'^iam/user/list/$', iam_users_list, name="iam_users_list"),
    url(r'^iam/user/detail/(?P<user_name>[a-zA-Z0-9_-]+)/$', iam_user_detail, name="iam_user_detail"),
    url(r'^iam/user/change-password/(?P<user_name>[a-zA-Z0-9_-]+)/$', iam_user_change_password, name="iam_user_change_password"),
    url(r'^iam/user/details/download/$', iam_user_details_download, name="iam_user_details_download"),
    url(r'^iam/user/delete/(?P<user_name>[a-zA-Z0-9_-]+)/$', delete_iam_user, name="delete_iam_user"),

    # policies
    url(r'^policies/(?P<user_name>[a-zA-Z0-9_-]+)/$', policies_list, name="policies_list"),
    url(r'^iam-userpolicy/detach/(?P<user_name>[a-zA-Z0-9_-]+)/$', detach_user_policies, name="detach_user_policies"),
    url(r'^iam/custom-policy/(?P<user_name>[a-zA-Z0-9_-]+)/$', generate_custom_policy, name="generate_custom_policy"),

    # EC2 Instances
    url(r'^ec2-instances/list/$', ec2_instances_list, name="ec2_instances_list"),
    url(r'^ec2-instances/detail/(?P<instance_id>[a-zA-Z0-9_-]+)/(?P<region_name>[a-zA-Z0-9_-]+)/$', instance_detail, name="instance_detail"),
    url(r'^ec2-instances/change-status/(?P<instance_id>[a-zA-Z0-9_-]+)/(?P<region_name>[a-zA-Z0-9_-]+)/$', change_instance_status, name="change_instance_status"),

    # S3 Buckets
    url(r'^s3-buckets/list/$', s3_buckets_list, name="s3_buckets_list"),
       
    # ses
    url(r'ses/send-email/(?P<region_name>[^/]*)/$', send_email, name='send_email'),

]
