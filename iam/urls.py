from django.conf.urls import patterns, include, url
from .views import *


urlpatterns = [
    url(r'^$', user_login, name="user_login"),
    url(r'^logout/$', user_logout, name="user_logout"),

    url(r'^register/$', user_register, name="user_register"),

    url(r'^user/settings/$', settings, name="settings"),

    # IAM User
    url(r'^iam/user/add/$', add_iam_user, name="add_iam_user"),
    url(r'^iam/user/list/$', iam_users_list, name="iam_users_list"),
    url(r'^iam/user/detail/(?P<user_name>[a-zA-Z0-9_-]+)/$', iam_user_detail, name="iam_user_detail"),
    url(r'^iam/user/change-password/(?P<iam_user_id>[a-zA-Z0-9_-]+)/$', iam_user_change_password, name="iam_user_change_password"),

    # policies
    url(r'^policies/(?P<iam_user_id>[a-zA-Z0-9_-]+)/$', policies_list, name="policies_list"),
    url(r'^iam-userpolicy/datach/(?P<iam_user_id>[a-zA-Z0-9_-]+)/(?P<policy_id>[a-zA-Z0-9_-]+)/$', detach_user_policies, name="detach_user_policies"),

]