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

    # policies
    url(r'^policies/(?P<user_name>[a-zA-Z0-9_-]+)/$', policies_list, name="policies_list"),
    url(r'^iam-userpolicy/detach/(?P<user_name>[a-zA-Z0-9_-]+)/$', detach_user_policies, name="detach_user_policies"),

]
